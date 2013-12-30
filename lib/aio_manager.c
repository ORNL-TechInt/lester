/* aio_manager.c -- read-only, asynchronous IO manager based on libaio
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU Library General
 * Public License version 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stddef.h>
#include <libaio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <ext2fs/ext2fs.h>

#include "list.h"
#include "rbtree.h"
#include "ext2fs-extra.h"

#include <stdio.h>

#define DEBUG 0

typedef int (*req_callback_t)(ext2_loff_t offset, ssize_t size,
				void *priv1, unsigned long priv2, void *data);

struct span {
	struct list_head list;
	ext2_loff_t offset;
	ssize_t size;
	void *data;
};

struct request {
	struct list_head list;
	struct list_head active;
	struct rb_node rb_node;
	ext2_loff_t offset;
	ssize_t size;
	unsigned long order;

	unsigned int *waiting;
        req_callback_t callback;
	void *priv1;
	unsigned long priv2;
};

struct cacheblock {
	struct list_head list;
	struct list_head reqs;
	struct iocb iocb;
	void *buffer;
	unsigned long order;

	/* These fields are used for retrieving data out of the read ahead
	 * requests. We could reuse the iocb internal fields, but this
	 * is cleaner.
	 */
	ext2_loff_t offset;
	ssize_t size;
	void *data;
	unsigned int age;
};

struct aio_data {
	int magic;
	int fd;
	int in_runqueue;
	int ignore_async;
	int async_only;
	ssize_t merge_gap;
	ssize_t max_size;
	unsigned int target_qd;
	unsigned int in_flight;
	unsigned int reserved_cacheblocks;
	ssize_t sector_size;
	unsigned long next_order;
	unsigned long used_order;

	unsigned long num_async;
	ext2_loff_t last_offset;

	io_context_t ioctx;
	struct iocb **iolist;
	struct io_event *events;

	/* Lists for cache blocks */
	unsigned int avail_cacheblocks;
	struct list_head cb_list;
	struct list_head cache;
	struct list_head waiting;

	/* span structs ready for use */
	struct list_head span_list;

	/* lists for requests */
	struct list_head req_list;
	struct list_head active;
	struct list_head rq;
	struct rb_root async_rq;

	time_t last_update;
	unsigned int num_bufs;
	unsigned int preallocate_reqs;
	struct cacheblock *cacheblock_base;
	unsigned long arena_size;
	void *arena;

	struct struct_aio_stats stats;
};

#define AIO_GET_PRIVATE(d) \
	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL); \
	aio = (struct aio_data *) channel->private_data; \
	EXT2_CHECK_MAGIC(aio, EXT2_ET_MAGIC_UNIX_IO_CHANNEL)

static void init_request(struct request *req)
{
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->active);
	RB_CLEAR_NODE(&req->rb_node);
}

static struct request *__rb_insert_req(struct rb_root *root,
					ext2_loff_t offset,
					struct rb_node *node)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct request *req;

	while (*p) {
		parent = *p;
		req = rb_entry(parent, struct request, rb_node);

		if (offset < req->offset)
			p = &(*p)->rb_left;
		else if (offset > req->offset)
			p = &(*p)->rb_right;
		else
			return req;
	}

	rb_link_node(node, parent, p);
	return NULL;
}

static void insert_async_req(struct aio_data *aio, struct request *req)
{
	struct request *found;

	found = __rb_insert_req(&aio->async_rq, req->offset, &req->rb_node);
	if (found)
		list_add_tail(&req->list, &found->list);
	else
		rb_insert_color(&req->rb_node, &aio->async_rq);
}

static struct request *next_async_request(struct aio_data *aio,
					  ext2_loff_t offset)
{
	/* Search the async RB tree for the next offset greater than
	 * or equal to the one given
	 */
	struct rb_node *p, *n = aio->async_rq.rb_node;
	struct request *req;

	if (!n)
		return NULL;

	while (n) {
		p = n;
		req = rb_entry(n, struct request, rb_node);

		if (offset < req->offset)
			n = n->rb_left;
		else if (offset > req->offset)
			n = n->rb_right;
		else
			return req;
	}

	/* We didn't find an exact match for the offset, walk up the
	 * tree to find the next largest one.
	 */
	while (p) {
		req = rb_entry(p, struct request, rb_node);

		if (req->offset > offset)
			return req;
		p = rb_parent(p);
	}

	/* Everything in the tree is before the offset */
	return NULL;
}

static errcode_t init_aio(struct aio_data *aio)
{
	unsigned int num_bufs;
	unsigned char *arena;
	struct cacheblock *cb, *cblocks = NULL;
	errcode_t rc;
	int i;

	/* Set our defaults unless overridden */
	if (!aio->max_size)
		aio->max_size = 1024 * 1024;
	if (!aio->target_qd)
		aio->target_qd = 8;
	if (!aio->reserved_cacheblocks)
		aio->reserved_cacheblocks = 4;

	if (aio->max_size < aio->merge_gap)
		aio->merge_gap = aio->max_size;

	num_bufs = aio->target_qd * 2 + aio->reserved_cacheblocks;
	if (!aio->num_bufs || aio->num_bufs < num_bufs)
		aio->num_bufs = num_bufs;

	aio->arena_size = aio->num_bufs * aio->max_size;

	rc = io_queue_init(aio->target_qd, &aio->ioctx);
	if (rc)
		return rc;

	arena = mmap(NULL, aio->arena_size, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, -1, 0);
	if (arena == MAP_FAILED)
		goto error_ioctx;
	aio->arena = arena;

	rc = ext2fs_get_array(aio->target_qd, sizeof(struct io_event),
					&aio->events);
	if (!rc)
		rc = ext2fs_get_array(aio->target_qd, sizeof(struct iocb *),
					&aio->iolist);
	if (!rc)
		rc = ext2fs_get_array(aio->num_bufs, sizeof(struct cacheblock),
					&cblocks);
	if (rc)
		goto error_mem;

	for (cb = cblocks, i = 0; i < aio->num_bufs; cb++, i++) {
		cb->buffer = arena;
		INIT_LIST_HEAD(&cb->list);
		INIT_LIST_HEAD(&cb->reqs);
		list_add_tail(&cb->list, &aio->cb_list);
		aio->avail_cacheblocks++;
		arena += aio->max_size;
	}

	for (i = 0; i < aio->preallocate_reqs; i++) {
		struct request *req;
		rc = ext2fs_get_mem(sizeof(struct request), &req);
		if (rc)
			goto error_mem;

		init_request(req);
		list_add(&req->list, &aio->req_list);
	}

	/* We use cacheblock_base as a flag that we've been initialized,
	 * so do this last.
	 */
	aio->cacheblock_base = cblocks;
	return 0;

error_mem:
	if (cblocks)
		ext2fs_free_mem(&cblocks);
	if (aio->iolist)
		ext2fs_free_mem(&aio->iolist);
	if (aio->events)
		ext2fs_free_mem(&aio->events);
	munmap(arena, aio->arena_size);

error_ioctx:
	io_destroy(aio->ioctx);

	/* Flag that we're clean for aio_close() */
	aio->cacheblock_base = NULL;
	return rc;
}

static errcode_t ensure_aio_init(struct aio_data *aio)
{
	if (aio->cacheblock_base)
		return 0;
	return init_aio(aio);
}

static void reclaim_cache(struct aio_data *aio)
{
	/* reclaim the smallest buffer that's been used or from before the
	 * last read-ahead request matched by a specific read call. If there
	 * is a tie for size, chose the oldest one.
	 *
	 * we use an unsigned long for the order fields, so wrapping of that
	 * field can be ignored for 64 bit machines for now.
	 */
	struct cacheblock *cb, *reap = NULL;
	unsigned long zero = 0, order = 0;

	list_for_each_entry(cb, &aio->cache, list) {
		if (!cb->order)
			zero++;
		else if (!order)
			order = cb->order;

		if (cb->order >= aio->used_order)
			continue;

		if (!reap)
			reap = cb;
		else if (cb->size < reap->size)
			reap = cb;
		else if (cb->size == reap->size && cb->age > reap->age)
			reap = cb;
	}

	if (DEBUG)
		fprintf(stderr, "checking for reclaimable buffers %u "
				"(used %lu, order %lu, zero %lu)\n",
				aio->avail_cacheblocks, aio->used_order,
				order, zero);

	if (reap) {
		if (DEBUG)
			fprintf(stderr, "reclaiming %llu:%ld age %u order %lu "
				"used %lu\n",
				reap->offset, reap->size, reap->age,
				reap->order, aio->used_order);
		list_move(&reap->list, &aio->cb_list);
		aio->avail_cacheblocks++;
	}
}

static int cache_below_reserve(struct aio_data *aio)
{
	return aio->avail_cacheblocks < aio->reserved_cacheblocks;
}

static struct cacheblock *get_cacheblock(struct aio_data *aio,
						struct request *req)
{
	struct cacheblock *cb;

	if (cache_below_reserve(aio))
		reclaim_cache(aio);

	if (!aio->avail_cacheblocks)
		return NULL;

	/* Allow waiting and async requests to tap into the reserve */
	if (!(req->waiting || req->callback) && cache_below_reserve(aio))
		return NULL;

	cb = list_first_entry(&aio->cb_list, struct cacheblock, list);
	list_del_init(&cb->list);
	aio->avail_cacheblocks--;

	/* Prep the cache fields */
	cb->data = cb->buffer;
	cb->offset = req->offset;
	cb->size = req->size;
	cb->order = req->order;
	cb->age = 0;

	return cb;
}

static struct request *next_request(struct aio_data *aio)
{
	struct request *areq, *req = NULL;

	if (!aio->async_only && !list_empty(&aio->rq))
		req = list_first_entry(&aio->rq, struct request, list);

	/* If there's no async requests, then we have a simple answer */
	if (RB_EMPTY_ROOT(&aio->async_rq))
		return req;

	areq = next_async_request(aio, aio->last_offset);
	if (areq && req) {
		if (areq->offset <= req->offset)
			return areq;
		return req;
	}

	if (areq || req) {
		if (areq)
			return areq;
		return req;
	}

	/* We have neither a readahead request nor an async request after
	 * the last offset sent to the disk. Start over at the beginning
	 * of the async queue
	 */
	areq = rb_entry(rb_first(&aio->async_rq), struct request, rb_node);
	return areq;
}

static struct cacheblock *build_async_request(struct aio_data *aio,
						struct request *req)
{
	struct cacheblock *cb = get_cacheblock(aio, req);
	struct rb_node *next;
	ssize_t size, gap;
	unsigned int req_count = 0;
	int instream = 1;

	if (!cb)
		return NULL;

	if (list_empty(&aio->rq) || aio->async_only)
		instream = 0;

	cb->offset = req->offset;
	gap = size = 0;

	for (;;) {
		req_count++;
		aio->stats.async_instream += instream;
		aio->stats.merged_gap_bytes += gap;
		size += req->size + gap;

		if (DEBUG) {
			fprintf(stderr, "build_async_request adding req %u: "
					"%llu:%ld to cb %llu:%ld\n",
					req_count, req->offset, req->size,
					cb->offset, size);
		}

		/* Add this request (and all duplicates) to the cacheblock
		 * If there are no duplicates, req->list will be empty and
		 * list_splice_tail_init() will be a noop. The list_add_tail()
		 * always adds this request.
		 */
		list_splice_tail_init(&req->list, &cb->reqs);
		list_add_tail(&req->list, &cb->reqs);

		/* Get the next merge candidate. If we're full, there's no
		 * reason to continue merging.
		 */
		next = (size == aio->max_size) ? NULL : rb_next(&req->rb_node);
		rb_erase(&req->rb_node, &aio->async_rq);

		if (!next)
			break;

		req = rb_entry(next, struct request, rb_node);

		gap = req->offset - (cb->offset + size);
		if (gap > aio->merge_gap)
			break;

		if (aio->max_size < size + gap + req->size)
			break;
	}

	io_prep_pread(&cb->iocb, aio->fd, cb->buffer, size, cb->offset);
	cb->size = size;

	if (req_count > 1) {
		aio->stats.merged_async_issued++;
		aio->stats.merged_async += req_count;
	}

	return cb;
}

static struct cacheblock *build_regular_request(struct aio_data *aio,
						struct request *req)
{
	struct cacheblock *cb = get_cacheblock(aio, req);

	if (!cb)
		return NULL;

	io_prep_pread(&cb->iocb, aio->fd, cb->buffer, req->size, req->offset);

	/* Add this request (there can be no duplicates here)
	 */
	list_move_tail(&req->list, &cb->reqs);
	list_add_tail(&req->active, &aio->active);
	return cb;
}

static errcode_t submit_requests(struct aio_data *aio)
{
	unsigned int needed = aio->target_qd - aio->in_flight;
	struct iocb **iolist = aio->iolist;
	struct request *req;
	struct cacheblock *cb;
	int ready = 0;

	if (DEBUG)
		fprintf(stderr, "submit_request %d %u\n", needed,
			aio->avail_cacheblocks);

	while (needed) {
		req = next_request(aio);
		if (!req)
			break;

		if (req->callback)
			cb = build_async_request(aio, req);
		else
			cb = build_regular_request(aio, req);

		if (!cb)
			break;

		if (DEBUG) {
			fprintf(stderr, "aio submit %d %llu:%ld:%lu%s%s\n",
				needed, cb->offset, cb->size, req->order,
				req->waiting ? " waiting" : "",
				req->callback ? " async" : "");
			if (req->callback && !list_empty(&aio->rq)) {
				struct request *t;
				t = list_first_entry(&aio->rq, struct request,
								list);
				fprintf(stderr, "aio submit last %lu next "
					"%lu\n",
					(unsigned long) aio->last_offset,
					(unsigned long) t->offset);
			}
		}

		aio->last_offset = cb->offset;
		*iolist++ = &cb->iocb;
		ready++;
		needed--;
	}

	if (DEBUG && needed && !list_empty(&aio->rq)) {
		int count = 0;
		list_for_each_entry(req, &aio->rq, list)
			if (++count == needed)
				break;
		fprintf(stderr, "postponing %d requests due to no buffers\n",
				count);
	}

	return ready;
}

static void insert_cacheblock(struct aio_data *aio, struct cacheblock *cb)
{
	/* Regular readahead, so put it on the cache list in order of
	 * submission. Start at the back in the hope that the requests
	 * complete in the same order they completed.
	 */
	struct list_head *pos = aio->cache.prev;
	struct cacheblock *pcb;

	while (pos != &aio->cache) {
		pcb = list_entry(pos, struct cacheblock, list);
		if (cb->order > pcb->order)
			break;
		pos = pos->prev;
	}
	list_add(&cb->list, pos);
}

static errcode_t process_completion(struct aio_data *aio,
					struct io_event *event)
{
	struct iocb *iocb = event->obj;
	struct cacheblock *cb = container_of(iocb, struct cacheblock, iocb);
	int waiting_for_cb = 0;
	int release_cb = 1;
	struct request *req, *pos;
	ssize_t offset;
	errcode_t rc;

	if (DEBUG) {
		/* We only merge async requests, so the first req on the
		 * list will tell us what we're dealing with.
		 */
		req = list_first_entry(&cb->reqs, struct request, list);
		fprintf(stderr, "process_completion %llu, %llu:%ld%s%s\n",
				iocb->u.c.offset, cb->offset, cb->size,
				req->waiting ? " waiting" : "",
				req->callback ? " async" : "");
	}

	if (event->res != cb->size) {
		// XXX check this, should we print here?
		fprintf(stderr, "Funky return for request: got %ld, "
				"expected %ld @ %lu\n",
				event->res, cb->size,
				(unsigned long) cb->offset);
		// XXX need proper errorcode
		return 1;
        }

	aio->stats.base.bytes_read += cb->size;

	list_for_each_entry_safe(req, pos, &cb->reqs, list) {
		aio->stats.completed_requests++;

		if (req->waiting) {
			/* synchronous request, put it on a separate list so we
			 * don't have to scan the entire cache for it.
			 */
			(*req->waiting)--;
			waiting_for_cb = 1;
		} else if (req->callback && !aio->ignore_async) {
			/* async request, go ahead and handle the callback */
			aio->num_async--;
			offset = req->offset - cb->offset;
			rc = req->callback(req->offset, req->size, req->priv1,
						req->priv2, cb->data + offset);
			if (rc)
				return rc;
		} else
			release_cb = 0;

		list_del_init(&req->active);
		list_move(&req->list, &aio->req_list);
	}

	/* Now that we've processed the requests for this cache block,
	 * determine its disposition.
	 */
	if (waiting_for_cb)
		list_add_tail(&cb->list, &aio->waiting);
	else if (release_cb) {
		list_add(&cb->list, &aio->cb_list);
		aio->avail_cacheblocks++;
	} else
		insert_cacheblock(aio, cb);
	return 0;
}

static errcode_t run_queue(struct aio_data *aio, int wait)
{
	int io_ready, rc, i;
	int min = wait ? 1 : 0;

	if (aio->in_runqueue)
		return 0;

	aio->in_runqueue = 1;

	if (DEBUG) {
		time_t now = time(NULL);

		if (aio->last_update != now) {
			struct tm *tm = localtime(&now);
			fprintf(stderr, "timestamp %02d:%02d:%02d\n", tm->tm_hour,
				tm->tm_min, tm->tm_sec);
			aio->last_update = now;
		}
		fprintf(stderr, "run_queue start %d\n", aio->in_flight);
	}

	if (aio->in_flight) {
		do {
			rc = io_getevents(aio->ioctx, min, aio->in_flight,
						aio->events, NULL);
		} while (rc == -EINTR);
		if (rc < 0) {
			/* Unexpected failure, programming error? */
			fprintf(stderr, "failed io_getevents(%u, %u) = %d\n",
					min, aio->in_flight, rc);
			exit(1);
		}

		aio->in_flight -= rc;
		for (i = 0; i < rc; i++) {
			if (process_completion(aio, &aio->events[i])) {
				// XXX failure, how to recover?
				fprintf(stderr, "process_completion failed\n");
				exit(1);
			}
		}
	}

	io_ready = submit_requests(aio);
	if (io_ready) {
		do {
			rc = io_submit(aio->ioctx, io_ready, aio->iolist);
		} while (rc == -EINTR);
		if (rc < 0) {
			// XXX failure, how to recover
			fprintf(stderr, "failed io_submit(%u, %u) = %d\n",
					io_ready, aio->in_flight, rc);
			exit(1);
		}

		aio->in_flight += io_ready;
		aio->stats.issued_requests += io_ready;
	}

	if (DEBUG)
		fprintf(stderr, "run_queue end %d\n", aio->in_flight);

	aio->in_runqueue = 0;
	return 0;
}


static errcode_t aio_close(io_channel channel)
{
	struct aio_data *aio;
	struct request *req, *rpos;
	struct span *s, *spos;
	struct rb_node *n;
	errcode_t rc = 0;

	AIO_GET_PRIVATE(channel);

	if (--channel->refcount > 0)
		return 0;

	if (aio->cacheblock_base) {
		/* Clean up the async_rq rb_tree without doing an explicit
		 * erase on each entry. Simple method is to move the requests
		 * to the readahead queue and clean them as part of that
		 * effort.
		 */
		n = rb_first(&aio->async_rq);
		while (n) {
			req = rb_entry(n, struct request, rb_node);
			list_splice_tail_init(&req->list, &aio->rq);
			list_add_tail(&req->list, &aio->rq);
			n = rb_next(n);
		}
		list_for_each_entry_safe(req, rpos, &aio->rq, list) {
			list_del(&req->list);
			ext2fs_free_mem(&req);
		}

		aio->ignore_async = 1;
		while (aio->in_flight) {
			if (run_queue(aio, 1))
				goto error;
		}
		
		list_for_each_entry_safe(req, rpos, &aio->req_list, list) {
			list_del(&req->list);
			ext2fs_free_mem(&req);
		}
		list_for_each_entry_safe(s, spos, &aio->span_list, list) {
			list_del(&s->list);
			ext2fs_free_mem(&s);
		}

		ext2fs_free_mem(&aio->cacheblock_base);
		ext2fs_free_mem(&aio->iolist);
		ext2fs_free_mem(&aio->events);
		munmap(aio->arena, aio->arena_size);
	}

error:
	if (close(aio->fd) < 0)
		rc = errno;

	ext2fs_free_mem(&aio);
	if (channel->name)
		ext2fs_free_mem(&channel->name);
	ext2fs_free_mem(&channel);
	return rc;
}

static errcode_t aio_set_blksize(io_channel channel, int blksize)
{
	struct aio_data *aio;

	AIO_GET_PRIVATE(channel);

	channel->block_size = blksize;
	return 0;
}

static errcode_t aio_set_option(io_channel channel, const char *option,
				const char *arg)
{
	struct aio_data *aio;
	unsigned long long tmp;
	char *end;

	AIO_GET_PRIVATE(channel);

	if (!arg)
		return EXT2_ET_INVALID_ARGUMENT;

	tmp = strtoull(arg, &end, 0);
	if (*end)
		return EXT2_ET_INVALID_ARGUMENT;

	if (!strcmp(option, "maxsize"))
		aio->max_size = tmp * 1024;
	else if (!strcmp(option, "qd") || !strcmp(option, "queuedepth"))
		aio->target_qd = tmp;
	else if (!strcmp(option, "req_preallocate"))
		aio->preallocate_reqs = tmp;
	else if (!strcmp(option, "cache_entries"))
		aio->num_bufs = tmp;
	else if (!strcmp(option, "reserved_entries"))
		aio->reserved_cacheblocks = tmp;
	else if (!strcmp(option, "merge_gap"))
		aio->merge_gap = tmp * 1024;
	else
		return EXT2_ET_INVALID_ARGUMENT;

	return 0;
}

static errcode_t aio_get_stats(io_channel channel, io_stats *stats)
{
	struct aio_data *aio;

	AIO_GET_PRIVATE(channel);

	if (stats)
		*stats = &aio->stats.base;
	return 0;
}

static errcode_t make_requests(io_channel channel, struct list_head *requests,
				unsigned long block, int count,
				unsigned int *waiting, req_callback_t callback,
				void *req_priv1, unsigned long req_priv2)
{
	struct aio_data *aio = channel->private_data;
	struct request *req;
	ext2_loff_t offset;
	ssize_t size;
	errcode_t rc;

	offset = block * channel->block_size;
	size = (count < 0) ? -count : count * channel->block_size;
	if (offset % aio->sector_size) {
		size += offset % aio->sector_size;
		offset -= offset % aio->sector_size;
	}
	size = (size + aio->sector_size - 1) & ~(aio->sector_size - 1);

	if (DEBUG)
		fprintf(stderr, "making request for %llu:%ld\n", offset, size);

	while (size > 0) {
		if (list_empty(&aio->req_list)) {
			rc = ext2fs_get_mem(sizeof(struct request), &req);
			if (rc)
				return rc;

			init_request(req);
		} else {
			req = list_first_entry(&aio->req_list, struct request, list);
			list_del_init(&req->list);
		}

		req->waiting = waiting;
		if (waiting) {
			(*waiting)++;
			req->order = 0;
		} else
			req->order = aio->next_order++;
		req->callback = callback;
		req->priv1 = req_priv1;
		req->priv2 = req_priv2;
		req->offset = offset;
		if (size <= aio->max_size)
			req->size = size;
		else
			req->size = aio->max_size;

		offset += req->size;
		size -= req->size;
		list_add_tail(&req->list, requests);
	}

	if (DEBUG) {
		list_for_each_entry(req, requests, list) {
			fprintf(stderr, "\t subreq %llu:%ld:%lu\n",
				req->offset, req->size,
				req->order);
		}
	}

	return 0;
}

static errcode_t aio_readahead(io_channel channel, unsigned long block,
				int count)
{
	struct aio_data *aio;
	LIST_HEAD(requests);
	errcode_t rc;

	AIO_GET_PRIVATE(channel);

	rc = ensure_aio_init(aio);
	if (rc)
		return rc;

	if (DEBUG)
		fprintf(stderr, "aio_readahead %lu %d\n", block, count);

	rc = make_requests(channel, &requests, block, count,
					NULL, NULL, NULL, 0);
	if (rc)
		return rc;

	/* Readahead requests are assumed to be submitted in the order
	 * they will be needed, so just put them on the tail of the list.
	 */
	list_splice_tail(&requests, &aio->rq);
	return run_queue(aio, 0);
}

static errcode_t add_span(struct aio_data *aio, struct list_head *prior_entry,
				ext2_loff_t offset, ssize_t size, void *data)
{
	struct span *s;
	errcode_t rc;

	if (DEBUG)
		fprintf(stderr, "adding span %llu %ld\n", offset, size);

	if (list_empty(&aio->span_list)) {
		rc = ext2fs_get_mem(sizeof(struct span), &s);
		if (rc)
			return rc;

		INIT_LIST_HEAD(&s->list);
	} else {
		s = list_first_entry(&aio->span_list, struct span, list);
		list_del_init(&s->list);
	}

	s->offset = offset;
	s->size = size;
	s->data = data;

	/* Insert this span after the list head given */
	list_add(&s->list, prior_entry);
	return 0;
}

static errcode_t clone_spans(struct aio_data *aio, struct list_head *orig,
				struct list_head *clone)
{
	struct span *s;
	errcode_t rc;

	list_for_each_entry(s, orig, list) {
		rc = add_span(aio, clone, s->offset, s->size, s->data);
		if (rc)
			return rc;

		/* Keep appending after the last span added. clone is
		 * assumed to be an empty list on entry
		 */
		clone = clone->next;
	}

	return 0;
}

static errcode_t fill_span(struct aio_data *aio, struct list_head *spans,
				struct cacheblock *cb)
{
	/* See if this IO buffer can fullfill any of the spans we need.
	 * Keep the spans ordered, so we can stop early if possible.
	 */
	ext2_loff_t start, end, i_end, s_end, noffset;
	ssize_t len, nsize;
	void *src, *dest, *ndata;
	struct span *s, *pos;
	errcode_t rc;

	list_for_each_entry_safe(s, pos, spans, list) {
		i_end = cb->offset + cb->size - 1;
		s_end = s->offset + s->size - 1;

		if (DEBUG) {
			fprintf(stderr, "checking cache block %llu:%ld:%llu:%lu "
					"for span %llu:%ld:%llu\n",
					cb->offset, cb->size, i_end, cb->order,
					s->offset, s->size, s_end);
		}

		/* is the span completely past the buffer? */
		if (s->offset > i_end)
			return 0;

		/* Is the buffer after this span? */
		if (cb->offset > s_end)
			continue;

		if (cb->order > aio->used_order)
			aio->used_order = cb->order;

		/* We have some degree of overlap */
		start = (s->offset > cb->offset) ? s->offset : cb->offset;
		end = (s_end < i_end) ? s_end : i_end;
		len = end - start + 1;

		if (cb->offset > s->offset && i_end < s_end) {
			/* This buffer splits the span */
			noffset = end + 1;
			nsize = s_end - noffset + 1;
			ndata = s->data + noffset - s->offset;

			dest = s->data + start - s->offset;
			src = cb->data;

			s->size -= nsize;
			rc = add_span(aio, &s->list, noffset, nsize, ndata);
			if (rc)
				return rc;
		} else if (s->offset > cb->offset && s_end < i_end) {
			/* This span splits the buffer, so first trim the
			 * front of the buffer to coincide with the span.
			 * If we start using spans in the buffer management,
			 * we could avoid discarding the data.
			 */
			cb->data += s->offset - cb->offset;
			cb->size -= s->offset - cb->offset;
			cb->offset = s->offset;

			dest = s->data;
			src = cb->data;

			/* Span is consumed; only need to update cache block */
			cb->offset += len;
			cb->data += len;
		} else {
			dest = s->data + (start - s->offset);
			src = cb->data + (start - cb->offset);

			if (start == cb->offset) {
				/* Covered tail of span, or span starts
				 * at the buffer's offset.
				 */
				cb->offset += len;
				cb->data += len;
				if (start == s->offset) {
					s->offset += len;
					s->data += len;
				}
			} else {
				/* Covered head of span */
				s->offset += len;
				s->data += len;
			}
		}

		memcpy(dest, src, len);
		cb->size -= len;
		s->size -= len;

		if (!s->size)
			list_move(&s->list, &aio->span_list);

		if (!cb->size) {
			list_move(&cb->list, &aio->cb_list);
			aio->avail_cacheblocks++;
			return 0;
		}
	}

	return 0;
}

static errcode_t req_needed_for_span(struct aio_data *aio, struct span *s,
					struct request *req,
					unsigned int *waiting,
					struct list_head *track)
{
	ext2_loff_t start, end, s_end, r_end;
	ssize_t len;
	errcode_t rc;

	r_end = req->offset + req->size - 1;
	s_end = s->offset + s->size - 1;

	if (DEBUG) {
		fprintf(stderr, "checking %s req %llu:%ld:%llu "
				"span %llu:%ld:%llu\n",
				track ? "queued" : "active",
				req->offset, req->size, r_end,
				s->offset, s->size, s_end);
	}

	if (s_end < req->offset || s->offset > r_end)
		return 0;

	/* This request holds data we need.
	 * The caller must ensure that we do not try to track an active
	 * request, or we'll corrupt the lists.
	 */
	if (track)
		list_move_tail(&req->list, track);
	if (req->order > aio->used_order)
		aio->used_order = req->order;
	req->waiting = waiting;
	(*waiting)++;

	start = (s->offset > req->offset) ? s->offset : req->offset;
	end = (s_end < r_end) ? s_end : r_end;
	len = end - start + 1;

	if (s->offset > req->offset && s_end < r_end) {
		/* This span splits the request, which means it is used up */
		s->size = 0;
	} else if (req->offset > s->offset && r_end < s_end) {
		/* This request splits the span */
		ext2_loff_t noffset = end + 1;
		ssize_t nsize = s_end - noffset + 1;
		rc = add_span(aio, &s->list, noffset, nsize, NULL);
		if (rc)
			return rc;
		s->size = start - s->offset;
	} else {
		if (start == s->offset)
			s->offset += len;
		s->size -= len;
	}

	if (DEBUG) {
		fprintf(stderr, "checking %s, len %ld, new span %llu:%ld\n",
			track ? "queued" : "active",
			len, s->offset, s->size);
	}

	if (!s->size)
		list_move(&s->list, &aio->span_list);

	return 0;
}

static errcode_t aio_read_blk64(io_channel channel, unsigned long long block,
				int count, void *data)
{
	struct aio_data *aio;
	struct cacheblock *cb, *pos;
	struct span *s, *spos;
	struct request *req, *rpos;
	ext2_loff_t offset;
	ssize_t size;
	errcode_t rc;
	LIST_HEAD(spans);
	LIST_HEAD(cloned_spans);
	LIST_HEAD(requests);
	LIST_HEAD(promote);
	struct list_head *needed_spans;
	unsigned int waiting = 0;
	unsigned long orig_used;

	AIO_GET_PRIVATE(channel);

	if (DEBUG)
		fprintf(stderr, "read %llu %d\n", block, count);

	rc = ensure_aio_init(aio);
	if (rc)
		return rc;

	if (aio->in_runqueue)
		return EXT2_ET_OP_NOT_SUPPORTED;

	offset = block * channel->block_size;
	size = (count < 0) ? -count : count * channel->block_size;

	if (DEBUG)
		fprintf(stderr, "read init %llu %ld\n", offset, size);

	rc = add_span(aio, &spans, offset, size, data);
	if (rc)
		return rc;

	orig_used = aio->used_order;
	list_for_each_entry_safe(cb, pos, &aio->cache, list) {
		cb->age++;
		rc = fill_span(aio, &spans, cb);
		if (rc)
			return rc;

		/* If there are no more spans to fill, then we're done. */
		if (list_empty(&spans))
			return run_queue(aio, 0);
	}

	if (DEBUG && aio->used_order != orig_used) {
		fprintf(stderr, "cache moved used from %lu to %lu\n",
				orig_used, aio->used_order);
		orig_used = aio->used_order;
	}

	/* Walk active and queued requests looking for ones that will
 	 * fulfill the  spans. We need a copy of the spans to keep track of
	 * what's still required.
	 */
	if (!list_empty(&aio->active) || !list_empty(&aio->rq)) {
		rc = clone_spans(aio, &spans, &cloned_spans);
		if (rc)
			return rc;

		/* First, search active requests */
		list_for_each_entry(req, &aio->active, active) {
			list_for_each_entry_safe(s, spos, &cloned_spans, list) {
				rc = req_needed_for_span(aio, s, req, &waiting,
							 NULL);
				if (rc)
					return rc;
			}

			if (list_empty(&cloned_spans))
				break;
		}

		/* then queued requests, tracking those that will satisfy
		 * one of the spans
		 */
		list_for_each_entry_safe(req, rpos, &aio->rq, list) {
			list_for_each_entry_safe(s, spos, &cloned_spans, list) {
				rc = req_needed_for_span(aio, s, req, &waiting,
							 &promote);
				if (rc)
					return rc;
			}

			if (list_empty(&cloned_spans))
				break;
		}

		/* If we found any requests to promote, then we can zap the
		 * intervening readahead requests in the assumption that
		 * they will be abandoned.
		 */
		if (!list_empty(&promote)) {
			unsigned count = 0;

			list_for_each_entry_safe(req, rpos, &aio->rq, list) {
				if (req->order > aio->used_order)
					break;
				count++;
				list_move(&req->list, &aio->req_list);
			}

			if (DEBUG) {
				fprintf(stderr, "found queued requests for "
						"read, discarding %u "
						"intervening requests\n",
						count);
			}

			list_splice(&promote, &aio->rq);
		}

		needed_spans = &cloned_spans;
	} else
		needed_spans = &spans;

	if (DEBUG && aio->used_order != orig_used) {
		fprintf(stderr, "requests moved used from %lu to %lu\n",
				orig_used, aio->used_order);
		orig_used = aio->used_order;
	}

	/* convert remaining spans into requests and place at the front
	 * of the queue. Traverse the list in reverse as so that we push
	 * requests into the front of the queue such that they come out
	 * in sequential order.
	 */
	if (DEBUG && !list_empty(needed_spans))
		fprintf(stderr, "making requests for sync read\n");

	list_for_each_entry_safe_reverse(s, spos, needed_spans, list) {
		rc = make_requests(channel, &requests,
					s->offset / channel->block_size,
					-s->size, &waiting, NULL, NULL, 0);
		if (rc)
			return rc;

		list_splice_init(&requests, &aio->rq);

		if (needed_spans == &cloned_spans)
			list_move(&s->list, &aio->span_list);
	}

	if (DEBUG)
		fprintf(stderr, "waiting for %u requests\n", waiting);

	/* wait for needed requests to complete */
	while (waiting) {
		rc = run_queue(aio, 1);
		if (rc)
			return rc;

		/* walk completed requests to fill final spans. We do
		 * this early to free up buffers as we go, as they may be
		 * needed to fulfill our read request
		 */
		list_for_each_entry_safe(cb, pos, &aio->waiting, list) {
			rc = fill_span(aio, &spans, cb);
			if (rc)
				return rc;

			if (cb->size) {
				list_del_init(&cb->list);
				insert_cacheblock(aio, cb);
			}

			/* We're done if we've filled all of the spans. */
			if (list_empty(&spans))
				break;
		}
	}

	list_for_each_entry_safe(cb, pos, &aio->waiting, list) {
		if (cb->size) {
			list_del_init(&cb->list);
			insert_cacheblock(aio, cb);
		}
	}

	if (DEBUG) {
		list_for_each_entry_safe(cb, pos, &aio->cache, list) {
			fprintf(stderr, "cache check %llu:%ld\n",
					cb->offset, cb->size);
		}
	}

	/* The span list should be empty at this point. If not, report
	 * an error. I'd like a better one, but this will have to do for
	 * now.
	 */
	if (!list_empty(&spans)) {
		fprintf(stderr, "Had spans left after read!\n");
		return EXT2_ET_INVALID_ARGUMENT;
	}

	/* We may have freed up some buffers, so try to send off some
	 * more requests.
	 */
	return run_queue(aio, 0);
}

static errcode_t aio_read_blk(io_channel channel, unsigned long block,
				int count, void *data)
{
	return aio_read_blk64(channel, block, count, data);
}

static errcode_t aio_flush(io_channel channel)
{
	/* We don't write, so nothing to flush */
	return 0;
}

static errcode_t aio_write_blk(io_channel channel, unsigned long block,
				int count, const void *data)
{
	return EXT2_ET_OP_NOT_SUPPORTED;
}

static errcode_t aio_write_byte(io_channel channel, unsigned long offset,
				int size, const void *data)
{
	return EXT2_ET_OP_NOT_SUPPORTED;
}

static errcode_t aio_write_blk64(io_channel channel, unsigned long long block,
				int count, const void *data)
{
	return EXT2_ET_OP_NOT_SUPPORTED;
}

static errcode_t aio_async_read(io_channel channel, unsigned long block,
				int count, req_callback_t cb, void *priv1,
				unsigned long priv2)
{
	struct aio_data *aio;
	LIST_HEAD(requests);
	struct request *req, *pos;
	errcode_t rc;

	AIO_GET_PRIVATE(channel);

	rc = ensure_aio_init(aio);
	if (rc)
		return rc;

	if (DEBUG)
		fprintf(stderr, "aio_async_read %lu %d\n", block, count);

	rc = make_requests(channel, &requests, block, count, NULL,
					cb, priv1, priv2);
	if (rc)
		return rc;

	list_for_each_entry_safe(req, pos, &requests, list) {
		list_del_init(&req->list);
		insert_async_req(aio, req);

		aio->num_async++;
		aio->stats.total_async++;
		if (aio->num_async > aio->stats.max_async)
			aio->stats.max_async = aio->num_async;
	}

	return run_queue(aio, 0);
}

static errcode_t aio_finish_async(io_channel channel, unsigned long max_async)
{
	struct aio_data *aio;
	errcode_t rc;

	AIO_GET_PRIVATE(channel);

	rc = ensure_aio_init(aio);
	if (rc)
		return rc;

	if (DEBUG)
		fprintf(stderr, "aio_finish_async\n");

	aio->async_only = 1;
	while (!rc && aio->num_async > max_async)
		rc = run_queue(aio, 1);

	aio->async_only = 0;
	return rc;
}

static errcode_t aio_async_count(io_channel channel, unsigned long *count)
{
	struct aio_data *aio;
	errcode_t rc;

	AIO_GET_PRIVATE(channel);

	rc = ensure_aio_init(aio);
	if (rc)
		return rc;

	*count = aio->num_async;
	return 0;
}

static errcode_t aio_open(const char *name, int flags, io_channel *channel);

static struct struct_io_manager struct_aio_manager = {
	.magic		= EXT2_ET_MAGIC_IO_MANAGER,
	.name		= "Linux AIO Manager",
	.open		= aio_open,
	.close		= aio_close,
	.set_blksize	= aio_set_blksize,
	.read_blk	= aio_read_blk,
	.write_blk	= aio_write_blk,
	.flush		= aio_flush,
	.write_byte	= aio_write_byte,
	.set_option	= aio_set_option,
	.get_stats	= aio_get_stats,
	.read_blk64	= aio_read_blk64,
	.write_blk64	= aio_write_blk64,
#if HAVE_LUSTRE_EXTFS2
	/* only available for Lustre e2fsprogs; make life easy during
	 * development by commenting it out here and providing an alternate
	 * interface
	 */
	.readahead	= aio_readahead,
#endif
};

io_manager aio_io_manager = &struct_aio_manager;

static errcode_t aio_open(const char *name, int flags, io_channel *channel)
{
	io_channel io;
	struct aio_data *aio;
	errcode_t rc;

	if (!name)
		return EXT2_ET_BAD_DEVICE_NAME;

	rc = ext2fs_get_mem(sizeof(struct struct_io_channel), &io);
	if (rc)
		return rc;

	memset(io, 0, sizeof(struct struct_io_channel));
	io->magic = EXT2_ET_MAGIC_IO_CHANNEL;
        rc = ext2fs_get_mem(sizeof(struct aio_data), &aio);
        if (rc)
                goto error_io;

	io->manager = aio_io_manager;
	rc = ext2fs_get_mem(strlen(name) + 1, &io->name);
        if (rc)
                goto error_aio;

	strcpy(io->name, name);
	io->private_data = aio;
	io->block_size = 1024;
	io->read_error = 0;
	io->write_error = 0;
	io->refcount = 1;

	memset(aio, 0, sizeof(struct aio_data));
	aio->magic = EXT2_ET_MAGIC_UNIX_IO_CHANNEL;
	aio->next_order = 1;
	aio->stats.base.num_fields = 2;
	
	INIT_LIST_HEAD(&aio->cb_list);
	INIT_LIST_HEAD(&aio->req_list);
	INIT_LIST_HEAD(&aio->span_list);
	INIT_LIST_HEAD(&aio->cache);
	INIT_LIST_HEAD(&aio->waiting);
	INIT_LIST_HEAD(&aio->active);
	INIT_LIST_HEAD(&aio->rq);
	aio->async_rq = RB_ROOT;
	
	if (flags & IO_FLAG_RW) {
		rc = EXT2_ET_OP_NOT_SUPPORTED;
		goto error_name;
	}

	aio->fd = open(io->name, O_RDONLY | O_DIRECT);
	if (aio->fd < 0) {
		rc = errno;
		goto error_name;
	}

	/* We use O_DIRECT, so we need to align our size to the actual
	 * sector size of the device.
	 */
	if (ioctl(aio->fd, BLKSSZGET, &aio->sector_size) < 0) {
		rc = errno;
		goto error_name;
	}

	*channel = io;
	return 0;

error_name:
	ext2fs_free_mem(&io->name);

error_aio:
	ext2fs_free_mem(&aio);

error_io:
	ext2fs_free_mem(&io);
	return rc;
}

#if !HAVE_LUSTRE_EXTFS2
errcode_t io_channel_readahead(io_channel channel, unsigned long block,
				int count)
{
	/* cannot help the unix manager do readahead here */
	if (channel->manager != aio_io_manager)
		return 0;

	return aio_readahead(channel, block, count);
}
#endif

static unsigned char unix_async_buffer[1024 * 1024];

errcode_t io_channel_async_read(io_channel channel, unsigned long block,
				int count, int (*cb)(ext2_loff_t offset,
							ssize_t size,
							void *priv1,
							unsigned long priv2,
							void *data),
				void *priv1, unsigned long priv2)
{
	errcode_t rc;

	/* Should be checking for existence of method, but that requires
	 * mods to libext2fs we want to defer until merge time.
	 */
	if (channel->manager == aio_io_manager)
		return aio_async_read(channel, block, count, cb, priv1, priv2);

	if (count * channel->block_size > (1024 * 1024))
		return EXT2_ET_FILE_TOO_BIG;

	rc = io_channel_read_blk64(channel, block, count, unix_async_buffer);
	if (!rc) {
		block *= channel->block_size;
		count *= channel->block_size;
		rc = cb(block, count, priv1, priv2, unix_async_buffer);
	}
	return rc;
}

errcode_t io_channel_finish_async(io_channel channel, unsigned long max_async)
{
	/* Should be checking for existence of method, but that requires
	 * mods to libext2fs we want to defer until merge time.
	 */
	if (channel->manager != aio_io_manager)
		return 0;
	return aio_finish_async(channel, max_async);
}

errcode_t io_channel_async_count(io_channel channel, unsigned long *count)
{
	/* Should be checking for existence of method, but that requires
	 * mods to libext2fs we want to defer until merge time.
	 */
	if (channel->manager != aio_io_manager)
		return 0;
	return aio_async_count(channel, count);
}
