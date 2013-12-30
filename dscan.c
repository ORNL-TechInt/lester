/* dscan.c -- Directory scan and naming phase of Lester
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * Some of this code is derived from Lustre e2fsprogs/e2scan; this file may may
 * be redistributed under the terms of the GNU General Public License version
 * 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>
#include "lester.h"

/* Lustre extended the file type in ext2_dir_entry_2; provide a helper so
 * we can be backwards compatible
 */
#ifndef EXT2_FT_MASK
#define EXT2_FT_MASK	0x0f
#endif

unsigned long dentries_freed = 0;
unsigned long dentries_created = 0;

struct attr_state {
	struct dentry *dentry;
	struct ea_info *eas;
	void *ext_attr_block;
	unsigned int pending_ios;
	struct ext2_inode inode[0];
};

struct chunk {
	blk64_t start;
	e2_blkcnt_t len;
};

static struct chunk *cur_chunk, *ra_chunk, *chunks;
static e2_blkcnt_t nr_chunks;

static int request_end_dscan;

unsigned long dir_readahead = 0;

static void release_state(struct attr_state *state)
{
	release_ea_info(state->eas);
	if (state->ext_attr_block)
		free(state->ext_attr_block);
	if (state->dentry)
		put_dentry(state->dentry);
	free(state);
}

static void dscan_ea_done(void *data)
{
	/* We completed reading in a requested EA; see if it is time
	 * to retry the dscan action
	 */
	struct attr_state *state = data;
	struct dentry *dentry = state->dentry;
	int action;

	state->pending_ios--;
	if (state->pending_ios)
		return;

	if (is_file_interesting(dentry->ino)) {
		action = scan_action->dscan(dentry->ino, state->inode,
					    dentry->d_parent, dentry->name,
					    dentry->namelen, state->eas);

		if (action & ACTION_IGNORE_FILE)
			ignore_file(dentry->ino);

		if (action & ACTION_END_SCAN) {
			request_end_dscan = 1;
		} else if (action & ~ACTION_IGNORE_FILE) {
			fprintf(stderr, "BUG: dscan action final attempt did "
					"not complete\n");
			exit(1);
		}
	}

	release_state(state);
}

static unsigned int validate_ea_reads(struct ea_info *ea)
{
	unsigned int ea_reqs = 0;

	for ( ; ea->name; ea++) {
		if (!ea->requested)
			continue;

		ea_reqs++;
		if (!ea->ext_ino) {
			fprintf(stderr, "BUG: dscan action requested "
					"read of non-external attr\n");
			exit(1);
		}
	}

	if (!ea_reqs) {
		fprintf(stderr, "BUG: dscan action requested extern "
				"attr read, but flagged none\n");
		exit(1);
	}

	return ea_reqs;
}
		
static int read_ext_attr_cb(ext2_loff_t offset, ssize_t size, void *priv1,
			    unsigned long priv2, void *xattr)
{
	/* We just read in the external xattr block for this inode; we need
	 * to parse the EA chain and hand it to our dscan action. We may
	 * still have more IO to do if any of the EA values are stored in
	 * external files/inodes.
	 */
	struct attr_state *state = priv1;
	struct dentry *dentry = state->dentry;
	unsigned int ea_reqs = 0;
	struct ea_info *ea;
	int action;

	ea_ext_block_read++;

	if (!is_file_interesting(dentry->ino))
		goto complete;

	state->eas = build_ea_info(state->inode, xattr);
	action = scan_action->dscan(dentry->ino, state->inode, 
				    dentry->d_parent, dentry->name,
				    dentry->namelen, state->eas);

	if (action & ACTION_IGNORE_FILE)
		ignore_file(dentry->ino);

	if (action & ACTION_WANT_READ_ATTRS)
		ea_reqs = validate_ea_reads(state->eas);

	if (action & ACTION_END_SCAN) {
		request_end_dscan = 1;
		goto complete;
	}

	action &= ~(ACTION_IGNORE_FILE | ACTION_END_SCAN);
	if (action == ACTION_COMPLETE)
		goto complete;

	/* We need to keep the external attribute block around... */
	state->ext_attr_block = malloc(fs->blocksize);
	if (!state->ext_attr_block) {
		fprintf(stderr, "Unable to allocate attr block\n");
		exit(1);
	}
	memcpy(state->ext_attr_block, xattr, fs->blocksize);
	state->eas = ea_memory_change(state->eas, state->inode,
				      state->ext_attr_block);

	/* initiate file read (inode) for each EA requested; keep an extra
	 * pending virtual IO while submitting the async requests to avoid
	 * early completion.
	 */
	state->pending_ios = ea_reqs + 1;
	for (ea = state->eas; ea->name; ea++) {
		if (ea->requested)
			async_read_ea_value(ea, dscan_ea_done, state);
	}

	dscan_ea_done(state);
	return 0;

complete:
	release_state(state);
	return 0;
}

static int read_inode_attr_cb(ext2_filsys fs, ext2_ino_t ino,
			      struct ext2_inode *inode, void *priv)
{
	/* The action requested the inode and EAs; see if we need to
	 * read in an external block to satisfy the EA info. If not,
	 * go ahead and parse the EAs and call the action again; we may
	 * still have to store state if any of the EA values are in separate
	 * inodes, though...
	 */
	struct dentry *dentry = priv;
	struct ea_info *ea, *eas = NULL;
	struct attr_state *state;
	unsigned int ea_reqs = 0;
	ssize_t inode_size;
	int action;

	if (!is_file_interesting(ino))
		goto complete;

	if (!inode->i_file_acl) {
		eas = build_ea_info(inode, NULL);
		action = scan_action->dscan(ino, inode, dentry->d_parent,
					    dentry->name, dentry->namelen,
					    eas);

		if (action & ACTION_IGNORE_FILE)
			ignore_file(ino);

		if (action & ACTION_WANT_READ_ATTRS)
			ea_reqs = validate_ea_reads(eas);

		if (action & ACTION_END_SCAN) {
			request_end_dscan = 1;
			goto complete;
		}

		action &= ~(ACTION_IGNORE_FILE | ACTION_END_SCAN);
		if (action == ACTION_COMPLETE)
			goto complete;
	}

	/* We have more IO to do for this dscan action; save our inode
	 * (and/or EA info) for later use.
	 */
	inode_size = EXT2_INODE_SIZE(fs->super);
	state = (struct attr_state *) calloc(1, sizeof(*state) + inode_size);
	if (!state) {
		fprintf(stderr, "unable to allocate attribute state buffer\n");
		exit(1);
	}

	state->dentry = dentry;
	memcpy(state->inode, inode, inode_size);
	if (eas)
		state->eas = ea_memory_change(eas, state->inode, NULL);

	if (inode->i_file_acl) {
		return io_channel_async_read(fs->io, inode->i_file_acl, 1,
					     read_ext_attr_cb, state, 0);
	}

	/* initiate file read (inode) for each EA requested; keep an extra
	 * pending virtual IO while submitting the async requests to avoid
	 * early completion.
	 */
	state->pending_ios = ea_reqs + 1;
	for (ea = state->eas; ea->name; ea++) {
		if (ea->requested)
			async_read_ea_value(ea, dscan_ea_done, state);
	}
	dscan_ea_done(state);
	return 0;

complete:
	release_ea_info(eas);
	put_dentry(dentry);
	return 0;
}

static int read_inode_cb(ext2_filsys fs, ext2_ino_t ino,
			 struct ext2_inode *inode, void *priv)
{
	/* Called to report a file after async inode read completes */
	struct dentry *dentry = priv;
	int action;

	/* The previous action call did not request attribute info, so no
	 * need to parse them here.
	 */
	if (is_file_interesting(ino)) {
		action = scan_action->dscan(ino, inode, dentry->d_parent,
					    dentry->name, dentry->namelen,
					    NULL);

		if (action & ACTION_IGNORE_FILE)
			ignore_file(ino);

		if (action & ACTION_END_SCAN) {
			request_end_dscan = 1;
		} else if (action & ~ACTION_IGNORE_FILE) {
			fprintf(stderr, "BUG: action didn't complete "
					"(expanded info request)\n");
			exit(1);
		}
	}

	put_dentry(dentry);
	return 0;
}


int path_resolved(ext2_ino_t ino, struct dentry *parent, const char *name,
		  int namelen, struct dentry *entry)
{
	errcode_t rc = 0;
	int action;

	/* We have a name, see if we care about the inode or attributes */
	action = scan_action->dscan(ino, NULL, parent, name, namelen, NULL);
	if (!action)
		return 0;

	if (action & ACTION_IGNORE_FILE) {
		if (action & ~(ACTION_IGNORE_FILE | ACTION_END_SCAN)) {
			fprintf(stderr, "BUG: action ignored file but wanted "
					"callback with more info\n");
			exit(1);
		}
		ignore_file(ino);
	}

	if (action & (ACTION_WANT_INODE | ACTION_WANT_ATTRS)) {
		if (!entry) {
			/* We're guaranteed to be a file here, as all dirs
			 * get created during the inode scan. As a dentry
			 * only needs to know its child dirs, we don't go
			 * on that list.
			 */
			entry = create_dentry(ino);
			dentry_attach_name(entry, namelen, name);
			entry->d_parent = parent;
			entry->is_file = 1;
			get_dentry(parent);
		} else
			get_dentry(entry);

		/* We need the inode for both cases, but if the action
		 * signals it wants attributes, then make sure we have them
		 * before calling back.
		 */
		if (action & ACTION_WANT_ATTRS) {
			rc = ext2fs_read_inode_async(fs, ino, NULL,
						     read_inode_attr_cb, entry);
		} else {
			rc = ext2fs_read_inode_async(fs, ino, NULL,
						     read_inode_cb, entry);
		}
		if (rc) {
			com_err("ext2fs_read_inode_async", rc,
				"initiating read");
			exit(1);
		}

		if (enforce_async_limit())
			exit(1);
	}

	if (action & ACTION_END_SCAN) {
		request_end_dscan = 1;
		return 1;
	}

	return 0;
}

/* Collapse the dblist into a list of contiguous sections; this is called
 * by ext2fs_dblist_iterate2().
 */
static int fill_chunks(ext2_filsys fs, struct ext2_db_entry2 *db_info,
		       void *priv_data)
{
	if (cur_chunk == NULL ||
			db_info->blk != cur_chunk->start + cur_chunk->len) {
		/* new sweep starts */
		if (cur_chunk == NULL)
			cur_chunk = chunks;
		else
			cur_chunk++;
		cur_chunk->start = db_info->blk;
		cur_chunk->len = 1;
	} else
		cur_chunk->len++;

	return 0;
}

/* Count the number of contiguous segments in the dblist; this is called
 * by ext2fs_dblist_iterate2().
 */
static int count_chunks(ext2_filsys fs, struct ext2_db_entry2 *db_info,
			void *priv_data)
{
	static blk64_t start = ~(blk64_t)0;
	static e2_blkcnt_t len;

	if (start == ~(blk64_t)0) {
		nr_chunks++;
		start = db_info->blk;
		len = 1;
		return 0;
	}

	if (db_info->blk != start + len) {
		nr_chunks++;
		start = db_info->blk;
		len = 1;
	} else
		len++;

	return 0;
}

static void start_dblist_readahead(unsigned long grpra)
{
	/* First, we generate a list of the contiguous runs of directory
	 * blocks, then we'll start readahead for the first few.
	 */
	ext2fs_dblist_iterate2(fs->dblist, count_chunks, NULL);
	chunks = malloc(sizeof(struct chunk) * nr_chunks);
	if (chunks == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(1);
	}
	ext2fs_dblist_iterate2(fs->dblist, fill_chunks, NULL);

	/* start readahead for first chunks */
	ra_chunk = chunks;
	cur_chunk = NULL;

	while (grpra-- && ra_chunk < chunks + nr_chunks) {
		io_channel_readahead(fs->io, ra_chunk->start, ra_chunk->len);
		ra_chunk++;
	}
}

static int dblist_readahead(void)
{
	if (cur_chunk == NULL)
		cur_chunk = chunks;
	if (--cur_chunk->len == 0) {
		cur_chunk++;
		if (ra_chunk < chunks + nr_chunks) {
			io_channel_readahead(fs->io, ra_chunk->start,
					     ra_chunk->len);
			ra_chunk++;
		}
	}
	return 0;
}

static int dblist_iterate_cb(ext2_ino_t dirino, int entry,
			     struct ext2_dir_entry *dirent, int offset,
			     int blocksize, char *buf, void *private)
{
	struct ext2_dir_entry_2 *dirent2;
	int namelen;

	static struct dentry *parent;
	static ext2_ino_t lastino;

	if (request_end_dscan)
		return DIRENT_ABORT;

	/* We ask for empty directory entries in order to detect when we
	 * transistion to the next block, indicated by offset == 0. As we
	 * move to a new directory block, release the reference held by
	 * iscan.c:block_async_iter_cb() on the previous directory's dentry.
	 *
	 * Note: this will leave a few dentries in the tree once we're
	 * finished with the iteration, as we'll not do the final
	 * put_dentry() on the last directory we iterate.
	 */
	if (offset == 0) {
		dblist_readahead();
		if (parent)
			put_dentry(parent);
		if (dirino != lastino) {
			parent = find_dentry(dirino);
			lastino = dirino;
		}
	}

	if (dirent->inode == 0)
		return 0;

	namelen = (dirent->name_len & 0xFF);
	if (namelen == 2 && !strncmp(dirent->name, "..", 2))
		return 0;

	if (namelen == 1 && !strncmp(dirent->name, ".", 1))
		return 0;

	if (dirent->inode > fs->super->s_inodes_count) {
		fprintf(stderr, "BUG: too big ino %u (%.*s)\n",
			dirent->inode, namelen, dirent->name);
		exit(1);
	}

	/* TODO propogate error/stop actions */
	dirent2 = (struct ext2_dir_entry_2 *) dirent;
	if ((dirent2->file_type & EXT2_FT_MASK) == EXT2_FT_DIR)
		dtree_name_dir(parent, dirent->inode, dirent->name, namelen);
	else
		dtree_name_file(parent, dirent->inode, dirent->name, namelen);
	return 0;
}

int resolve_paths(void)
{
	struct timeval start, now, diff;
	aio_stats stats;
	errcode_t rc;

	gettimeofday(&start, NULL);

	if (scan_action->dscan_begin) {
		if (scan_action->dscan_begin() & ACTION_END_SCAN)
			return 0;
	}

	if (verbosity) {
		fprintf(stdout, "scanning %u directory blocks\n",
				ext2fs_dblist_count(fs->dblist));
	}

	start_dblist_readahead(dir_readahead);

	gettimeofday(&now, NULL);
	diff_timevals(&start, &now, &diff);
	start = now;

	if (verbosity) {
		fprintf(stdout, "started dblist readahead in %d.%06u seconds\n",
			(int) diff.tv_sec, (unsigned int) diff.tv_usec);
	}

	rc = ext2fs_dblist_dir_iterate(fs->dblist, DIRENT_FLAG_INCLUDE_EMPTY,
					NULL, dblist_iterate_cb, NULL);
	if (rc) {
		com_err("ext2fs_dblist_dir_iterate", rc,
			"dir iterating dblist\n");
		return 1;
	}

	gettimeofday(&now, NULL);
	diff_timevals(&start, &now, &diff);
	start = now;

	if (verbosity) {
		fprintf(stdout, "finished directory scan in %d.%06u\n",
			(int) diff.tv_sec, (unsigned int) diff.tv_usec);
	}

	if (!use_unix) {
		rc = io_channel_finish_async(fs->io, 0);
		if (rc) {
			com_err("io_channel_finish_async", rc,
				"failed to complete IO");
			return 1;
		}

		gettimeofday(&now, NULL);
		diff_timevals(&start, &now, &diff);
		start = now;
		if (verbosity) {
			fprintf(stdout, "finished remaining dirscan async "
					"work in %d.%06u seconds\n",
					(int) diff.tv_sec,
					(unsigned int) diff.tv_usec);
		}
	}

	if (scan_action->dscan_end) {
		rc = scan_action->dscan_end();
		if (rc)
			return rc;
	}

	if (verbosity && !use_unix) {
		rc = io_channel_get_stats(fs->io, (io_stats *) &stats);
		if (rc) {
			com_err("io_channel_get_stats", rc,
				"failed to get stats");
			return 1;
		}

		fprintf(stdout, "Had total %lu async requests\n",
				stats->total_async);
		fprintf(stdout, "Had max %lu async requests outstanding\n",
				stats->max_async);
		fprintf(stdout, "Inserted %lu async into readahead stream\n",
				stats->async_instream);
		fprintf(stdout, "Issued %lu total requests\n",
				stats->issued_requests);
		fprintf(stdout, "Completed %lu total requests\n",
				stats->completed_requests);
		fprintf(stdout, "Issued %lu merged async requests\n",
				stats->merged_async_issued);
		fprintf(stdout, "Total of %lu async requests merged\n",
				stats->merged_async);
		fprintf(stdout, "Total of %llu gap bytes in merges\n",
				stats->merged_gap_bytes);
	}

	if (verbosity) {
		fprintf(stdout, "Freed %lu of %lu dentries during dscan\n",
				dentries_freed, dentries_created);
		fprintf(stdout, "Read %lu external EA blocks during dscan\n",
				ea_ext_block_read);
		fprintf(stdout, "Read %lu external EA values during dscan\n",
				ea_ext_value_read);
	}

	return 0;
}
