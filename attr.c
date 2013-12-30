/* attr.c -- extended attribute handling
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "lester.h"

unsigned long ea_ext_value_read = 0;
unsigned long ea_ext_block_read = 0;

static void ea_complete_read(struct ea_info *eas)
{
	eas->pending--;
	if (!eas->pending)
		eas->done(eas->data);
}

static int ea_block_copy(ext2_loff_t offset, ssize_t size, void *priv1,
			 unsigned long file_block, void *data)
{
	/* We've read a portion of the EA, so copy it into our storage
	 * as we're not guaranteed this is all of it.
	 */
	struct ea_info *eas = priv1;
	void *dst = eas->value + (file_block * fs->blocksize);

	/* If this is the last block of the value, we may only do a partial
	 * copy.
	 */
	if ((eas->value_len / fs->blocksize) == file_block)
		size = eas->value_len % fs->blocksize;

	memcpy(dst, data, size);
	ea_complete_read(eas);
	return 0;
}

static int ea_block_iter_cb(ext2_filsys fs, blk64_t blocknr,
			    e2_blkcnt_t blockcnt, void *priv)
{
	struct ea_info *eas = priv;
	errcode_t rc;

	if (blocknr < 0)
		return 0;

	eas->pending++;
	rc = io_channel_async_read(fs->io, blocknr, 1, ea_block_copy,
				   eas, blockcnt);
	if (rc) {
		com_err("ea_block_iter_cb", rc, "during async_read launch\n");
		return BLOCK_ABORT;
	}
	return 0;
}

static void ea_block_iter_end(ext2_filsys fs, errcode_t error, void *priv)
{
	struct ea_info *eas = priv;

	if (error) {
		com_err("ea_block_iter_end", error, "during iteration\n");
		exit(1);
	}

	/* Drop the ref we held during the iteration; we've submitted all
	 * of our requests, so we're safe to do the callback once all of
	 * them complete.
	 */
	ea_complete_read(eas);
}

static int ea_block_iter_cb_sync(ext2_filsys fs, blk64_t *block_nr,
				 e2_blkcnt_t blockcnt, blk64_t ref_block,
				 int ref_offset, void *priv_data)
{
	return ea_block_iter_cb(fs, *block_nr, blockcnt, priv_data);
}

static int ea_read_inode_cb(ext2_filsys fs, ext2_ino_t ino,
			    struct ext2_inode *inode, void *priv)
{
	struct ea_info *eas = priv;
	errcode_t rc;

	if (EXT2_I_SIZE(inode) != eas->value_len) {
		fprintf(stderr, "inode size does not match EA size\n");
		exit(1);
	}

	/* Squirrel away the inode, as the block iteration may need it --
	 * this is somewhat future-proofing, as it currently won't need
	 * it after the inital call returns, but properly handling extents
	 * in an async manner may.
	 *
	 * To ensure we don't prematurely complete the EA read request
	 * before all of the async IO completes -- ie, one read completes
	 * before we can submit the second -- we hold an extra reference
	 * while the iteration proceeds.
	 */
	memcpy(eas->inode, inode, EXT2_INODE_SIZE(fs->super));
	eas->pending++;
	if (use_unix) {
		rc = ext2fs_block_iterate3(fs, eas->ext_ino, 0, NULL,
					   ea_block_iter_cb_sync, eas);
		if (rc) {
			com_err("ext2fs_block_iterate2", rc,
				"failed during ea block iteration\n");
			return 1;
		}

		/* The iteration was synchronous, so we can drop our ref now */
		ea_complete_read(eas);
	} else {
		rc = ext2fs_block_iterate_async(fs, eas->ext_ino, eas->inode,
						ea_block_iter_cb,
						ea_block_iter_end, eas);
		if (rc) {
			com_err("ext2fs_block_iterate_async", rc,
				"failed to initiate ea async iteration");
			return 1;
		}
	}

	return 0;
}

static void iterate_ea_entries(void *ea_data,
		       void (*cb)(struct ext2_ext_attr_entry *, void *, void *),
		       void *base, void *data)
{
	struct ext2_ext_attr_entry *entry;
	for (entry = (struct ext2_ext_attr_entry *) ea_data;
			!EXT2_EXT_IS_LAST_ENTRY(entry);
			entry = EXT2_EXT_ATTR_NEXT(entry)) {
		cb(entry, base, data);
	}
}

static void count_entries(struct ext2_ext_attr_entry *entry, void *base,
			  void *data)
{
	unsigned int *n = data;
	*n += 1;
}

static void parse_entry(struct ext2_ext_attr_entry *entry, void *base,
			void *data)
{
	struct ea_info **ea_iter = data;
	struct ea_info *ea = *ea_iter;

	/* Ugh; some installed libe2fs headers don't have e_name, so
	 * we have to hardcode the offset here. Similarly for e_value_inum;
	 * it is also known as e_value_block, but points to an inode that
	 * holds the value.
	 */
	ea->name	= (char *) entry + 16;
	ea->ext_ino	= *((unsigned int *) entry + 1);
	ea->index	= entry->e_name_index;
	ea->name_len	= entry->e_name_len;
	ea->value_len	= entry->e_value_size;
	if (!ea->ext_ino)
		ea->value = (char *) base + entry->e_value_offs;

	*ea_iter += 1;
}

struct ea_info *build_ea_info(struct ext2_inode *in, void *ext_attr)
{
	/* NOTE: the returned ea_info chain points into the memory given
	 * to this function; if you reuse that memory, you must copy
	 * the old contents elsewhere and call ea_memory_change() to
	 * reparse and copy the requests over.
	 */
	struct ext2_inode_large *inode = (struct ext2_inode_large *) in;
	struct ext2_ext_attr_header *hdr;
	struct ea_info *ea, *ea_iter;
	char *start;
	unsigned int count = 1;

	start = (char *)inode + EXT2_GOOD_OLD_INODE_SIZE +
			inode->i_extra_isize + sizeof(__u32);
	iterate_ea_entries(start, count_entries, start, &count);

	if (ext_attr) {
		/* Check that the external attribute block is still valid */
		hdr = (struct ext2_ext_attr_header *) ext_attr;
		if (hdr->h_magic == EXT2_EXT_ATTR_MAGIC && hdr->h_blocks == 1)
			iterate_ea_entries(hdr + 1, count_entries, hdr, &count);
		else
			ext_attr = NULL;
	}

	ea = calloc(count, sizeof(*ea));
	if (!ea) {
		fprintf(stderr, "unable to allocate EA info storage\n");
		exit(1);
	}

	ea_iter = ea;
	iterate_ea_entries(start, parse_entry, start, &ea_iter);
	if (ext_attr)
		iterate_ea_entries(hdr + 1, parse_entry, hdr, &ea_iter);

	return ea;
}

void release_ea_info(struct ea_info *ea)
{
	struct ea_info *entry;

	if (ea == NULL)
		return;

	for (entry = ea; entry->name; entry++) {
		if (entry->allocated)
			free(entry->value);
	}
	if (ea->inode)
		free(ea->inode);
	free(ea);
}

struct ea_info *ea_memory_change(struct ea_info *orig, struct ext2_inode *in,
				 void *ext_attr)
{
	/* The memory for the inode or external attribute block changed,
	 * so we need to reindex the EA info structure -- build a new one
	 * and copy the requests over from the old one. Both lists will
	 * be in the same order.
	 */
	struct ea_info *o_ea, *n_ea, *eas;

	eas = build_ea_info(in, ext_attr);
	for (o_ea = orig, n_ea = eas; o_ea->name; o_ea++, n_ea++) {
		n_ea->requested = o_ea->requested;
		if (o_ea->allocated) {
			n_ea->allocated = o_ea->allocated;
			n_ea->value = o_ea->value;
		}
	}

	if (orig->inode)
		free(orig->inode);
	free(orig);

	return eas;
}

void async_read_ea_value(struct ea_info *eas, void (*done)(void *), void *data)
{
	/* Read the value of an external EA value from the blocks associated
	 * with the inode in the descriptor. We need to set aside space for
	 * the EA value, and read the inode. From there, we'll iterate its
	 * blocks and read into the appropriate place in the buffer.
	 */
	errcode_t rc;

	if (eas->value) {
		fprintf(stderr, "BUG: async_read_ea_value with non-NULL val\n");
		exit(1);
	}
	if (!eas->ext_ino) {
		fprintf(stderr, "BUG: async_read_ea_value with inode 0\n");
		exit(1);
	}

	/* Store our callback info for later use. */
	eas->done = done;
	eas->data = data;
	eas->allocated = 1;
	eas->value = malloc(eas->value_len);
	eas->inode = malloc(EXT2_INODE_SIZE(fs->super));
	if (!eas->value || !eas->inode) {
		fprintf(stderr, "unable to allocate external attr data\n");
		exit(1);
	}

	rc = ext2fs_read_inode_async(fs, eas->ext_ino, NULL,
				     ea_read_inode_cb, eas);
	if (rc) {
		com_err("ext2fs_read_inode_async", rc,
			"initiating ea inode read");
		exit(1);
	}

	ea_ext_value_read++;
}
