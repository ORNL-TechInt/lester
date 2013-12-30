/* iscan.c -- Inode scan phase of Lester
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * Much of this code is derived from Lustre e2fsprogs/e2scan; this file may
 * may be redistributed under the terms of the GNU General Public License
 * version 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>
#include "lester.h"

struct iscan_state {
	ext2_ino_t ino;
	struct ea_info *eas;
	void *ext_attr_block;
	unsigned int pending_ios;
	struct ext2_inode inode[0];
};

unsigned long grp_readahead = 0;

static unsigned long inode_scanned;
static unsigned long inode_candidate;
static unsigned long inode_path_requested;
static int request_end_iscan;

static char *block_iter_buf;

static struct iscan_state *iscan_save_state(ext2_ino_t ino, void *inode)
{
	size_t inode_size = EXT2_INODE_SIZE(fs->super);
	struct iscan_state *state;

	state = calloc(1, sizeof(*state) + inode_size);
	if (!state) {
		fprintf(stderr, "Unable to allocate iscan state\n");
		exit(1);
	}

	memcpy(state->inode, inode, inode_size);
	state->ino = ino;
	return state;
}

static void release_iscan_state(struct iscan_state *state)
{
	release_ea_info(state->eas);
	if (state->ext_attr_block)
		free(state->ext_attr_block);
	free(state);
}

static errcode_t group_done(ext2_filsys fs, ext2_inode_scan scan, dgrp_t group,
			    void *vp)
{
	int ra_blks;
	static dgrp_t ra_group;
	unsigned int inodes, inode_size;
	blk64_t ra_start;

	/* Start read ahead on the next block group descriptor, taking
	 * care to not run on after the last one, and to only read the
	 * blocks with active data in them.
	 */
	if (ra_group >= fs->group_desc_count)
		return 0;

	/* if we skipped readahead on this one, then don't get too far ahead */
	if (ext2fs_bg_flags(fs, group) & EXT2_BG_INODE_UNINIT)
		return 0;

	while (ext2fs_bg_flags(fs, ra_group) & EXT2_BG_INODE_UNINIT) {
		ra_group++;
		if (ra_group >= fs->group_desc_count)
			return 0;
	}

	ra_start = ext2fs_inode_table_loc(fs, ra_group);
	inodes = EXT2_INODES_PER_GROUP(fs->super);
	inodes -= ext2fs_bg_itable_unused(fs, ra_group);
	inode_size = EXT2_INODE_SIZE(fs->super);
	ra_blks = (inodes + (fs->blocksize / inode_size - 1)) *
			inode_size / fs->blocksize;

	io_channel_readahead(fs->io, ra_start, ra_blks);
	ra_group++;
	return 0;
}


/* Main worker for directory block iteration; add this block to the
 * filesystem's dblist.
 */
static int block_async_iter_cb(ext2_filsys fs, blk64_t blocknr,
			       e2_blkcnt_t blockcnt, void *priv)
{
	ext2_ino_t ino = (ext2_ino_t) (unsigned long) priv;

	/* blockcnt is u64, but the constant for indirect blocks are given
	 * as ints...
	 */
	if ((int) blockcnt < 0)
		return 0;

	if (ext2fs_add_dir_block2(fs->dblist, ino, blocknr, blockcnt))
		return BLOCK_ABORT;

	/* Hold a reference to the dentry for this inode; we created the
	 * entry during the inode scan, and we need to keep it in place
	 * until we iterate every block of the directory contents. The
	 * ref gets released in dscan.c:dblist_iterate_cb().
	 */
	dtree_get_ino(ino);

	return 0;
}

static void block_async_iter_end(ext2_filsys fs, errcode_t error, void *priv)
{
	if (error) {
		com_err("block_iterate_async", error, "during iteration\n");
		exit(1);
	}
}

static int block_iterate_cb(ext2_filsys fs, blk64_t *block_nr,
			    e2_blkcnt_t blockcnt, blk64_t ref_block,
			    int ref_offset, void *priv_data)
{
	return block_async_iter_cb(fs, *block_nr, blockcnt, priv_data);
}

static int add_directory(ext2_ino_t ino, struct ext2_inode *inode)
{
	errcode_t rc;

	dtree_add_dir(ino);

	if (use_unix) {
		rc = ext2fs_block_iterate3(fs, ino, 0, block_iter_buf,
					   block_iterate_cb,
					   (void *)(unsigned long) ino);
		if (rc) {
			com_err("ext2fs_block_iterate2", rc,
				"failed during block iteration\n");
			return 1;
		}
	} else {
		rc = ext2fs_block_iterate_async(fs, ino, inode,
						block_async_iter_cb,
						block_async_iter_end,
						(void *)(unsigned long) ino);
		if (rc) {
			com_err("ext2fs_block_iterate_async", rc,
				"failed to initiate async iteration");
			return 1;
		}

		if (enforce_async_limit())
			return 1;
	}

	return 0;
}

static void iscan_ea_done(void *data)
{
	/* We read in a EA requested by the action; see if we've got all of
	 * them and are ready to retry the iscan action.
	 */
	struct iscan_state *state = data;
	int action;

	state->pending_ios--;
	if (state->pending_ios)
		return;

	action = scan_action->iscan(state->ino, state->inode, state->eas);
	if (action & ACTION_END_SCAN)
		request_end_iscan = 1;
	else if (action & (ACTION_WANT_READ_ATTRS | ACTION_WANT_ATTRS)) {
		fprintf(stderr, "BUG: iscan action final attempt did not "
				"complete\n");
		exit(1);
	} else if (action & ACTION_WANT_PATH) {
		inode_path_requested++;
	} else {
		/* We don't want a path, so we're done with this one. */
		ext2fs_fast_unmark_inode_bitmap2(fs->inode_map, state->ino);
	}

	release_iscan_state(state);
}

static void iscan_read_attrs(struct iscan_state *state)
{
	unsigned int ea_reqs = 0;
	struct ea_info *ea;

	if (!state->eas) {
		fprintf(stderr, "BUG: iscan action wants to read "
				"EAs, but none stored\n");
		exit(1);
	}

	for (ea = state->eas; ea->name; ea++) {
		if (!ea->requested)
			continue;

		ea_reqs++;
		if (!ea->ext_ino) {
			fprintf(stderr, "BUG: iscan action requested "
					"read of non-external attr.\n");
			exit(1);
		}
	}

	if (!ea_reqs) {
		fprintf(stderr, "BUG: iscan action requested extern "
				"attr read, but flagged none.\n");
		exit(1);
	}

	/* initiate a file read for each external EA requested; keep
	 * an extra reference while submitting the requests to avoid
	 * an early completion callback.
	 */
	state->pending_ios = ea_reqs + 1;
	for (ea = state->eas; ea->name; ea++) {
		if (ea->requested)
			async_read_ea_value(ea, iscan_ea_done, state);
	}

	iscan_ea_done(state);
	return;
}

static int iscan_read_attr_cb(ext2_loff_t offset, ssize_t size, void *priv1,
			      unsigned long priv2, void *xattr)
{
	/* We just read in the external xattr block for the inode; parse
	 * the EA chain and hand it to the iscan action. We may have more
	 * IO to do if any of the EA values are stored in an external file.
	 */
	struct iscan_state *state = priv1;
	struct ea_info *eas;
	int action;

	ea_ext_block_read++;
	eas = build_ea_info(state->inode, xattr);
	action = scan_action->iscan(state->ino, state->inode, eas);

	/* Don't try to start new IO if we're ending, but we still need
	 * to clean up our state below.
	 */
	if (action & ACTION_END_SCAN) {
		request_end_iscan = 1;
	} else if (action & ACTION_WANT_READ_ATTRS) {
		/* We need to save the external attribute block, but ea_info
		 * points into it; copy the data, then reparse it. We can
		 * then walk the chains (they will be in the same order)
		 * and transfer the requests over.
		 */
		state->ext_attr_block = malloc(fs->blocksize);
		if (!state->ext_attr_block) {
			fprintf(stderr, "Unable to allocate attr block\n");
			exit(1);
		}
		memcpy(state->ext_attr_block, xattr, fs->blocksize);
		state->eas = ea_memory_change(eas, state->inode,
					      state->ext_attr_block);
		iscan_read_attrs(state);
		/* Don't release state just yet; we still have IO pending */
		return 0;
	} else if (action & ACTION_WANT_PATH) {
		inode_path_requested++;
	} else {
		/* We don't want a path nor the xattr, so this inode
		 * is no longer interesting...
		 */
		ext2fs_fast_unmark_inode_bitmap2(fs->inode_map, state->ino);
	}

	release_ea_info(eas);
	release_iscan_state(state);
	return 0;
}

int scan_inodes(const char *dev)
{
	struct timeval scan_start, scan_end, async_end, diff;
	struct ea_info *eas = NULL;
	struct iscan_state *state;
	struct ext2_inode *inode;
	size_t inode_size;
	ext2_inode_scan scan;
	ext2_ino_t ino;
	errcode_t rc;
	int i, action;

	if (use_unix) {
		rc = ext2fs_get_mem(fs->blocksize * 3, &block_iter_buf);
		if (rc) {
			com_err("ext2fs_get_mem", rc,
				"allocating iter buff\n");
			return 1;
		}
	}

	inode_size = EXT2_INODE_SIZE(fs->super);
	inode = malloc(inode_size);
	if (!inode) {
		fprintf(stderr, "Could not allocate inode storage for scan\n");
		return 1;
	}

	rc = create_root_dentries(root_path);
	if (rc) {
		com_err("create_root_dentries", rc,
			"creating root dentries\n");
		return 1;
	}

	if (scan_action->iscan_begin && scan_action->iscan_begin())
		return 1;

	gettimeofday(&scan_start, NULL);

        rc = ext2fs_open_inode_scan(fs, fs->inode_blocks_per_group, &scan);
        if (rc) {
		com_err("ext2fs_open_inode_scan", rc,
			"opening inode scan on %s\n", dev);
		fprintf(stderr, "failed to open inode scan\n");
		return 1;
	}
	ext2fs_set_inode_callback(scan, group_done, NULL);

	for (i = 0; i < grp_readahead; i++)
		group_done(fs, scan, 0, NULL);

	while (!ext2fs_get_next_inode_full(scan, &ino, inode, inode_size)) {
		if (request_end_iscan || !ino)
			break;

		inode_scanned++;

		/* Deleted inode? */
		if (!ext2fs_fast_test_inode_bitmap2(fs->inode_map, ino))
			continue;

		/* Ignore inodes that hold the external EA values */
		if (inode->i_flags & EXT4_EA_INODE_FL)
			continue;

		inode_candidate++;

		if (LINUX_S_ISDIR(inode->i_mode) && add_directory(ino, inode))
			return 1;

		if (scan_action->flags & ACTION_FLAG_ISCAN_NO_EAS) {
			action = scan_action->iscan(ino, inode, NULL);
		} else if (!inode->i_file_acl) {
			eas = build_ea_info(inode, NULL);
			action = scan_action->iscan(ino, inode, eas);
		} else {
			/* We need to come back to this inode as it has
			 * an external attribute block...
			 */
			state = iscan_save_state(ino, inode);
			rc = io_channel_async_read(fs->io, inode->i_file_acl,
						   1, iscan_read_attr_cb, state,
						   0);
			if (rc) {
				com_err("io_channel_async_read", rc,
					"failed to start IO");
				return 1;
			}
			continue;
		}

		if (action & ACTION_WANT_READ_ATTRS) {
			/* We asked for the externally stored EAs to be read
			 * in, so we need to set up for async IO.
			 */
			state = iscan_save_state(ino, inode);
			state->eas = ea_memory_change(eas, state->inode, NULL);
			iscan_read_attrs(state);

			/* ea_memory_change() releases the EA info, so forget
			 * about it.
			 */
			eas = NULL;
		} else if (action & ACTION_WANT_PATH) {
			inode_path_requested++;
		} else {
			/* We don't want a path nor the xattr, so this inode
			 * is no longer interesting...
			 */
			ext2fs_fast_unmark_inode_bitmap2(fs->inode_map, ino);
		}

		release_ea_info(eas);

		if (action & ACTION_END_SCAN)
			request_end_iscan = 1;
	}

	gettimeofday(&scan_end, NULL);

	ext2fs_close_inode_scan(scan);

	if (!use_unix) {
		rc = io_channel_finish_async(fs->io, 0);
		if (rc) {
			com_err("io_channel_finish_async", rc,
				"failed to complete IO");
			return 1;
		}

		gettimeofday(&async_end, NULL);
	}

	if (verbosity) {
		diff_timevals(&scan_start, &scan_end, &diff);
		fprintf(stdout, "counted %lu inodes (%lu non-deleted) in "
				"%d.%06u\n", inode_scanned, inode_candidate,
				(int) diff.tv_sec, (unsigned int) diff.tv_usec);
	}

	if (verbosity && !use_unix) {
		aio_stats stats;

		diff_timevals(&scan_end, &async_end, &diff);
                fprintf(stdout, "finished remaining inode scan async work in "
				"%d.%06u seconds\n",
	                        (int) diff.tv_sec, (unsigned int) diff.tv_usec);

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
                fprintf(stdout, "Inserted %lu async requests into readahead "
                                "stream\n", stats->async_instream);

                stats->async_instream = 0;
                stats->total_async = stats->max_async = 0;
	}

	if (verbosity) {
		fprintf(stdout, "Read %lu external EA blocks during iscan\n",
				ea_ext_block_read);
		fprintf(stdout, "Read %lu external EA values during iscan\n",
				ea_ext_value_read);

		ea_ext_block_read = ea_ext_value_read = 0;
        }

	if (scan_action->iscan_end && scan_action->iscan_end())
		return 1;

	free(inode);
	return 0;
}
