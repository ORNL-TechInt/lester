/* block_async.c --- async read-only iteration over all blocks in an inode
 *
 * Copyright (C) 1993, 1994, 1995, 1996 Theodore Ts'o.
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU Library Public
 * License, version 2.
 */
#include <stdio.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ext2fs/ext2_fs.h>
#include <ext2fs/ext2fs.h>

#include "ext2fs-extra.h"

struct block_async_context {
	ext2_filsys	fs;
	int (*func)(ext2_filsys	fs,
		    blk64_t	blocknr,
		    e2_blkcnt_t count,
		    void	*priv_data);
	void (*end)(ext2_filsys	fs,
		    errcode_t	errcode,
		    void	*priv_data);
	errcode_t	errcode;
	e2_blkcnt_t	count;
	void		*priv_data;
	unsigned long	use_count;
};

static int block_iterate_async_ind(ext2_loff_t offset, ssize_t size,
					void *private, unsigned long priv2,
					void *data)
{
	struct block_async_context *ctx = private;
	blk_t *block_nr = data;
	e2_blkcnt_t bcount = priv2;
	int i, limit, flags;

	limit = ctx->fs->blocksize / sizeof(blk_t);
	for (i = 0; i < limit; i++, bcount++, block_nr++) {
		if (*block_nr == 0)
			continue;
#ifdef WORDS_BIGENDIAN
                *block_nr = ext2fs_swab32(*block_nr);
#endif
		flags = (*ctx->func)(ctx->fs, *block_nr, bcount, ctx->priv_data);
		if (flags & BLOCK_ABORT)
			break;
	}

	if (!--ctx->use_count) {
		if (ctx->end)
			(*ctx->end)(ctx->fs, ctx->errcode, ctx->priv_data);
		ext2fs_free_mem(&ctx);
	}

	return 0;
}

static int block_iterate_async_dind(ext2_loff_t offset, ssize_t size,
					void *private, unsigned long priv2,
					void *data)
{
	struct block_async_context *ctx = private;
	blk_t *block_nr = data;
	e2_blkcnt_t bcount = priv2;
	int i, limit;
	errcode_t rc;

	limit = ctx->fs->blocksize / sizeof(blk_t);
	for (i = 0; i < limit; i++, block_nr++, bcount += limit) {
		if (*block_nr == 0)
			continue;
#ifdef WORDS_BIGENDIAN
                *block_nr = ext2fs_swab32(*block_nr);
#endif
		if (*block_nr >= ctx->fs->super->s_blocks_count ||
		    *block_nr < ctx->fs->super->s_first_data_block) {
			if (!ctx->errcode)
				ctx->errcode = EXT2_ET_BAD_IND_BLOCK;
			break;
		}
		rc = io_channel_async_read(ctx->fs->io, *block_nr, 1,
						block_iterate_async_ind,
						ctx, bcount);
		if (rc) {
			if (!ctx->errcode)
				ctx->errcode = rc;
			break;
		}
		ctx->use_count++;
	}

	if (!--ctx->use_count) {
		if (ctx->end)
			(*ctx->end)(ctx->fs, ctx->errcode, ctx->priv_data);
		ext2fs_free_mem(&ctx);
	}

	return 0;
}

static int block_iterate_async_tind(ext2_loff_t offset, ssize_t size,
					void *private, unsigned long priv2,
					void *data)
{
	struct block_async_context *ctx = private;
	blk_t *block_nr = data;
	e2_blkcnt_t bcount = priv2;
	int i, limit;
	errcode_t rc;

	limit = ctx->fs->blocksize / sizeof(blk_t);
	for (i = 0; i < limit; i++, block_nr++, bcount += limit * limit) {
		if (*block_nr == 0)
			continue;
#ifdef WORDS_BIGENDIAN
                *block_nr = ext2fs_swab32(*block_nr);
#endif
		if (*block_nr >= ctx->fs->super->s_blocks_count ||
		    *block_nr < ctx->fs->super->s_first_data_block) {
			if (!ctx->errcode)
				ctx->errcode = EXT2_ET_BAD_DIND_BLOCK;
			break;
		}
		rc = io_channel_async_read(ctx->fs->io, *block_nr, 1,
						block_iterate_async_dind,
						ctx, bcount);
		if (rc) {
			if (!ctx->errcode)
				ctx->errcode = rc;
			break;
		}
		ctx->use_count++;
	}

	if (!--ctx->use_count) {
		if (ctx->end)
			(*ctx->end)(ctx->fs, ctx->errcode, ctx->priv_data);
		ext2fs_free_mem(&ctx);
	}

	return 0;
}

errcode_t ext2fs_block_iterate_async(ext2_filsys fs,
				ext2_ino_t ino,
				struct ext2_inode *inode,
				int (*func)(ext2_filsys fs,
					    blk64_t	blocknr,
					    e2_blkcnt_t count,
					    void	*priv_data),
				void (*end)(ext2_filsys	fs,
					    errcode_t	errcode,
					    void	*priv_data),
				void *priv_data)
{
	int	i;
	int	ret = 0;
	struct ext2_inode local_inode;
	errcode_t	retval;
	struct block_async_context *ctx;
	int	limit;
	blk64_t	block_nr;
	int called = 0;
	e2_blkcnt_t blockcnt = 0;

	EXT2_CHECK_MAGIC(fs, EXT2_ET_MAGIC_EXT2FS_FILSYS);

	/* TODO To make this interface truely asynchronous, we need
	 * to ensure that we are passed in an inode to work with, or
	 * add some state tracking info to our context.
	 *
	 * ext2fs_extent_open2() will not do any IO if it is passed in
	 * the contents of the inode, but we will need to import
	 * ext2fs_extent_get() and modify it into ext2fs_extent_get_async(),
	 * along with the tracking info (and block storage) required to
	 * avoid blocking requests.
	 *
	 * For now, we'll punt since we expect to run on the MDS and most of
	 * our extents should fit in the inode.
	 */
	if (!inode) {
		inode = &local_inode;
		retval = ext2fs_read_inode(fs, ino, inode);
		if (retval)
			return retval;
	}

	retval = ext2fs_get_mem(sizeof(struct block_async_context), &ctx);
	if (retval)
		return retval;

	limit = fs->blocksize >> 2;

	ctx->fs = fs;
	ctx->func = func;
	ctx->end = end;
	ctx->errcode = 0;
	ctx->priv_data = priv_data;
	ctx->use_count = 1;

	if (inode->i_flags & EXT4_EXTENTS_FL) {
		ext2_extent_handle_t	handle;
		struct ext2fs_extent	extent;
		blk64_t			blk, new_blk;
		int			op = EXT2_EXTENT_ROOT;
		unsigned int		j;

		retval = ext2fs_extent_open2(fs, ino, inode, &handle);
		if (retval)
			goto errout;

		while (1) {
			retval = ext2fs_extent_get(handle, op, &extent);
			if (retval) {
				if (retval == EXT2_ET_EXTENT_NO_NEXT)
					retval = 0;
				break;
			}

			op = EXT2_EXTENT_NEXT;
			blk = extent.e_pblk;

			if (!(extent.e_flags & EXT2_EXTENT_FLAGS_LEAF))
				continue;

			for (blockcnt = extent.e_lblk, j = 0;
			     j < extent.e_len;
			     blk++, blockcnt++, j++) {
				new_blk = blk;
				called = 1;
				ret = (*ctx->func)(fs, new_blk, blockcnt,
								priv_data);
				if (ret & BLOCK_ABORT)
					goto extent_errout;
			}
		}

	extent_errout:
		ext2fs_extent_free(handle);
		ctx->errcode = retval;
		goto errout;
	}

	/*
	 * Iterate over normal data blocks
	 */
	for (i = 0; i < EXT2_NDIR_BLOCKS ; i++, blockcnt++) {
		if (inode->i_block[i]) {
			called = 1;
			ret |= (*ctx->func)(fs, inode->i_block[i], blockcnt,
								priv_data);
			if (ret & BLOCK_ABORT)
				goto errout;
		}
	}

	if (inode->i_block[EXT2_IND_BLOCK]) {
		block_nr = inode->i_block[EXT2_IND_BLOCK];
		if (block_nr >= ctx->fs->super->s_blocks_count ||
		    block_nr < ctx->fs->super->s_first_data_block) {
			ctx->errcode = EXT2_ET_BAD_IND_BLOCK;
			goto errout;
		}
		retval = io_channel_async_read(fs->io, block_nr, 1,
						block_iterate_async_ind,
						ctx, blockcnt);
		if (retval) {
			ctx->errcode = retval;
			goto errout;
		}
		ctx->use_count++;
		called = 1;
	}
	blockcnt += limit;

	if (inode->i_block[EXT2_DIND_BLOCK]) {
		block_nr = inode->i_block[EXT2_DIND_BLOCK];
		if (block_nr >= ctx->fs->super->s_blocks_count ||
		    block_nr < ctx->fs->super->s_first_data_block) {
			ctx->errcode = EXT2_ET_BAD_DIND_BLOCK;
			goto errout;
		}
		retval = io_channel_async_read(fs->io, block_nr, 1,
						block_iterate_async_dind,
						ctx, blockcnt);
		if (retval) {
			ctx->errcode = retval;
			goto errout;
		}
		ctx->use_count++;
		called = 1;
	}
	blockcnt += limit * limit;

	if (inode->i_block[EXT2_TIND_BLOCK]) {
		block_nr = inode->i_block[EXT2_TIND_BLOCK];
		if (block_nr >= ctx->fs->super->s_blocks_count ||
		    block_nr < ctx->fs->super->s_first_data_block) {
			ctx->errcode = EXT2_ET_BAD_TIND_BLOCK;
			goto errout;
		}
		retval = io_channel_async_read(fs->io, block_nr, 1,
						block_iterate_async_tind,
						ctx, blockcnt);
		if (retval) {
			ctx->errcode = retval;
			goto errout;
		}
		ctx->use_count++;
		called = 1;
	}

errout:
	if (!--ctx->use_count) {
		if (called && ctx->end)
			(*ctx->end)(fs, ctx->errcode, ctx->priv_data);
		ext2fs_free_mem(&ctx);
	}

	if (called)
		retval = 0;
	return retval;
}
