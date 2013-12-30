/* inode_async.c --- utility routines to asynchronously read inodes
 *
 * Copyright (C) 1993, 1994, 1995, 1996, 1997 Theodore Ts'o.
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU Library Public
 * License, version 2.
 */
#include <ext2fs/ext2fs.h>
#include "ext2fs-extra.h"

int ext2fs_read_inode_async_helper(ext2_loff_t offset, ssize_t size,
					void *priv1, unsigned long priv2,
					void *data)
{
	struct ext2fs_inode_async * async = priv1;
	struct ext2_inode_large *inode = data + priv2;
	int rc;

#ifdef WORDS_BIGENDIAN
	ext2fs_swap_inode_full(async->fs, (struct ext2_inode_large *) inode,
			       (struct ext2_inode_large *) inode,
			       0, EXT2_INODE_SIZE(async->fs->super));
#endif

	rc = async->func(async->fs, async->ino,(struct ext2_inode *) inode,
			 async->priv);
	if (async->allocated)
		ext2fs_free_mem(&async);
	return rc;
}

errcode_t ext2fs_read_inode_async(ext2_filsys fs, ext2_ino_t ino,
				  struct ext2fs_inode_async *async,
				  int (*func)(ext2_filsys fs,
					      ext2_ino_t ino,
					      struct ext2_inode *inode,
					      void *priv),
				  void *priv)
{
	unsigned long 	group, block, block_nr, offset;
	errcode_t	rc;
	int 		blocks;

	EXT2_CHECK_MAGIC(fs, EXT2_ET_MAGIC_EXT2FS_FILSYS);

	if ((ino == 0) || (ino > fs->super->s_inodes_count))
		return EXT2_ET_BAD_INODE_NUM;

	if (!async) {
		rc = ext2fs_get_mem(sizeof(struct ext2fs_inode_async), &async);
		if (rc)
			return rc;
		async->allocated = 1;
	} else
		async->allocated = 0;

	async->fs = fs;
	async->ino = ino;
	async->func = func;
	async->priv = priv;

	group = (ino - 1) / EXT2_INODES_PER_GROUP(fs->super);
	rc = EXT2_ET_BAD_INODE_NUM;
	if (group > fs->group_desc_count)
		goto err;
	offset = ((ino - 1) % EXT2_INODES_PER_GROUP(fs->super)) *
		EXT2_INODE_SIZE(fs->super);
	block = offset >> EXT2_BLOCK_SIZE_BITS(fs->super);
	rc = EXT2_ET_MISSING_INODE_TABLE;
	if (!ext2fs_inode_table_loc(fs, group))
		goto err;
	block_nr = ext2fs_inode_table_loc(fs, group) + block;

	offset &= (EXT2_BLOCK_SIZE(fs->super) - 1);

	blocks = (EXT2_INODE_SIZE(fs->super) + EXT2_BLOCK_SIZE(fs->super) - 1);
	blocks /= EXT2_BLOCK_SIZE(fs->super);

	rc = io_channel_async_read(fs->io, block_nr, blocks,
				   ext2fs_read_inode_async_helper, async,
				   offset);
err:
	if (rc && async->allocated)
		ext2fs_free_mem(&async);
	return rc;
}
