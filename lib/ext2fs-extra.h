/* ext2fs-extra.h -- extensions to libext2fs for async operations
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU Library General
 * Public License version 2; see COPYING for details.
 */
#ifndef __ext2fs_extra_h__
#define __ext2fs_extra_h__

struct struct_aio_stats {
	struct struct_io_stats base;
	unsigned long async_instream;
	unsigned long max_async;
	unsigned long total_async;
	unsigned long issued_requests;
	unsigned long completed_requests;
	unsigned long merged_async_issued;
	unsigned long merged_async;
	unsigned long long merged_gap_bytes;
};

typedef struct struct_aio_stats *aio_stats;
extern io_manager aio_io_manager;


errcode_t io_channel_get_stats(io_channel channel, io_stats *stats);

errcode_t io_channel_async_read(io_channel channel, unsigned long block,
				int count, int (*cb)(ext2_loff_t offset,
							ssize_t size,
							void *priv1,
							unsigned long priv2,
							void *data),
				void *priv1, unsigned long priv2);

/* max_async is the number of async requests allowed to remain after this call
 */
errcode_t io_channel_finish_async(io_channel channel, unsigned long max_async);
errcode_t io_channel_async_count(io_channel channel, unsigned long *count);

errcode_t ext2fs_block_iterate_async(ext2_filsys fs, ext2_ino_t ino,
					struct ext2_inode *inode,
					int (*func)(ext2_filsys fs,
							blk64_t blocknr,
							e2_blkcnt_t blockcnt,
							void *priv_data),
					void (*end)(ext2_filsys fs,
							errcode_t errcode,
							void *priv_data),
					void *priv_data);

struct ext2fs_inode_async {
	ext2_filsys fs;
	ext2_ino_t ino;
	int (*func)(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode *inode, void *priv);
	void *priv;
	int allocated;
};

errcode_t ext2fs_read_inode_async(ext2_filsys fs, ext2_ino_t ino,
				  struct ext2fs_inode_async *async,
				  int (*func)(ext2_filsys fs,
					      ext2_ino_t ino,
					      struct ext2_inode *inode,
					      void *priv),
				  void *priv);

#if !HAVE_LUSTRE_EXTFS2
/* Already in Lustre's libe2fs */
errcode_t io_channel_readahead(io_channel channel, unsigned long block,
			       int count);
#endif

#endif /* __ext2fs_extra_h__ */
