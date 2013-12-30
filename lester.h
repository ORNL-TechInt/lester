/* lester.h -- Lester, the Lustre lister
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#ifndef __lester_h
#define __lester_h 1

#include <ext2fs/ext2fs.h>
#include "ext2fs-extra.h"
#include "rbtree.h"
#include "list.h"

struct dentry {
	struct rb_node tree;
	struct dentry *d_parent;
	char *name;
	struct list_head d_children;    /* a list of my children */
	struct list_head list;          /* My location on parent's child list */
	ext2_ino_t ino;
	unsigned namelen:8;
	unsigned connected_to_root:1;
	unsigned is_file:1;
	unsigned is_dir:1;
	unsigned not_in_root:1;
	unsigned is_printed:1;
	unsigned refs;
};

struct ea_info {
	/* These fields should be considered constant by users */
	/* End of the EAs is indicate by name == NULL */
	char *name;
	void *value;
	ext2_ino_t ext_ino;
	unsigned int value_len;
	unsigned char name_len;
	unsigned char index;
	int allocated;

	/* State info for async read of the external value file */
	struct ext2_inode *inode;
	void (*done)(void *);
	void *data;
	unsigned int pending;

	/* Users can change these fields to request the value */
	int requested;
};

struct action_ops {
	const char *name;

	int (*init)(const char *dev, int argc, const char **argv);
	void (*help)(void);
	int (*iscan_begin)(void);
	int (*iscan)(ext2_ino_t, struct ext2_inode *, struct ea_info *ea);
	int (*iscan_end)(void);
	int (*dscan_begin)(void);
	int (*dscan)(ext2_ino_t, struct ext2_inode *, struct dentry *parent,
		     const char *name, int namelen, struct ea_info *ea);
	int (*dscan_end)(void);

	unsigned int flags;
};

enum {
	ACTION_COMPLETE = 0,
	ACTION_END_SCAN = 1,
	ACTION_WANT_PATH = 2,
	ACTION_WANT_INODE = 4,
	ACTION_WANT_ATTRS = 8,
	ACTION_WANT_READ_ATTRS = 16,
	ACTION_IGNORE_FILE = 32,
};

#define ACTION_FLAG_ISCAN_NO_EAS	1

/* From lester.c */
int enforce_async_limit(void);
void diff_timevals(struct timeval *start, struct timeval *end,
		   struct timeval *out);


/* From dtree.c */
void ignore_file(ext2_ino_t ino);
int is_file_interesting(ext2_ino_t ino);
int create_root_dentries(char *root);
struct dentry *create_dentry(ext2_ino_t ino);
void dtree_add_dir(ext2_ino_t ino);
void dtree_get_ino(ext2_ino_t ino);
void dtree_put_ino(ext2_ino_t ino);
void get_dentry(struct dentry *dentry);
void put_dentry(struct dentry *dentry);
struct dentry *find_dentry(ext2_ino_t ino);
void dentry_attach_name(struct dentry *dentry, int namelen, const char *name);
int dtree_name_dir(struct dentry *parent, ext2_ino_t ino,
			const char *name, int namelen);
int dtree_name_file(struct dentry *parent, ext2_ino_t ino,
			const char *name, int namelen);
int build_path(struct dentry *dentry, int len);

/* From iscan.c */
int scan_inodes(const char *dev);

/* From dscan.c */
int resolve_paths(void);
int path_resolved(ext2_ino_t ino, struct dentry *parent, const char *name,
			int namelen, struct dentry *entry);

/* From attr.c */
struct ea_info *build_ea_info(struct ext2_inode *in, void *ext_attr);
struct ea_info *ea_memory_change(struct ea_info *orig, struct ext2_inode *in,
				 void *ext_attr);
void release_ea_info(struct ea_info *ea);
void async_read_ea_value(struct ea_info *eas, void (*done)(void *), void *data);
extern unsigned long ea_ext_value_read, ea_ext_block_read;

/* Config params, defined in lester.c */
extern ext2_filsys fs;
extern FILE *outfile;

extern char *root_path;
extern unsigned int verbosity;
extern int use_unix;
extern unsigned long grp_readahead;
extern unsigned long dir_readahead;
extern struct action_ops *scan_action;

/* Action structures */
extern struct action_ops fslist_action;
extern struct action_ops namei_action;
extern struct action_ops lsost_action;

extern char *path_buffer;
extern unsigned long dentries_freed;
extern unsigned long dentries_created;

#endif /* __lester_h */
