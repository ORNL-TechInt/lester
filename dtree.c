/* dtree.c -- Directory naming code
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * Much of this code is derived from Lustre e2fsprogs/e2scan this file may may
 * be redistributed under the terms of the GNU General Public License version
 * 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/errno.h>
#include "lester.h"

#define DEBUG_REFS	1

static ext2_ino_t visible_root_ino;

/*
create root dentry
    root->connected_to_root = 1
    root->d_path = "/"
for each directory block:
    if (directory is not in memory)
        create new directory dentry
        set directory->connected_to_root = 0
    for each entry found in directory block:
        if (entry is a subdirectory)
            if (subdir is in memory)
                subdir->d_parent = directory
                if (directory->connected_to_root)
                    recurse for each subsubdir
			subsubdir->connected_to_root = 1
			subsubdir->d_parent = subdir
			subsubdir->d_path = subdir->d_path + name
			for each non-directory entry on subdir
			    generate full pathname and output
			    drop filename entry from RAM
            else
                create new subdir dentry
                subdir->connected_to_root = directory->connected_to_root
                subdir->d_parent = directory
                if (directory->connected_to_root)
		    subdir->d_path = directory->d_path + name
        else if (file is interesting)
            if (directory->connected_to_root)
                generate full pathname and output
            else
		create filename entry
                attach filename to directory
*/

char *path_buffer;

static int max_path_size;
static struct dentry *path_last_dentry;
static int path_last_offset;

static struct rb_root dentry_tree = RB_ROOT;

void ignore_file(ext2_ino_t ino)
{
	ext2fs_fast_unmark_inode_bitmap2(fs->inode_map, ino);
}

int is_file_interesting(ext2_ino_t ino)
{
	return ext2fs_fast_test_inode_bitmap2(fs->inode_map, ino);
}

struct dentry *find_dentry(ext2_ino_t ino)
{
	struct rb_node *n = dentry_tree.rb_node;
	struct dentry *dentry;

	while (n) {
		dentry = rb_entry(n, struct dentry, tree);
		if (ino < dentry->ino)
			n = n->rb_left;
		else if (ino > dentry->ino)
			n = n->rb_right;
		else
			return dentry;
	}
	return NULL;
}

static struct dentry *__find_dentry_or_parent(ext2_ino_t ino,
						struct rb_node **parent,
						struct rb_node ***pparent)
{
	struct rb_node **p = &dentry_tree.rb_node;
	struct dentry *dentry;

	*parent = NULL;
	while (*p) {
		*parent = *p;
		dentry = rb_entry(*parent, struct dentry, tree);

		if (ino < dentry->ino)
			p = &(*p)->rb_left;
		else if (ino > dentry->ino)
			p = &(*p)->rb_right;
		else
			return dentry;
	}

	*pparent = p;
	return NULL;
}

static struct dentry *find_or_create_dentry(ext2_ino_t ino, int *created)
{
	struct rb_node *parent, **pparent;
	struct dentry *dentry;

	*created = 0;
	dentry = __find_dentry_or_parent(ino, &parent, &pparent);
	if (!dentry) {
		dentry = create_dentry(ino);
		rb_link_node(&dentry->tree, parent, pparent);
		rb_insert_color(&dentry->tree, &dentry_tree);
		*created = 1;
	}
	return dentry;
}

static void link_to_parent(struct dentry *parent, struct dentry *child)
{
	list_add(&child->list, &parent->d_children);
	child->d_parent = parent;
	get_dentry(parent);
}

void dentry_attach_name(struct dentry *dentry, int namelen, const char *name)
{
	if (dentry->name) {
		if (namelen == 1 && (!strcmp(name, ".") || !strcmp(name, "/")))
			return;
		fprintf(stderr, "BUG: dentry has name: %s, adding name %.*s\n",
			dentry->name, namelen, name);
		exit(1);
	}
	asprintf(&dentry->name, "%.*s", namelen, name);
	dentry->namelen = namelen;
}

/* create_root_dentries()
 * - look up $ROOT in the filesystem
 * - build dentry for each component of the path, starting at /
 * - for each component of the path except the last, mark dentry "not_in_root"
 */
int create_root_dentries(char *root)
{
	int created;
	char *name;
	ext2_ino_t ino;
	struct dentry *child, *parent;
	struct ext2_inode inode;
	char *copy, *p;

	copy = p = strdup(root);

	ino = EXT2_ROOT_INO;
	name = "/";
	parent = NULL;
	do {
		child = find_or_create_dentry(ino, &created);
		dentry_attach_name(child, strlen(name), name);
		child->connected_to_root = 1;
		child->not_in_root = 1;
		if (parent != NULL)
			link_to_parent(parent, child);
		parent = child;

		name = strtok(copy, "/");
		if (name == NULL)
			break;
		copy = NULL;

		if (ext2fs_lookup(fs, ino, name, strlen(name), NULL, &ino))
			return ENOENT;
	} while (1);

	if (ext2fs_read_inode(fs, ino, &inode))
		return EIO;

	if (!LINUX_S_ISDIR(inode.i_mode)) {
		return ENOTDIR;
	}
	child->not_in_root = 0;
	visible_root_ino = ino;

	if (verbosity)
		fprintf(stdout, "visible root: \"%s\"\n", root);

	free(p);

	return 0;
}

static void check_path_size(int len)
{
	if (len < max_path_size)
		return;

	if (!max_path_size)
		max_path_size = 8192;

	while (max_path_size <= len)
		max_path_size *= 2;

	if (path_buffer)
		free(path_buffer);
	path_buffer = malloc(max_path_size);
	if (!path_buffer) {
		fprintf(stderr, "unable able allocate path buffer\n");
		exit(1);
	}
}

static int __build_path(struct dentry *dentry, int len)
{
	/* On the descent of the tree to root, len accumulates the
	 * length of the path. At the root, we ensure we have a large
	 * enough buffer, and then we'll use our return value to let the
	 * caller know where to put their path component.
	 *
	 * We return -1 if this path is not actually part of the visible
	 * tree.
	 */
	int offset;

	if (dentry->ino == visible_root_ino) {
		/* Account for the root and trailing NULL */
		len += 2;
		check_path_size(len);
		path_buffer[0] = '/';
		return 1;
	}

	if (dentry->ino == EXT2_ROOT_INO) {
		/* This path is not visible from the designated root */
		return -1;
	}

	/* Account for our name, plus the directory seperator */
	len += dentry->namelen + 1;
	offset = __build_path(dentry->d_parent, len);
	if (offset == -1)
		return -1;

	memcpy(path_buffer + offset, dentry->name, dentry->namelen);
	offset += dentry->namelen;
	path_buffer[offset++] = '/';

	return offset;
}

int build_path(struct dentry *dentry, int len)
{
	if (path_last_dentry != dentry) {
		path_last_offset = __build_path(dentry, 0);
		path_last_dentry = dentry;
	}

	return path_last_offset;
}

static int path_is_visible(struct dentry *dentry)
{
	static struct dentry *last_dentry;
	static int visible;

	if (path_last_dentry == dentry)
		return path_last_offset != -1;

	if (last_dentry != dentry) {
		last_dentry = dentry;
		visible = 1;
		while (dentry->ino != visible_root_ino) {
			if (dentry->ino == EXT2_ROOT_INO) {
				visible = 0;
				break;
			}
			dentry = dentry->d_parent;
		}
	}

	return visible;
}

static void connect_subtree_to_root(struct dentry *parent, int not_in_root)
{
	struct dentry *child, *p;

	assert(!parent->is_file);
	parent->connected_to_root = 1;
	parent->not_in_root = not_in_root;

	/* Force our parent dentry to stick around until we're done */
	get_dentry(parent);

	/* We try to print out the parent directory before its children,
	 * but if printing the directory requires async requests then
	 * it may be delayed.
	 */
	if (!parent->is_printed) {
		parent->is_printed = 1;
		if (is_file_interesting(parent->ino) &&
						path_is_visible(parent)) {
			path_resolved(parent->ino, parent->d_parent,
				      parent->name, parent->namelen,
				      parent);
		}

		/* We held a reference from creation until we could try
		 * to print it; we've done our part -- path_resolved()
		 * must have its own reference if it needs to do async IO.
		 */
		put_dentry(parent);
	}

	list_for_each_entry_safe(child, p, &parent->d_children, list) {
		if (child->is_file) {
			if (is_file_interesting(child->ino) &&
						path_is_visible(child)) {
				path_resolved(child->ino, parent,
					      child->name, child->namelen,
					      child);
			}

			/* As above, we've held our reference until we tried
			 * to print the path name.
			 */
			put_dentry(child);
			continue;
		}

		connect_subtree_to_root(child, not_in_root);
	}

	put_dentry(parent);
}

struct dentry *create_dentry(ext2_ino_t ino)
{
	struct dentry *dentry;

	dentry = calloc(1, sizeof(struct dentry));
	if (!dentry) {
		fprintf(stderr, "malloc failed");
		exit(1);
	}
	dentry->ino = ino;
	INIT_LIST_HEAD(&dentry->d_children);
	INIT_LIST_HEAD(&dentry->list);
	RB_CLEAR_NODE(&dentry->tree);

	dentries_created++;

	/* We hold a reference for each dentry until we get a chance to
	 * try to print it.
	 */
	dentry->refs = 1;

	return dentry;
}

void get_dentry(struct dentry *dentry)
{
	if (DEBUG_REFS && dentry->refs == 0) {
		fprintf(stderr, "ERROR get_dentry(ino %u)\n", dentry->ino);
		return;
	}

	dentry->refs++;
}

void put_dentry(struct dentry *dentry)
{
	if (DEBUG_REFS && dentry->refs == 0) {
		fprintf(stderr, "ERROR put_dentry(ino %u)\n", dentry->ino);
		return;
	}

	if (--dentry->refs)
		return;

	/* Refcount hit zero, free the dentry */
	rb_erase(&dentry->tree, &dentry_tree);
	list_del(&dentry->list);

	if (dentry->d_parent)
		put_dentry(dentry->d_parent);

	assert(list_empty(&dentry->d_children));

	free(dentry->name);
	free(dentry);

	dentries_freed++;
}

void dtree_add_dir(ext2_ino_t ino)
{
	struct dentry *dentry;
	int created;

	dentry = find_or_create_dentry(ino, &created);
	dentry->is_dir = 1;
}

void dtree_get_ino(ext2_ino_t ino)
{
	struct dentry *dentry;

	dentry = find_dentry(ino);
	get_dentry(dentry);
}

void dtree_put_ino(ext2_ino_t ino)
{
	struct dentry *dentry;

	dentry = find_dentry(ino);
	put_dentry(dentry);
}

int dtree_name_dir(struct dentry *parent, ext2_ino_t ino,
		   const char *name, int namelen)
{
	struct dentry *subdir;

	subdir = find_dentry(ino);
	if (!subdir) {
		/* This is a new subdirectory, so ignore it */
		return 0;
	}

	if (subdir->d_parent) {
		/* We've been connected into the tree, but we must have been
		 * renamed since then (active filesystem). Just keep the
		 * old name for consistency.
		 */
		return 0;
	}

	dentry_attach_name(subdir, namelen, name);
	link_to_parent(parent, subdir);
	if (parent->connected_to_root)
		connect_subtree_to_root(subdir, parent->not_in_root);

	return 0;
}

int dtree_name_file(struct dentry *parent, ext2_ino_t ino,
		    const char *name, int namelen)
{
	struct dentry *file;

	if (!is_file_interesting(ino))
		return 0;

	if (parent->connected_to_root) {
		if (path_is_visible(parent))
			path_resolved(ino, parent, name, namelen, NULL);

		/* Since we never created a dentry for this name, we don't
		 * have a reference to our parent.
		 */
		return 0;
	}

	/* We cannot name this inode just yet, so create a dentry for it
	 */
	file = create_dentry(ino);
	file->is_file = 1;
	dentry_attach_name(file, namelen, name);
	link_to_parent(parent, file);

	return 0;
}
