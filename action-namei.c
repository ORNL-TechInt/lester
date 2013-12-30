/* action-namei.c -- given a list of inodes, find their path name(s)
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#include "lester.h"
#include "rbtree.h"

struct target_inode {
	struct rb_node rb_node;
	ext2_ino_t ino;
	unsigned int nlinks;
};

static struct rb_root namei_targets = RB_ROOT;
static int namei_all_names;

static void namei_help(void)
{
	fprintf(stderr, "Action arguments for namei:\n");
	fprintf(stderr, "    file=FILE\t\tRead list of inodes from FILE\n");
	fprintf(stderr, "    all_names\t\tList all names for a file\n");
	fprintf(stderr, "    NUMBER\t\tInode number to name\n");
	fprintf(stderr, "\nAs many inode numbers as needed may be listed\n");
}

static void namei_add_inode(ext2_ino_t ino)
{
	struct target_inode *t, *n;
	struct rb_node **p = &namei_targets.rb_node;
	struct rb_node *parent = NULL;

	n = malloc(sizeof(*n));
	if (!n) {
		fprintf(stderr, "Unable to allocate space for inode\n");
		exit(1);
	}

	RB_CLEAR_NODE(&n->rb_node);
	n->ino = ino;
	n->nlinks = 1;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct target_inode, rb_node);

		if (ino < t->ino)
			p = &(*p)->rb_left;
		else if (ino > t->ino)
			p = &(*p)->rb_right;
		else
			return;
	}

	rb_link_node(&n->rb_node, parent, p);
	rb_insert_color(&n->rb_node, &namei_targets);
}

static struct target_inode *namei_find_inode(ext2_ino_t ino)
{
	struct rb_node *n = namei_targets.rb_node;
	struct target_inode *t;

	while (n) {
		t = rb_entry(n, struct target_inode, rb_node);

		if (ino < t->ino)
			n = n->rb_left;
		else if (ino > t->ino)
			n = n->rb_right;
		else
			return t;
	}

	return NULL;
}

static int namei_init(const char *device, int argc, const char **argv)
{
	unsigned long ino;
	FILE *file;
	int rc;

	while (argc--) {
		if (!strcmp(*argv, "all_names")) {
			namei_all_names = 1;
		} else if (!strncmp(*argv, "file=", 5)) {
			file = fopen(*argv + 5, "r");
			if (!file) {
				int e = errno;
				fprintf(stderr, "Unable to open ");
				errno = e;
				perror(*argv + 5);
				return 1;
			}

			while (!feof(file)) {
				rc = fscanf(file, "%lu", &ino);
				if (rc == 1)
					namei_add_inode(ino);
				else if (rc != EOF) {
					fprintf(stderr, "Bad read from %s\n",
							*argv + 5);
					fclose(file);
					return 1;
				}
			}
			fclose(file);
		} else {
			char *end;
			if (!**argv) {
				fprintf(stderr, "Unable to parse empty action "
						"arg\n");
				return 1;
			}
			ino = strtoul(*argv, &end, 0);
			if (*end || end == *argv) {
				fprintf(stderr, "Invalid action argument "
						"'%s'\n", *argv);
				return 1;
			}
			namei_add_inode(ino);
		}

		argv++;
	}

	if (RB_EMPTY_ROOT(&namei_targets)) {
		fprintf(stderr, "No inodes given to name\n");
		return 1;
	}

	return 0;
}

static int namei_iscan(ext2_ino_t ino, struct ext2_inode *inode,
		       struct ea_info *eas)
{
	struct target_inode *t = namei_find_inode(ino);

	/* If it isn't in our tree, we don't care about it */
	if (!t)
		return ACTION_COMPLETE;

	if (namei_all_names && !LINUX_S_ISDIR(inode->i_mode))
		t->nlinks = inode->i_links_count;
	else
		t->nlinks = 1;

	return ACTION_WANT_PATH;
}

static int namei_dscan(ext2_ino_t ino, struct ext2_inode *inode,
		       struct dentry *parent, const char *name, int namelen,
		       struct ea_info *eas)
{
	struct target_inode *t = namei_find_inode(ino);
	int offset;

	/* We may have already printed a name for this inode, and no longer
	 * care about it.
	 */
	if (!t)
		return ACTION_COMPLETE;

	if (--t->nlinks == 0)
		rb_erase(&t->rb_node, &namei_targets);

	offset = build_path(parent, 0);
	fprintf(outfile, "%lu %.*s%.*s\n", ino, offset, path_buffer,
			 namelen, name);

	if (RB_EMPTY_ROOT(&namei_targets))
		return ACTION_END_SCAN;

	return ACTION_COMPLETE;
}

struct action_ops namei_action = {
	.name	= "namei",
	.init	= namei_init,
	.help	= namei_help,
	.iscan	= namei_iscan,
	.dscan	= namei_dscan,
	.flags	= ACTION_FLAG_ISCAN_NO_EAS,
};
