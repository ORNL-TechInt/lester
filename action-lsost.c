/* action-lsost.c -- find files with objects on specified OSTs
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#include "lester.h"
#include "lustre_lov.h"

#define BITS_PER_ENTRY	(sizeof(unsigned long) * 8)
static unsigned int lsost_max_ost;
static unsigned long *lsost_interesting_osts;
static unsigned long lsost_work_remaining;
static int lsost_show_osts;

static void lsost_help(void)
{
	fprintf(stderr, "Action arguments for lsost:\n");
	fprintf(stderr, "    show_osts\t\tShow OST numbers (default if "
			"multiple OSTs requested)\n");
	fprintf(stderr, "    hide_osts\t\tDo not show OST numbers\n");
	fprintf(stderr, "    file=FILE\t\tRead list of OSTs from FILE\n");
	fprintf(stderr, "    NUMBER\t\tOST number to list files for\n");
	fprintf(stderr, "\nAs many OSTs as needed may be listed\n");
}

static void lsost_add_ost(unsigned int ost)
{
	unsigned int entry = ost / BITS_PER_ENTRY;
	unsigned int bit = ost % BITS_PER_ENTRY;
	unsigned int new_max;

	if (ost < lsost_max_ost) {
		lsost_interesting_osts[entry] |= (1UL << bit);
		return;
	}

	new_max = 2 * ost;
	if (new_max < 1024)
		new_max = 1024;

	/* Make sure we allocate whole entries */
	new_max *= BITS_PER_ENTRY;
	new_max--;
	new_max /= BITS_PER_ENTRY;

	lsost_interesting_osts = realloc(lsost_interesting_osts, new_max);
	if (!lsost_interesting_osts) {
		fprintf(stderr, "Unable to allocate memory for OST bitmap\n");
		exit(1);
	}

	memset(lsost_interesting_osts + (lsost_max_ost / BITS_PER_ENTRY), 0,
	       ((new_max - lsost_max_ost) / BITS_PER_ENTRY) *
	       sizeof(unsigned long));
	lsost_interesting_osts[entry] |= (1UL << bit);
	lsost_max_ost = new_max;
}

static int lsost_interesting(unsigned int ost)
{
	unsigned int entry = ost / BITS_PER_ENTRY;
	unsigned int bit = ost % BITS_PER_ENTRY;

	if (ost >= lsost_max_ost)
		return 0;

	return !!(lsost_interesting_osts[entry] & (1UL << bit));
}

static int lsost_file_interesting(struct ea_info *lov)
{
	struct lov_mds_md_v1 *lov1;
	struct lov_ost_data_v1 *ost;
	int cnt;

	lov1 = lov->value;
	if (lov1->lmm_magic == LOV_MAGIC_V1) {
		cnt = lov1->lmm_stripe_count;
		ost = lov1->lmm_objects;
	} else if (lov1->lmm_magic == LOV_MAGIC_V3) {
		struct lov_mds_md_v3 *lov3 = lov->value;
		cnt = lov3->lmm_stripe_count;
		ost = lov3->lmm_objects;
	} else
		return 0;

	for (; cnt; ost++, cnt--) {
		if (lsost_interesting(ost->l_ost_idx))
			return 1;
	}

	return 0;
}

static void lsost_print_interesting(struct ea_info *lov)
{
	struct lov_mds_md_v1 *lov1;
	struct lov_ost_data_v1 *ost;
	char *sep = "";
	int cnt;

	lov1 = lov->value;
	if (lov1->lmm_magic == LOV_MAGIC_V1) {
		cnt = lov1->lmm_stripe_count;
		ost = lov1->lmm_objects;
	} else if (lov1->lmm_magic == LOV_MAGIC_V3) {
		struct lov_mds_md_v3 *lov3 = lov->value;
		cnt = lov3->lmm_stripe_count;
		ost = lov3->lmm_objects;
	} else
		return;

	for (; cnt; ost++, cnt--) {
		if (lsost_interesting(ost->l_ost_idx)) {
			fprintf(outfile, "%s%u", sep, ost->l_ost_idx);
			sep = ",";
		}
	}

	fprintf(outfile, " ");
}

static struct ea_info *lsost_find_lov(struct ea_info *eas)
{
	struct ea_info *ea;

	for (ea = eas; ea->name; ea++) {
		if (ea->index != EXT2_XATTR_INDEX_TRUSTED &&
		    ea->index != EXT2_XATTR_INDEX_LUSTRE)
			continue;

		if (ea->name_len != 3 || strncmp(ea->name, "lov", 3))
			continue;

		return ea;
	}

	return NULL;
}

static int lsost_init(const char *device, int argc, const char **argv)
{
	unsigned long ost;
	unsigned int count = 0;
	int hide_osts = 0;
	FILE *file;
	int rc;

	while (argc--) {
		if (!strcmp(*argv, "show_osts")) {
			lsost_show_osts = 1;
		} else if (!strcmp(*argv, "hide_osts")) {
			hide_osts = 1;
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
				rc = fscanf(file, "%lu", &ost);
				if (rc == 1) {
					if (ost > ~0U) {
						fprintf(stderr, "OST %lu too "
								"large\n", ost);
						return 1;
					}
					lsost_add_ost(ost);
					count++;
				} else if (rc != EOF) {
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
			ost = strtoul(*argv, &end, 0);
			if (*end || end == *argv) {
				fprintf(stderr, "Invalid action argument "
						"'%s'\n", *argv);
				return 1;
			}
			if (ost > ~0U) {
				fprintf(stderr, "OST %lu too large\n", ost);
				return 1;
			}
			lsost_add_ost(ost);
			count++;
		}

		argv++;
	}

	if (!count) {
		fprintf(stderr, "No OSTs given for lsost action\n");
		return 1;
	}

	if (count > 1 && !hide_osts)
		lsost_show_osts = 1;

	return 0;
}

static int lsost_iscan(ext2_ino_t ino, struct ext2_inode *inode,
		       struct ea_info *eas)
{
	struct ea_info *lov = NULL;

	if (!LINUX_S_ISREG(inode->i_mode))
		return ACTION_COMPLETE;

	lov = lsost_find_lov(eas);
	if (lov && !lov->value) {
		lov->requested = 1;
		return ACTION_WANT_READ_ATTRS;
	}

	if (!lov || !lsost_file_interesting(lov))
		return ACTION_COMPLETE;

	lsost_work_remaining++;
	return ACTION_WANT_PATH;
}

static int lsost_dscan(ext2_ino_t ino, struct ext2_inode *inode,
		       struct dentry *parent, const char *name, int namelen,
		       struct ea_info *eas)
{
	int offset;

	if (lsost_show_osts) {
		struct ea_info *lov;

		if (!inode)
			return ACTION_WANT_INODE | ACTION_WANT_ATTRS;

		/* Get our LOV attribute; if we cannot find one, we've
		 * been deleted.
		 */
		lov = lsost_find_lov(eas);
		if (!lov)
			return ACTION_COMPLETE;

		if (!lov->value) {
			lov->requested = 1;
			return ACTION_WANT_READ_ATTRS;
		}

		lsost_print_interesting(lov);
	}

	offset = build_path(parent, 0);
	fprintf(outfile, "%.*s%.*s\n", offset, path_buffer, namelen, name);

	if (--lsost_work_remaining)
		return ACTION_COMPLETE;

	return ACTION_END_SCAN;
}

struct action_ops lsost_action = {
	.name	= "lsost",
	.init	= lsost_init,
	.help	= lsost_help,
	.iscan	= lsost_iscan,
	.dscan	= lsost_dscan,
};
