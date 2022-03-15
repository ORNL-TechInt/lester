/* action-fslist.c -- ne2scan-style listing for Lester
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#include "lester.h"
#include "lustre_lov.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <regex.h>
#include <time.h>

enum {
	FORMAT_NAME,
	FORMAT_INUM,
	FORMAT_EXTENDED,
	FORMAT_LUSTRE,
	FORMAT_NE2SCAN,
};

enum filter_type {
	FIL_NONE	= 0x0,
	FIL_BEFORE	= 0x1,
	FIL_NEWER	= 0x2,
	FIL_CONTEXT	= 0x4,
	FIL_ALL		= 0x7,
};

struct filter_elt;

typedef int (*filter_cb_t)(struct filter_elt *elt,
			    struct ext2_inode *i,
			    struct ea_info *ctx);

struct filter_elt {
	filter_cb_t fe_cb;
	int fe_not;
	union {
		time_t time;
		regex_t regex;
		char *str;
	}fe_d;
};

#define MAX_FILTER_NUMBER 10
struct filter_array {
	int fa_msk;
	int fa_cnt;
	struct filter_elt fa_array[MAX_FILTER_NUMBER];
};

static int fslist_format = FORMAT_NE2SCAN;
static const char *fsname = "UNKNOWN";
static const char *user_note = "";
static int show_dirs = 0;
static int show_fid = 0;
static int show_ctx = 0;
static int show_one = 0;
static const char *target_dev;
static struct filter_array filters = { 0 };
static FILE *genhit;

static int add_to_filters(enum filter_type type, filter_cb_t cb, int not,
			  void *data, size_t len)
{
	struct filter_elt *elt;

	if (filters.fa_cnt >= MAX_FILTER_NUMBER || len > sizeof(elt->fe_d) ||
	    type > FIL_ALL)
		return -1;

	elt = &filters.fa_array[filters.fa_cnt];
	elt->fe_cb = cb;
	elt->fe_not = not;
	memcpy(&elt->fe_d, data, len);

	filters.fa_cnt++;
	filters.fa_msk |= type;

	return 0;
}

static int is_filters_match( struct ext2_inode *inode, struct ea_info *ctx)
{
	int i;
	int match = 0;
	struct filter_elt *elt = &filters.fa_array[0];

	for (i = 0; i < filters.fa_cnt; i++, elt++) {
		match = elt->fe_cb(elt, inode, ctx);

		if (elt->fe_not)
			match = !match;
		if (!match)
			break;
	}

	return match;
}

static int filter_accessed_before(struct filter_elt *elt, struct ext2_inode *i,
				  struct ea_info *ctx)
{
	time_t cutoff_time = elt->fe_d.time;

	if (i->i_atime < cutoff_time &&
	    i->i_mtime < cutoff_time &&
	    i->i_ctime < cutoff_time)
		return 1;

	return 0;
}

static int filter_newer_than(struct filter_elt *elt, struct ext2_inode *i,
			     struct ea_info *ctx)
{
	time_t cutoff_time = elt->fe_d.time;

	if (i->i_mtime >= cutoff_time &&
	    i->i_ctime >= cutoff_time)
		return 1;

	return 0;
}

static int filter_context(struct filter_elt *elt, struct ext2_inode *i,
			  struct ea_info *ctx)
{
	regex_t *reg = &elt->fe_d.regex;

	if (!ctx)
		return 0;

	return regexec(reg, ctx->value, 0, NULL, 0) == 0;
}

static void report_fid(FILE *f, struct ea_info *lov)
{
	struct lustre_mdt_attrs *lma = lov->value;
	fprintf(f, "0x%lx:0x%x:0x%x", lma->lma_self_fid.f_seq,
		lma->lma_self_fid.f_oid, lma->lma_self_fid.f_ver);
}

static void report_ctx(FILE *f, struct ea_info *ctx)
{
	char *ctx_str = ctx->value;

	fprintf(f, "%s", ctx_str);
}

static void report_osts(FILE *f, struct ea_info *lov)
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
	} else {
		fprintf(f, "UNKNOWN LOV %x", lov1->lmm_magic);
		return;
	}

	if (!cnt)
		return;

	/* Print in reverse order to keep compatibility with ne2scan output;
	 * make ost[] start at index 1.
	 */
	ost--;
	fprintf(f, "%u:%lx", ost[cnt].l_ost_idx,
		   (unsigned long) ost[cnt].l_object_id);
	while (--cnt) {
		fprintf(f, ",%u:%lx", ost[cnt].l_ost_idx,
			   (unsigned long) ost[cnt].l_object_id);
	}
}

static int get_timestamp(const char *path, time_t *atime, time_t *mctime)
{
	struct stat stats;

	if (stat(path, &stats)) {
		fprintf(stderr, "Unable to stat '%s': %s\n", path,
				strerror(errno));
		return 1;
	}

	if (atime)
		*atime = stats.st_atime;
	if (mctime) {
		*mctime = stats.st_ctime;
		if (stats.st_ctime < stats.st_mtime)
			*mctime = stats.st_mtime;
	}

	return 0;
}

static void fslist_help(void)
{
	fprintf(stderr, "Action arguments for fslist:\n");
	fprintf(stderr, "    format=FORMAT\tOutput format\n");
	fprintf(stderr, "\tne2scan\t\t    Full ne2scan output (default)\n");
	fprintf(stderr, "\tlustre\t\t    Include inode attributes and Lustre "
			"objects\n");
	fprintf(stderr, "\textended\t    Include inode attributes\n");
	fprintf(stderr, "\tinum\t\t    Include inode number\n");
	fprintf(stderr, "\tname\t\t    Only name of matching files\n");
	fprintf(stderr, "    show_one\t\tShow one name for hardlinked files "
			"(default all names)\n");
	fprintf(stderr, "    show_dirs\t\tAlso show directory names\n");
	fprintf(stderr, "    show_fid\t\tAlso show FID in lov, ne2scan "
			"format\n");
	fprintf(stderr, "    show_ctx\t\tAlso show selinux context, ne2scan "
			"format\n");
	fprintf(stderr, "    note=MSG\t\tAdd MSG to ne2scan header\n");
	fprintf(stderr, "    fs=NAME\t\tName filesystem for ne2scan output\n");
	fprintf(stderr, "    newer=FILE\t\tFiles newer than FILE\n");
	fprintf(stderr, "    before=FILE\t\tFiles not accessed since FILE\n");
	fprintf(stderr, "    context=REGEX\t\tFiles match context regex\n");
	fprintf(stderr, "    genhit=FILE\t\tCopy entries matching newer/before "
			"options to FILE\n");
	fprintf(stderr, "\t\t\t    (Main output will get all files, matching "
			"or not)\n");
}

static int fslist_init(const char *dev, int argc, const char **argv)
{
	const char *genhit_name = NULL;
	int rc;
	target_dev = dev;

	while (argc--) {
		int not = 0;

		if (!bcmp(*argv, "not_", 4)) {
			not = 1;
			*argv += 4;
		}

		if (!strcmp(*argv, "show_dirs"))
			show_dirs = 1;
		else if (!strcmp(*argv, "show_fid"))
			show_fid = 1;
		else if (!strcmp(*argv, "show_ctx"))
			show_ctx = 1;
		else if (!strcmp(*argv, "show_one"))
			show_one = 1;
		else if (!strncmp(*argv, "fs=", 3))
			fsname = *argv + 3;
		else if (!strncmp(*argv, "note=", 5))
			user_note = *argv + 5;
		else if (!strncmp(*argv, "newer=", 6)) {
			time_t f_time;

			if (get_timestamp(*argv + 6, NULL, &f_time))
				return 1;

			rc = add_to_filters(FIL_NEWER, filter_newer_than, not,
				       &f_time, sizeof(f_time));
			if (rc) {
				fprintf(stderr, "Fail to add filter '%s'\n",
					*argv);
				return 1;
			}

		} else if (!strncmp(*argv, "before=", 7)) {
			time_t f_time;

			if (get_timestamp(*argv + 7, NULL, &f_time))
				return 1;

			rc = add_to_filters(FIL_BEFORE, filter_accessed_before,
					    not, &f_time, sizeof(f_time));
			if (rc) {
				fprintf(stderr, "Fail to add filter '%s'\n",
					*argv);
				return 1;
			}
		} else if (!strncmp(*argv, "context=", 8)) {
			const char *context_str = *argv + 8;
			regex_t reg;

			if (regcomp(&reg, context_str, REG_EXTENDED)) {
				fprintf(stderr, "Could not compile context regex\n");
				return 1;
			}

			rc = add_to_filters(FIL_CONTEXT, filter_context, not,
					    &reg, sizeof(reg));
			if (rc) {
				fprintf(stderr, "Fail to add filter '%s'\n",
					*argv);
				return 1;
			}
		} else if (!strncmp(*argv, "format=", 7)) {
			if (!strcmp(*argv, "format=ne2scan"))
				fslist_format = FORMAT_NE2SCAN;
			else if (!strcmp(*argv, "format=lustre"))
				fslist_format = FORMAT_LUSTRE;
			else if (!strcmp(*argv, "format=extended"))
				fslist_format = FORMAT_EXTENDED;
			else if (!strcmp(*argv, "format=inum"))
				fslist_format = FORMAT_INUM;
			else if (!strcmp(*argv, "format=name"))
				fslist_format = FORMAT_NAME;
			else {
				fprintf(stderr, "Unknown fslist format: %s\n",
					*argv + 7);
				return 1;
			}
		} else if (!strncmp(*argv, "genhit=", 7)) {
			genhit_name = *argv + 7;
		} else {
			fprintf(stderr, "Unknown fslist arg: %s\n", *argv);
			return 1;
		}

		argv++;
	}

	if (genhit_name) {
		if (!(filters.fa_msk & FIL_ALL)) {
			fprintf(stderr, "genhit only makes sense with a filter"
				"option\n");
			return 1;
		}

		genhit = fopen(genhit_name, "w");
		if (!genhit) {
			fprintf(stderr, "Unable to open genhit output "
					"file: %s\n", genhit_name);
			return 1;
		}
	}
	return 0;
}

static int fslist_iscan(ext2_ino_t ino, struct ext2_inode *inode,
			struct ea_info *eas)
{
	/* We only show directories if asked, otherwise we'll want a
	 * path name and inode info in the directory scan.
	 */
	if (!show_dirs && LINUX_S_ISDIR(inode->i_mode))
		return ACTION_COMPLETE;

	/* Are we pruning the list based on a timestamp?
	 * When looking for files accessed before the cutoff, we'll prune
	 * it if any of the times are after the cutoff. For files newer
	 * than the cutoff, we only care if the have been changed since then.
	 *
	 * Note, if we're sending data to a separate genhit file, then
	 * we actually want everything for the main file.
	 */
	if (!genhit && is_filters_match(inode, NULL))
		return ACTION_COMPLETE;

	return ACTION_WANT_PATH | ACTION_WANT_INODE;
}

static int fslist_dscan_begin(void)
{
	time_t start = time(NULL);
	const char *e2ver;
	char host[256];
	char stime[90];

	/* We only put a header in for ne2scan compatibility */
	if (fslist_format < FORMAT_NE2SCAN)
		return 0;

	ext2fs_get_library_version(&e2ver, NULL);
	gethostname(host, sizeof(host));
	strftime(stime, sizeof(stime), "%a %b %d %X %Z %Y", gmtime(&start));
	fprintf(outfile, "#IDENT#|%s|%s|%d|%s|%s|%s|0|0|0|0|%s|%s\n",
		PACKAGE_VERSION, e2ver, start, stime, host, target_dev,
		fsname, user_note);

	if (genhit) {
		fprintf(genhit, "#IDENT#|%s|%s|%d|%s|%s|%s|0|0|0|0|%s|%s\n",
			PACKAGE_VERSION, e2ver, start, stime, host, target_dev,
			fsname, user_note);
	}

	return 0;
}

static int fslist_output(FILE *f, ext2_ino_t ino, struct ext2_inode *inode,
			 int offset, const char *name, int namelen,
			 struct ea_info *lov, struct ea_info *lma,
			 struct ea_info *ctx)
{
	if (fslist_format > FORMAT_INUM) {
		fprintf(f, "%u|%u|%u|%u|%u|%o|%lu|%u", inode->i_atime,
			inode->i_ctime, inode->i_mtime, inode_uid(*inode),
			inode_gid(*inode), inode->i_mode,
			(unsigned long) EXT2_I_SIZE(inode), ino);

		if (fslist_format >= FORMAT_LUSTRE) {
			/* TODO deal with default stripe info on dirs */
			fprintf(f, "|");
			if (lov && LINUX_S_ISREG(inode->i_mode))
				report_osts(f, lov);
		}

		if (show_fid) {
			fprintf(f, "|");
			if (lma)
				report_fid(f, lma);
		}

		if (show_ctx) {
			fprintf(f, "|");
			if (ctx)
				report_ctx(f, ctx);
		}

		fprintf(f, "|");
	} else if (fslist_format == FORMAT_INUM) {
		fprintf(f, "%lu ", ino);
	}

	fprintf(f, "%.*s%.*s\n", offset, path_buffer, namelen, name);
}

static int fslist_dscan(ext2_ino_t ino, struct ext2_inode *inode,
			struct dentry *parent, const char *name, int namelen,
			struct ea_info *eas)
{
	int need_ctx = show_ctx || (filters.fa_msk | FIL_CONTEXT);
	struct ea_info *lov = NULL;
	struct ea_info *lma = NULL;
	struct ea_info *ctx = NULL;
	struct ea_info *ea;
	int requested = 0;
	int offset;

	if (!inode)
		return ACTION_WANT_INODE | ACTION_WANT_ATTRS;

	if (fslist_format >= FORMAT_LUSTRE || need_ctx) {
		for (ea = eas; ea->name; ea++) {
			if (need_ctx &&
			    ea->index == EXT2_XATTR_INDEX_SECURITY &&
			    ea->name_len == 7 &&
			    !strncmp(ea->name, "selinux", 7)) {
				char *ctx_str = ea->value;

				ctx = ea;
				if (!ctx_str) {
					ea->requested = 1;
					requested++;
				} else {
					ctx_str[ctx->value_len - 1] = '\0';
				}
			}

			if (ea->index != EXT2_XATTR_INDEX_TRUSTED &&
			    ea->index != EXT2_XATTR_INDEX_LUSTRE)
				continue;

			if (ea->name_len == 3 && !strncmp(ea->name, "lov", 3)) {
				lov = ea;
				/* Request the EA value if it isn't loaded */
				if (!ea->value) {
					ea->requested = 1;
					requested++;
				}
			}

			if (show_fid && ea->name_len == 3 &&
						!strncmp(ea->name, "lma", 3)) {
				lma = ea;
				if (!ea->value) {
					ea->requested = 1;
					requested++;
				}
			}
		}
	}

	if (requested)
		return ACTION_WANT_READ_ATTRS;

	offset = build_path(parent, 0);
	fslist_output(outfile, ino, inode, offset, name, namelen, lov, lma, ctx);

	if (genhit && is_filters_match(inode, ctx))
		fslist_output(genhit, ino, inode, offset, name,
			      namelen, lov, lma, ctx);

	if (show_one)
		return ACTION_COMPLETE | ACTION_IGNORE_FILE;

	return ACTION_COMPLETE;
}

static int fslist_dscan_end(void)
{
	/* We only put a footer in for ne2scan compatibility */
	if (fslist_format == FORMAT_NE2SCAN) {
		fprintf(outfile, "#complete#%ld\n", time(NULL));
		if (genhit)
			fprintf(genhit, "#complete#%ld\n", time(NULL));
	}

	if (genhit)
		fclose(genhit);

	return 0;
}

struct action_ops fslist_action = {
	.name		= "fslist",
	.init		= fslist_init,
	.help		= fslist_help,
	.iscan		= fslist_iscan,
	.dscan_begin	= fslist_dscan_begin,
	.dscan		= fslist_dscan,
	.dscan_end	= fslist_dscan_end,
	.flags		= ACTION_FLAG_ISCAN_NO_EAS,
};
