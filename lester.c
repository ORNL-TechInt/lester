/* lester.c -- the Lustre lister (also works for ext2+)
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>
#include "lester.h"

ext2_filsys fs;
FILE *outfile;

char *root_path = "/";
unsigned int verbosity = 0;
int use_unix = 0;

static unsigned long max_async = 128 * 1024;
struct action_ops *scan_action = NULL;

void diff_timevals(struct timeval *start, struct timeval *end,
				struct timeval *out)
{
	out->tv_sec = end->tv_sec - start->tv_sec;
	out->tv_usec = end->tv_usec - start->tv_usec;
	if (start->tv_usec > end->tv_usec) {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
}

int enforce_async_limit(void)
{
	unsigned long async_count;
	errcode_t rc;

	rc = io_channel_async_count(fs->io, &async_count);
	if (rc) {
		com_err("io_channel_async_count", rc,
			"failed to get async count");
		return 1;
	}

	if (async_count > max_async) {
		rc = io_channel_finish_async(fs->io, 0);
		if (rc) {
			com_err("io_channel_finish_async", rc,
				"failed to finish async");
			return 1;
		}
	}

	return 0;
}

static int read_bitmaps(const char *dev)
{
	struct timeval start, end, diff;
	errcode_t rc;
	int i;

	if (verbosity)
		fprintf(stdout, "Starting bitmaps\n");

	gettimeofday(&start, NULL);
	for (i = 0; i < fs->group_desc_count; i++) {
		if (!(ext2fs_bg_flags(fs, i) & EXT2_BG_INODE_UNINIT))
			io_channel_readahead(fs->io,
					     ext2fs_inode_table_loc(fs, i), 1);
	}

	rc = ext2fs_read_inode_bitmap(fs);
	if (rc) {
		com_err("ext2fs_read_inode_bitmap", rc,
			"opening inode bitmap on %s\n", dev);
		return 1;
	}

	if (verbosity) {
		gettimeofday(&end, NULL);
		diff_timevals(&start, &end, &diff);
		fprintf(stdout, "Finished bitmaps in %d.%06u seconds\n",
				(int) diff.tv_sec, (unsigned int) diff.tv_usec);
	}
	return 0;
}

static int run_scan(const char *dev, const char *io_opts)
{
	struct timeval start, now, diff;
	errcode_t rc;

	gettimeofday(&start, NULL);

	rc = ext2fs_open2(dev, io_opts, EXT2_FLAG_SOFTSUPP_FEATURES, 0, 0,
			  use_unix ? unix_io_manager : aio_io_manager, &fs);
	if (rc) {
		com_err("ext2fs_open", rc, "opening %s\n", dev);
		return 1;
	}

	if (read_bitmaps(dev))
		return 1;

	rc = ext2fs_init_dblist(fs, NULL);
	if (rc) {
		com_err("ext2fs_init_dblist", rc, "initializing dblist\n");
		return 1;
	}

	if (scan_inodes(dev))
		return 1;

	if (resolve_paths())
		return 1;

	ext2fs_close(fs);

	if (verbosity) {
		gettimeofday(&now, NULL);
		diff_timevals(&start, &now, &diff);
		fprintf(stdout, "Success! Finished in %d.%06u seconds\n",
				(int) diff.tv_sec, (unsigned int) diff.tv_usec);
	}

	return 0;
}

static void usage(const char *pname)
{
	fprintf(stderr, "Lester, the Lustre lister (version %s)\n\n",
			PACKAGE_VERSION);
	fprintf(stderr, "usage: %s [OPTIONS] BLOCKDEV\n", pname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h,--help\t\t\t\tThis message\n");
	fprintf(stderr, "    -v,--verbose\t\t\tIncrease verbosity level\n");
	fprintf(stderr, "    -u,--unix\t\t\t\tUse the Unix IO manager\n");
	fprintf(stderr, "    -o=FILE,--output=FILE\t\t"
			"Direct result of scan to FILE\n");
	fprintf(stderr, "    -A=NAME,--action=NAME\t\tScan action to "
			"perform (default fslist)\n");
	fprintf(stderr, "\t\t\t\t\t    fslist:\n");
	fprintf(stderr, "\t\t\t\t\t\tList files matching criteria\n");
	fprintf(stderr, "\t\t\t\t\t    namei:\n");
	fprintf(stderr, "\t\t\t\t\t\tFind names for inodes\n");
	fprintf(stderr, "\t\t\t\t\t    lsost:\n");
	fprintf(stderr, "\t\t\t\t\t\tFind files on given OSTs\n");
	fprintf(stderr, "    -a=ARG,--action-arg=ARG\t\tPass argument to scan "
			"action\n");
	fprintf(stderr, "\t\t\t\t\t    Use \"-a help\" to get list\n");
	fprintf(stderr, "    -r=PATH,--root=PATH\t\t\tHide files not under "
			"PATH\n");
	fprintf(stderr, "    -g=NUM,--group-readahead=NUM\t"
			"Readahead NUM groups in the inode table\n");
	fprintf(stderr, "\t\t\t\t\t    Default 1 for Unix manager\n");
	fprintf(stderr, "\t\t\t\t\t    Default 8 for AIO manager\n");
	fprintf(stderr, "    -d=NUM,--dir-readahead=NUM\t\t"
			"Readahead NUM chunks in the dir scan\n");
	fprintf(stderr, "\t\t\t\t\t    Default 2 for Unix manager\n");
	fprintf(stderr, "\t\t\t\t\t    Default 64 for AIO manager\n");
	fprintf(stderr, "    -m,=NUM,--max-async=NUM\t\t"
			"Max number of outstanding async\n");
	fprintf(stderr, "\t\t\t\t\t  requests allowed\n");
	fprintf(stderr, "    -O=ARG,--io-options=ARG\t\t"
			"Pass options to IO manager\n");
	fprintf(stderr, "\tAIO manager supported options (separated by &):\n");
	fprintf(stderr, "\t\tmaxsize=KB\t\tMaximum request size in KB\n");
	fprintf(stderr, "\t\t(qd|queuedepth)=INT\tMaximum queue depth\n");
	fprintf(stderr, "\t\tcache_entries=INT\tNumber of cache blocks "
			"to allocate\n");
	fprintf(stderr, "\t\treserved_entries=INT\tCache blocks reserved "
			"for sync IO\n");
	fprintf(stderr, "\t\treq_preallocate=INT\tPreallocate queue entries\n");
	fprintf(stderr, "\t\tmerge_gap=KB\t\tAllowed gap between "
			"merged async reqs\n");

	exit(2);
}

int main(int argc, char **argv)
{
	const char *output = NULL;
	const char *device = NULL;
	const char *io_opts = NULL;
	const char *action = NULL;
	const char **action_argv;
	int action_argc = 0;
	int action_help = 0;

	static struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "io-options", required_argument, NULL, 'O' },
		{ "unix", required_argument, NULL, 'u' },
		{ "group-readahead", required_argument, NULL, 'g' },
		{ "dir-readahead", required_argument, NULL, 'd' },
		{ "output", required_argument, NULL, 'p' },
		{ "max-async", required_argument, NULL, 'm' },
		{ "action", required_argument, NULL, 'A' },
		{ "action-arg", required_argument, NULL, 'a' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "root", required_argument, NULL, 'r' },
		{ NULL }
	};

	action_argv = calloc(argc, sizeof(char *));
	if (!action_argv) {
		fprintf(stderr, "unable to allocate memory for args\n");
		exit(1);
	}

	for (;;) {
		int opt = getopt_long(argc, argv, "hO:ug:d:o:m:A:a:vr:",
							options, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'o':
			output = optarg;
			break;
		case 'O':
			io_opts = optarg;
			break;
		case 'u':
			use_unix = 1;
			break;
		case 'g':
			grp_readahead = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			dir_readahead = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			max_async = strtoul(optarg, NULL, 0);
			break;
		case 'A':
			if (action) {
				fprintf(stderr, "Only specify one action\n");
				exit(1);
			}
			action = optarg;
			break;
		case 'a':
			action_argv[action_argc++] = optarg;
			if (!strcmp(optarg, "help"))
				action_help = 1;
			break;
		case 'r':
			root_path = optarg;
			break;
		case 'v':
			verbosity++;
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			break;
		}
	}

	if (!action)
		action = "fslist";

	if (!action_help && optind == argc) {
		fprintf(stderr, "%s: missing block device\n", argv[0]);
		usage(argv[0]);
	}
	device = argv[optind];

	if (grp_readahead == 0)
		grp_readahead = use_unix ? 1 : 8;

	if (dir_readahead == 0)
		dir_readahead = use_unix ? 2 : 64;

	add_error_table(&et_ext2_error_table);

	if (!strcmp(action, "fslist"))
		scan_action = &fslist_action;
	else if (!strcmp(action, "namei"))
		scan_action = &namei_action;
	else if (!strcmp(action, "lsost"))
		scan_action = &lsost_action;
	else {
		fprintf(stderr, "%s: unknown action \"%s\"\n", argv[0], action);
		return 1;
	}

	if (action_help) {
		scan_action->help();
		return 2;
	}

	if (scan_action->init(device, action_argc, action_argv))
		return 1;

	if (output) {
		outfile = fopen(output, "w");
		if (!outfile) {
			com_err("fopen", errno, "opening output file\n");
			return 1;
		}
	} else
		outfile = stdout;

	return run_scan(device, io_opts);
}
