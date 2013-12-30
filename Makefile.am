
AUTOMAKE_OPTIONS = -Wall foreign
ACLOCAL_AMFLAGS = ${ALOCAL_FLAGS}

AM_CPPFLAGS = -Ilib
AM_CFLAGS = -Wall -Werror

bin_PROGRAMS = lester

lester_SOURCES = lester.c iscan.c dscan.c dtree.c attr.c \
		lib/aio_manager.c lib/block_async.c lib/inode_async.c \
		lib/get_stats.c lib/rbtree.c action-fslist.c action-namei.c \
		action-lsost.c
lester_CFLAGS = -Ilib

# Clean up all the generated files that are ignored in the source repo
#
mrproper: maintainer-clean
	rm -f Makefile.in aclocal.m4 configure
	rm -f compile depcomp install-sh missing
