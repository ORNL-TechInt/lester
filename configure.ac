AC_INIT([lester], [1.0], [help@nccs.gov], [lester])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.11 -Wall no-define foreign silent-rules subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG()

dnl We may be able to use older versions, but I have not verified that
PKG_CHECK_MODULES([ext2fs], [ext2fs >= 1.42.7 com_err >= 1.42.7])

dnl Pull the needed libraries into LIBS (needed for the AC_LINK_IFELSE below)
dnl These should never fail if the PKG_CHECK above passes
AC_SEARCH_LIBS([com_err], [com_err])
AC_SEARCH_LIBS([ext2fs_open2], [ext2fs])
AC_SEARCH_LIBS([io_queue_init], [aio], [],
	AC_MSG_ERROR([unable to find io_queue_init() -- install libaio-devel?]))

dnl io_channel_readahead() is actually a #define, so we cannot just use
dnl AC_CHECK_LIB here
AC_MSG_CHECKING([if we're using Lustre's libext2fs])
AC_LINK_IFELSE([
	AC_LANG_SOURCE([[#include <ext2fs/ext2fs.h>
		int main() {
			ext2_filsys fs;
			return io_channel_readahead(fs->io, 0, 0);
		}
	]])],
	[AC_MSG_RESULT(yes)
	 AC_DEFINE([HAVE_LUSTRE_EXTFS2], [1],
			[Define non-zero if using Lustre e2fsprogs])],
	[AC_MSG_RESULT(no)
	 AC_DEFINE([HAVE_LUSTRE_EXTFS2], [0],
			[Define non-zero if using Lustre e2fsprogs])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
