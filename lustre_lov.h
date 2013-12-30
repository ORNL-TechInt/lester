/* lustre_lov.h -- Lustre structures
 *
 * Derived from Lustre headers
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 *
 * This file may be redistributed under the terms of the GNU General
 * Public License version 2; see COPYING for details.
 */
#ifndef __lustre_lov_h
#define __lustre_lov_h 1

/* Should use Lustre's headers, if possible. This is here for build
 * testing against plain libext2fs.
 */
#ifndef EXT2_XATTR_INDEX_TRUSTED
#define EXT2_XATTR_INDEX_TRUSTED	4
#endif
#ifndef EXT2_XATTR_INDEX_LUSTRE
#define EXT2_XATTR_INDEX_LUSTRE		5
#endif

/* From lustre_idl.h */
#define LOV_MAGIC_V1	0x0BD10BD0
#define LOV_MAGIC_V3	0x0BD30BD0
#define MAXPOOLNAME	16

struct lov_ost_data_v1 {	/* per-stripe data structure (little-endian)*/
	__u64 l_object_id;	/* OST object ID */
	__u64 l_object_gr;	/* OST object group (creating MDS number) */
	__u32 l_ost_gen;	/* generation of this l_ost_idx */
	__u32 l_ost_idx;	/* OST index in LOV (lov_tgt_desc->tgts) */
};

struct lov_mds_md_v1 {		/* LOV EA mds/wire data (little-endian) */
	__u32 lmm_magic;	/* magic number = LOV_MAGIC_V1 */
	__u32 lmm_pattern;	/* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	__u64 lmm_object_id;	/* LOV object ID */
	__u64 lmm_object_gr;	/* LOV object group */
	__u32 lmm_stripe_size;	/* size of stripe in bytes */
	__u32 lmm_stripe_count;	/* num stripes in use for this object */
	struct lov_ost_data_v1 lmm_objects[0]; /* per-stripe data */
};

struct lov_mds_md_v3 {		/* LOV EA mds/wire data (little-endian) */
	__u32 lmm_magic;	/* magic number = LOV_MAGIC_V3 */
	__u32 lmm_pattern;	/* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	__u64 lmm_object_id;	/* LOV object ID */
	__u64 lmm_object_gr;	/* LOV object group */
	__u32 lmm_stripe_size;	/* size of stripe in bytes */
	__u32 lmm_stripe_count;	/* num stripes in use for this object */
	char  lmm_pool_name[MAXPOOLNAME]; /* must be 32bit aligned */
	struct lov_ost_data_v1 lmm_objects[0]; /* per-stripe data */
};

struct lu_fid {
	/**
	 * FID sequence. Sequence is a unit of migration: all files (objects)
	 * with FIDs from a given sequence are stored on the same server.
	 * Lustre should support 2^64 objects, so even if each sequence
	 * has only a single object we can still enumerate 2^64 objects.
	 */
	__u64 f_seq;
	/** FID number within sequence. */
	__u32 f_oid;
        /**
	 * FID version, used to distinguish different versions (in the sense
	 * of snapshots, etc.) of the same file system object. Not currently
	 * used.
	 */
	__u32 f_ver;
};

struct lustre_mdt_attrs {
        /**
	 * Bitfield for supported data in this structure. From enum lma_compat.
	 * lma_self_fid and lma_flags are always available.
	 */
	__u32	lma_compat;
	/**
	 * Per-file incompat feature list. Lustre version should support all
	 * flags set in this field. The supported feature mask is available in
	 * LMA_INCOMPAT_SUPP.
	 */
	__u32	lma_incompat;
	/** FID of this inode */
	struct lu_fid	lma_self_fid;
	/** mdt/ost type, others */
	__u64	lma_flags;
	/* IO Epoch SOM attributes belongs to */
	__u64	lma_ioepoch;
	/** total file size in objects */
	__u64	lma_som_size;
	/** total fs blocks in objects */
	__u64	lma_som_blocks;
	/** mds mount id the size is valid for */
	__u64	lma_som_mountid;
};

#endif /* __lustre_lov_h */
