/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  GRUB is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DSL_DATASET_H
#define	_SYS_DSL_DATASET_H

typedef struct dsl_dataset_phys {
	grub_uint64_t ds_dir_obj;
	grub_uint64_t ds_prev_snap_obj;
	grub_uint64_t ds_prev_snap_txg;
	grub_uint64_t ds_next_snap_obj;
	grub_uint64_t ds_snapnames_zapobj;	/* zap obj of snaps; ==0 for snaps */
	grub_uint64_t ds_num_children;	/* clone/snap children; ==0 for head */
	grub_uint64_t ds_creation_time;	/* seconds since 1970 */
	grub_uint64_t ds_creation_txg;
	grub_uint64_t ds_deadlist_obj;
	grub_uint64_t ds_used_bytes;
	grub_uint64_t ds_compressed_bytes;
	grub_uint64_t ds_uncompressed_bytes;
	grub_uint64_t ds_unique_bytes;	/* only relevant to snapshots */
	/*
	 * The ds_fsid_guid is a 56-bit ID that can change to avoid
	 * collisions.  The ds_guid is a 64-bit ID that will never
	 * change, so there is a small probability that it will collide.
	 */
	grub_uint64_t ds_fsid_guid;
	grub_uint64_t ds_guid;
	grub_uint64_t ds_flags;
	blkptr_t ds_bp;
	grub_uint64_t ds_pad[8]; /* pad out to 320 bytes for good measure */
} dsl_dataset_phys_t;

#endif /* _SYS_DSL_DATASET_H */
