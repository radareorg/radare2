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

#ifndef	_SYS_DSL_DIR_H
#define	_SYS_DSL_DIR_H

typedef struct dsl_dir_phys {
	grub_uint64_t dd_creation_time; /* not actually used */
	grub_uint64_t dd_head_dataset_obj;
	grub_uint64_t dd_parent_obj;
	grub_uint64_t dd_clone_parent_obj;
	grub_uint64_t dd_child_dir_zapobj;
	/*
	 * how much space our children are accounting for; for leaf
	 * datasets, == physical space used by fs + snaps
	 */
	grub_uint64_t dd_used_bytes;
	grub_uint64_t dd_compressed_bytes;
	grub_uint64_t dd_uncompressed_bytes;
	/* Administrative quota setting */
	grub_uint64_t dd_quota;
	/* Administrative reservation setting */
	grub_uint64_t dd_reserved;
	grub_uint64_t dd_props_zapobj;
	grub_uint64_t dd_deleg_zapobj;	/* dataset permissions */
	grub_uint64_t dd_pad[20]; /* pad out to 256 bytes for good measure */
} dsl_dir_phys_t;

#endif /* _SYS_DSL_DIR_H */
