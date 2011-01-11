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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_UBERBLOCK_IMPL_H
#define	_SYS_UBERBLOCK_IMPL_H

/*
 * The uberblock version is incremented whenever an incompatible on-disk
 * format change is made to the SPA, DMU, or ZAP.
 *
 * Note: the first two fields should never be moved.  When a storage pool
 * is opened, the uberblock must be read off the disk before the version
 * can be checked.  If the ub_version field is moved, we may not detect
 * version mismatch.  If the ub_magic field is moved, applications that
 * expect the magic number in the first word won't work.
 */
#define	UBERBLOCK_MAGIC		0x00bab10c		/* oo-ba-bloc!	*/
#define	UBERBLOCK_SHIFT		10			/* up to 1K	*/

typedef struct uberblock {
	grub_uint64_t	ub_magic;	/* UBERBLOCK_MAGIC		*/
	grub_uint64_t	ub_version;	/* ZFS_VERSION			*/
	grub_uint64_t	ub_txg;		/* txg of last sync		*/
	grub_uint64_t	ub_guid_sum;	/* sum of all vdev guids	*/
	grub_uint64_t	ub_timestamp;	/* UTC time of last sync	*/
	blkptr_t	ub_rootbp;	/* MOS objset_phys_t		*/
} uberblock_t;

#define	UBERBLOCK_SIZE		(1ULL << UBERBLOCK_SHIFT)
#define	VDEV_UBERBLOCK_SHIFT	UBERBLOCK_SHIFT

/* XXX Uberblock_phys_t is no longer in the kernel zfs */
typedef struct uberblock_phys {
	uberblock_t	ubp_uberblock;
	char		ubp_pad[UBERBLOCK_SIZE - sizeof (uberblock_t) -
				sizeof (zio_eck_t)];
	zio_eck_t	ubp_zec;
} uberblock_phys_t;


#endif	/* _SYS_UBERBLOCK_IMPL_H */
