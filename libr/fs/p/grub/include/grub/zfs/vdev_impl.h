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

#ifndef _SYS_VDEV_IMPL_H
#define	_SYS_VDEV_IMPL_H

#define	VDEV_SKIP_SIZE		(8 << 10)
#define	VDEV_BOOT_HEADER_SIZE	(8 << 10)
#define	VDEV_PHYS_SIZE		(112 << 10)
#define	VDEV_UBERBLOCK_RING	(128 << 10)

/* ZFS boot block */
#define	VDEV_BOOT_MAGIC		0x2f5b007b10cULL
#define	VDEV_BOOT_VERSION	1		/* version number	*/

typedef struct vdev_boot_header {
	grub_uint64_t	vb_magic;		/* VDEV_BOOT_MAGIC	*/
	grub_uint64_t	vb_version;		/* VDEV_BOOT_VERSION	*/
	grub_uint64_t	vb_offset;		/* start offset	(bytes) */
	grub_uint64_t	vb_size;		/* size (bytes)		*/
	char		vb_pad[VDEV_BOOT_HEADER_SIZE - 4 * sizeof (grub_uint64_t)];
} vdev_boot_header_t;

typedef struct vdev_phys {
	char		vp_nvlist[VDEV_PHYS_SIZE - sizeof (zio_eck_t)];
	zio_eck_t	vp_zbt;
} vdev_phys_t;

typedef struct vdev_label {
	char		vl_pad[VDEV_SKIP_SIZE];			/*   8K	*/
	vdev_boot_header_t vl_boot_header;			/*   8K	*/
	vdev_phys_t	vl_vdev_phys;				/* 112K	*/
	char		vl_uberblock[VDEV_UBERBLOCK_RING];	/* 128K	*/
} vdev_label_t;							/* 256K total */

/*
 * Size and offset of embedded boot loader region on each label.
 * The total size of the first two labels plus the boot area is 4MB.
 */
#define	VDEV_BOOT_OFFSET	(2 * sizeof (vdev_label_t))
#define	VDEV_BOOT_SIZE		(7ULL << 19)			/* 3.5M	*/

/*
 * Size of label regions at the start and end of each leaf device.
 */
#define	VDEV_LABEL_START_SIZE	(2 * sizeof (vdev_label_t) + VDEV_BOOT_SIZE)
#define	VDEV_LABEL_END_SIZE	(2 * sizeof (vdev_label_t))
#define	VDEV_LABELS		4

#endif	/* _SYS_VDEV_IMPL_H */
