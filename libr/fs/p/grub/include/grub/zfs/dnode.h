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

#ifndef	_SYS_DNODE_H
#define	_SYS_DNODE_H

#include <grub/zfs/spa.h>

/*
 * Fixed constants.
 */
#define	DNODE_SHIFT		9	/* 512 bytes */
#define	DN_MIN_INDBLKSHIFT	10	/* 1k */
#define	DN_MAX_INDBLKSHIFT	14	/* 16k */
#define	DNODE_BLOCK_SHIFT	14	/* 16k */
#define	DNODE_CORE_SIZE		64	/* 64 bytes for dnode sans blkptrs */
#define	DN_MAX_OBJECT_SHIFT	48	/* 256 trillion (zfs_fid_t limit) */
#define	DN_MAX_OFFSET_SHIFT	64	/* 2^64 bytes in a dnode */

/*
 * Derived constants.
 */
#define	DNODE_SIZE	(1 << DNODE_SHIFT)
#define	DN_MAX_NBLKPTR	((DNODE_SIZE - DNODE_CORE_SIZE) >> SPA_BLKPTRSHIFT)
#define	DN_MAX_BONUSLEN	(DNODE_SIZE - DNODE_CORE_SIZE - (1 << SPA_BLKPTRSHIFT))
#define	DN_MAX_OBJECT	(1ULL << DN_MAX_OBJECT_SHIFT)

#define	DNODES_PER_BLOCK_SHIFT	(DNODE_BLOCK_SHIFT - DNODE_SHIFT)
#define	DNODES_PER_BLOCK	(1ULL << DNODES_PER_BLOCK_SHIFT)
#define	DNODES_PER_LEVEL_SHIFT	(DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT)

#define	DNODE_FLAG_SPILL_BLKPTR (1<<2)

#define	DN_BONUS(dnp)	((void*)((dnp)->dn_bonus + \
	(((dnp)->dn_nblkptr - 1) * sizeof (blkptr_t))))

typedef struct dnode_phys {
	grub_uint8_t dn_type;		/* dmu_object_type_t */
	grub_uint8_t dn_indblkshift;		/* ln2(indirect block size) */
	grub_uint8_t dn_nlevels;		/* 1=dn_blkptr->data blocks */
	grub_uint8_t dn_nblkptr;		/* length of dn_blkptr */
	grub_uint8_t dn_bonustype;		/* type of data in bonus buffer */
	grub_uint8_t	dn_checksum;		/* ZIO_CHECKSUM type */
	grub_uint8_t	dn_compress;		/* ZIO_COMPRESS type */
	grub_uint8_t dn_flags;		/* DNODE_FLAG_* */
	grub_uint16_t dn_datablkszsec;	/* data block size in 512b sectors */
	grub_uint16_t dn_bonuslen;		/* length of dn_bonus */
	grub_uint8_t dn_pad2[4];

	/* accounting is protected by dn_dirty_mtx */
	grub_uint64_t dn_maxblkid;		/* largest allocated block ID */
	grub_uint64_t dn_used;		/* bytes (or sectors) of disk space */

	grub_uint64_t dn_pad3[4];

	blkptr_t dn_blkptr[1];
	grub_uint8_t dn_bonus[DN_MAX_BONUSLEN - sizeof (blkptr_t)];
	blkptr_t dn_spill;
} dnode_phys_t;

#endif	/* _SYS_DNODE_H */
