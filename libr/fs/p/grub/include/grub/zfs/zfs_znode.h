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

#ifndef	_SYS_FS_ZFS_ZNODE_H
#define	_SYS_FS_ZFS_ZNODE_H

#include <grub/zfs/zfs_acl.h>

#define	MASTER_NODE_OBJ	1
#define	ZFS_ROOT_OBJ		"ROOT"
#define	ZPL_VERSION_STR		"VERSION"
#define	ZFS_SA_ATTRS		"SA_ATTRS"

#define	ZPL_VERSION		5ULL

#define	ZFS_DIRENT_OBJ(de) BF64_GET(de, 0, 48)

/*
 * This is the persistent portion of the znode.  It is stored
 * in the "bonus buffer" of the file.  Short symbolic links
 * are also stored in the bonus buffer.
 */
typedef struct znode_phys {
	grub_uint64_t zp_atime[2];      /*  0 - last file access time */
	grub_uint64_t zp_mtime[2];	/* 16 - last file modification time */
	grub_uint64_t zp_ctime[2];	/* 32 - last file change time */
	grub_uint64_t zp_crtime[2];	/* 48 - creation time */
	grub_uint64_t zp_gen;		/* 64 - generation (txg of creation) */
	grub_uint64_t zp_mode;		/* 72 - file mode bits */
	grub_uint64_t zp_size;		/* 80 - size of file */
	grub_uint64_t zp_parent;	/* 88 - directory parent (`..') */
	grub_uint64_t zp_links;		/* 96 - number of links to file */
	grub_uint64_t zp_xattr;		/* 104 - DMU object for xattrs */
	grub_uint64_t zp_rdev;		/* 112 - dev_t for VBLK & VCHR files */
	grub_uint64_t zp_flags;		/* 120 - persistent flags */
	grub_uint64_t zp_uid;		/* 128 - file owner */
	grub_uint64_t zp_gid;		/* 136 - owning group */
	grub_uint64_t zp_pad[4];	/* 144 - future */
	zfs_znode_acl_t zp_acl;		/* 176 - 263 ACL */
	/*
	 * Data may pad out any remaining bytes in the znode buffer, eg:
	 *
	 * |<---------------------- dnode_phys (512) ------------------------>|
	 * |<-- dnode (192) --->|<----------- "bonus" buffer (320) ---------->|
	 *			|<---- znode (264) ---->|<---- data (56) ---->|
	 *
	 * At present, we only use this space to store symbolic links.
	 */
} znode_phys_t;

#endif	/* _SYS_FS_ZFS_ZNODE_H */
