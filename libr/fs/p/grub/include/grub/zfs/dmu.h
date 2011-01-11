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

#ifndef	_SYS_DMU_H
#define	_SYS_DMU_H

/*
 * This file describes the interface that the DMU provides for its
 * consumers.
 *
 * The DMU also interacts with the SPA.  That interface is described in
 * dmu_spa.h.
 */
typedef enum dmu_object_type {
	DMU_OT_NONE,
	/* general: */
	DMU_OT_OBJECT_DIRECTORY,	/* ZAP */
	DMU_OT_OBJECT_ARRAY,		/* UINT64 */
	DMU_OT_PACKED_NVLIST,		/* UINT8 (XDR by nvlist_pack/unpack) */
	DMU_OT_PACKED_NVLIST_SIZE,	/* UINT64 */
	DMU_OT_BPLIST,			/* UINT64 */
	DMU_OT_BPLIST_HDR,		/* UINT64 */
	/* spa: */
	DMU_OT_SPACE_MAP_HEADER,	/* UINT64 */
	DMU_OT_SPACE_MAP,		/* UINT64 */
	/* zil: */
	DMU_OT_INTENT_LOG,		/* UINT64 */
	/* dmu: */
	DMU_OT_DNODE,			/* DNODE */
	DMU_OT_OBJSET,			/* OBJSET */
	/* dsl: */
	DMU_OT_DSL_DIR,			/* UINT64 */
	DMU_OT_DSL_DIR_CHILD_MAP,	/* ZAP */
	DMU_OT_DSL_DS_SNAP_MAP,		/* ZAP */
	DMU_OT_DSL_PROPS,		/* ZAP */
	DMU_OT_DSL_DATASET,		/* UINT64 */
	/* zpl: */
	DMU_OT_ZNODE,			/* ZNODE */
	DMU_OT_OLDACL,			/* OLD ACL */
	DMU_OT_PLAIN_FILE_CONTENTS,	/* UINT8 */
	DMU_OT_DIRECTORY_CONTENTS,	/* ZAP */
	DMU_OT_MASTER_NODE,		/* ZAP */
	DMU_OT_UNLINKED_SET,		/* ZAP */
	/* zvol: */
	DMU_OT_ZVOL,			/* UINT8 */
	DMU_OT_ZVOL_PROP,		/* ZAP */
	/* other; for testing only! */
	DMU_OT_PLAIN_OTHER,		/* UINT8 */
	DMU_OT_UINT64_OTHER,		/* UINT64 */
	DMU_OT_ZAP_OTHER,		/* ZAP */
	/* new object types: */
	DMU_OT_ERROR_LOG,		/* ZAP */
	DMU_OT_SPA_HISTORY,		/* UINT8 */
	DMU_OT_SPA_HISTORY_OFFSETS,	/* spa_his_phys_t */
	DMU_OT_POOL_PROPS,		/* ZAP */
	DMU_OT_DSL_PERMS,		/* ZAP */
	DMU_OT_ACL,			/* ACL */
	DMU_OT_SYSACL,			/* SYSACL */
	DMU_OT_FUID,			/* FUID table (Packed NVLIST UINT8) */
	DMU_OT_FUID_SIZE,		/* FUID table size UINT64 */
	DMU_OT_NEXT_CLONES,		/* ZAP */
	DMU_OT_SCRUB_QUEUE,		/* ZAP */
	DMU_OT_USERGROUP_USED,		/* ZAP */
	DMU_OT_USERGROUP_QUOTA,		/* ZAP */
	DMU_OT_USERREFS,		/* ZAP */
	DMU_OT_DDT_ZAP,			/* ZAP */
	DMU_OT_DDT_STATS,		/* ZAP */
	DMU_OT_SA,			/* System attr */
	DMU_OT_SA_MASTER_NODE,		/* ZAP */
	DMU_OT_SA_ATTR_REGISTRATION,	/* ZAP */
	DMU_OT_SA_ATTR_LAYOUTS,		/* ZAP */
	DMU_OT_NUMTYPES
} dmu_object_type_t;

typedef enum dmu_objset_type {
	DMU_OST_NONE,
	DMU_OST_META,
	DMU_OST_ZFS,
	DMU_OST_ZVOL,
	DMU_OST_OTHER,			/* For testing only! */
	DMU_OST_ANY,			/* Be careful! */
	DMU_OST_NUMTYPES
} dmu_objset_type_t;

/*
 * The names of zap entries in the DIRECTORY_OBJECT of the MOS.
 */
#define	DMU_POOL_DIRECTORY_OBJECT	1
#define	DMU_POOL_CONFIG			"config"
#define	DMU_POOL_ROOT_DATASET		"root_dataset"
#define	DMU_POOL_SYNC_BPLIST		"sync_bplist"
#define	DMU_POOL_ERRLOG_SCRUB		"errlog_scrub"
#define	DMU_POOL_ERRLOG_LAST		"errlog_last"
#define	DMU_POOL_SPARES			"spares"
#define	DMU_POOL_DEFLATE		"deflate"
#define	DMU_POOL_HISTORY		"history"
#define	DMU_POOL_PROPS			"pool_props"
#define	DMU_POOL_L2CACHE		"l2cache"

#endif	/* _SYS_DMU_H */
