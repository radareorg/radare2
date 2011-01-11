/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *  Copyright (C) 2010  Robert Millan <rmh@gnu.org>
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DMU_OBJSET_H
#define	_SYS_DMU_OBJSET_H

#include <grub/zfs/zil.h>

#define OBJSET_PHYS_SIZE	2048
#define OBJSET_PHYS_SIZE_V14	1024

typedef struct objset_phys {
	dnode_phys_t os_meta_dnode;
	zil_header_t os_zil_header;
	grub_uint64_t os_type;
	grub_uint64_t os_flags;
	char os_pad[OBJSET_PHYS_SIZE - sizeof (dnode_phys_t)*3 -
	    sizeof (zil_header_t) - sizeof (grub_uint64_t)*2];
	dnode_phys_t os_userused_dnode;
	dnode_phys_t os_groupused_dnode;
} objset_phys_t;

#endif /* _SYS_DMU_OBJSET_H */
