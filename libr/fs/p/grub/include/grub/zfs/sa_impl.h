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
#ifndef	_SYS_SA_IMPL_H
#define	_SYS_SA_IMPL_H

typedef struct sa_hdr_phys {
	grub_uint32_t sa_magic;
	grub_uint16_t sa_layout_info;
	grub_uint16_t sa_lengths[1];
} sa_hdr_phys_t;

#define	SA_HDR_SIZE(hdr)	BF32_GET_SB(hdr->sa_layout_info, 10, 16, 3, 0)
#define	SA_SIZE_OFFSET	0x8

#endif	/* _SYS_SA_IMPL_H */
