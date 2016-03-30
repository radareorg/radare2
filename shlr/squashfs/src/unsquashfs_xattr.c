/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * unsquashfs_xattr.c
 */

#include "unsquashfs.h"
#include "xattr.h"

#include <sys/xattr.h>

extern int root_process;

void write_xattr(char *pathname, unsigned int xattr)
{
	unsigned int count;
	struct xattr_list *xattr_list;
	int i;

	if(xattr == SQUASHFS_INVALID_XATTR ||
			sBlk.s.xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return;

	xattr_list = get_xattr(xattr, &count);
	if(xattr_list == NULL) {
		ERROR("Failed to read xattrs for file %s\n", pathname);
		return;
	}

	for(i = 0; i < count; i++) {
		int prefix = xattr_list[i].type & SQUASHFS_XATTR_PREFIX_MASK;

		if(root_process || prefix == SQUASHFS_XATTR_USER) {
#if 0
			int res = lsetxattr(pathname, xattr_list[i].full_name,
				xattr_list[i].value, xattr_list[i].vsize, 0);
#endif
			int res = -1;

			if(res == -1)
				ERROR("write_xattr: failed to write xattr %s"
					" for file %s because %s\n",
					xattr_list[i].full_name, pathname,
					errno == ENOSPC || errno == EDQUOT ?
					"no extended attribute space remaining "
					"on destination filesystem" :
					errno == ENOTSUP ?
					"extended attributes are not supported "
					"by the destination filesystem" :
					"a weird error occurred");
		} else
			ERROR("write_xattr: could not write xattr %s "
					"for file %s because you're not "
					"superuser!\n",
					xattr_list[i].full_name, pathname);
	}
}
