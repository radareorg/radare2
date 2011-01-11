/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2009  Free Software Foundation, Inc.
 *  Copyright 2007 Sun Microsystems, Inc.
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

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/zfs/zfs.h>
#include <grub/zfs/zio.h>
#include <grub/zfs/dnode.h>
#include <grub/zfs/uberblock_impl.h>
#include <grub/zfs/vdev_impl.h>
#include <grub/zfs/zio_checksum.h>
#include <grub/zfs/zap_impl.h>
#include <grub/zfs/zap_leaf.h>
#include <grub/zfs/zfs_znode.h>
#include <grub/zfs/dmu.h>
#include <grub/zfs/dmu_objset.h>
#include <grub/zfs/dsl_dir.h>
#include <grub/zfs/dsl_dataset.h>

#define	MATCH_BITS	6
#define	MATCH_MIN	3
#define	OFFSET_MASK	((1 << (16 - MATCH_BITS)) - 1)

/*
 * Decompression Entry - lzjb
 */
#ifndef	NBBY
#define	NBBY	8
#endif

grub_err_t
lzjb_decompress (void *s_start, void *d_start, grub_size_t s_len,
		 grub_size_t d_len);

grub_err_t
lzjb_decompress (void *s_start, void *d_start, grub_size_t s_len,
		 grub_size_t d_len)
{
  grub_uint8_t *src = s_start;
  grub_uint8_t *dst = d_start;
  grub_uint8_t *d_end = (grub_uint8_t *) d_start + d_len;
  grub_uint8_t *s_end = (grub_uint8_t *) s_start + s_len;
  grub_uint8_t *cpy, copymap = 0;
  int copymask = 1 << (NBBY - 1);

  while (dst < d_end && src < s_end)
    {
      if ((copymask <<= 1) == (1 << NBBY))
	{
	  copymask = 1;
	  copymap = *src++;
	}
      if (src >= s_end)
	return grub_error (GRUB_ERR_BAD_FS, "lzjb decompression failed");
      if (copymap & copymask)
	{
	  int mlen = (src[0] >> (NBBY - MATCH_BITS)) + MATCH_MIN;
	  int offset = ((src[0] << NBBY) | src[1]) & OFFSET_MASK;
	  src += 2;
	  cpy = dst - offset;
	  if (src > s_end || cpy < (grub_uint8_t *) d_start)
	    return grub_error (GRUB_ERR_BAD_FS, "lzjb decompression failed");
	  while (--mlen >= 0 && dst < d_end)
	    *dst++ = *cpy++;
	}
      else
	*dst++ = *src++;
    }
  if (dst < d_end)
    return grub_error (GRUB_ERR_BAD_FS, "lzjb decompression failed");
  return GRUB_ERR_NONE;
}
