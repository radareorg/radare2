/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2006,2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#ifndef GRUB_HFS_HEADER
#define GRUB_HFS_HEADER	1

#include <grub/types.h>

#define GRUB_HFS_MAGIC		0x4244

/* A single extent.  A file consists of one or more extents.  */
struct grub_hfs_extent
{
  /* The first physical block.  */
  grub_uint16_t first_block;
  grub_uint16_t count;
};

/* HFS stores extents in groups of 3.  */
typedef struct grub_hfs_extent grub_hfs_datarecord_t[3];

/* The HFS superblock (The official name is `Master Directory
   Block').  */
struct grub_hfs_sblock
{
  grub_uint16_t magic;
  grub_uint8_t unused[18];
  grub_uint32_t blksz;
  grub_uint8_t unused2[4];
  grub_uint16_t first_block;
  grub_uint8_t unused4[6];

  /* A pascal style string that holds the volumename.  */
  grub_uint8_t volname[28];

  grub_uint8_t unused5[52];
  grub_uint64_t num_serial;
  grub_uint16_t embed_sig;
  struct grub_hfs_extent embed_extent;
  grub_uint8_t unused6[4];
  grub_hfs_datarecord_t extent_recs;
  grub_uint32_t catalog_size;
  grub_hfs_datarecord_t catalog_recs;
} __attribute__ ((packed));

#endif /* ! GRUB_HFS_HEADER */
