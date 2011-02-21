/* amiga.c - Read amiga partition tables (RDB).  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2004,2005,2006,2007  Free Software Foundation, Inc.
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

#include <grub/disk.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/dl.h>

struct grub_amiga_rdsk
{
  /* "RDSK".  */
  grub_uint8_t magic[4];
  grub_uint32_t size;
  grub_int32_t checksum;
  grub_uint32_t scsihost;
  grub_uint32_t blksz;
  grub_uint32_t flags;
  grub_uint32_t badblcklst;
  grub_uint32_t partitionlst;
  grub_uint32_t fslst;

  /* The other information is not important for us.  */
} __attribute__ ((packed));

struct grub_amiga_partition
{
  /* "PART".  */
  grub_uint8_t magic[4];
  grub_int32_t size;
  grub_int32_t checksum;
  grub_uint32_t scsihost;
  grub_uint32_t next;
  grub_uint32_t flags;
  grub_uint32_t unused1[2];
  grub_uint32_t devflags;
  grub_uint8_t namelen;
  grub_uint8_t name[31];
  grub_uint32_t unused2[15];

  grub_uint32_t unused3[3];
  grub_uint32_t heads;
  grub_uint32_t unused4;
  grub_uint32_t block_per_track;
  grub_uint32_t unused5[3];
  grub_uint32_t lowcyl;
  grub_uint32_t highcyl;

  grub_uint32_t firstcyl;
} __attribute__ ((packed));

struct grub_partition_map grub_amiga_partition_map;



static grub_err_t
amiga_partition_map_iterate (grub_disk_t disk,
			     int (*hook) (grub_disk_t disk,
					  const grub_partition_t partition,
					  void *closure),
			     void *closure)
{
  struct grub_partition part;
  struct grub_amiga_rdsk rdsk;
  int partno = 0;
  int next = -1;
  unsigned pos;

  /* The RDSK block is one of the first 15 blocks.  */
  for (pos = 0; pos < 15; pos++)
    {
      /* Read the RDSK block which is a descriptor for the entire disk.  */
      if (grub_disk_read (disk, pos, 0, sizeof (rdsk), &rdsk))
	return grub_errno;

      if (grub_strcmp ((char *) rdsk.magic, "RDSK") == 0)
	{
	  /* Found the first PART block.  */
	  next = grub_be_to_cpu32 (rdsk.partitionlst);
	  break;
	}
    }

  if (next == -1)
    return grub_error (GRUB_ERR_BAD_PART_TABLE,
		       "Amiga partition map not found");

  /* The end of the partition list is marked using "-1".  */
  while (next != -1)
    {
      struct grub_amiga_partition apart;

      /* Read the RDSK block which is a descriptor for the entire disk.  */
      if (grub_disk_read (disk, next, 0, sizeof (apart), &apart))
	return grub_errno;

      /* Calculate the first block and the size of the partition.  */
      part.start = (grub_be_to_cpu32 (apart.lowcyl)
		    * grub_be_to_cpu32 (apart.heads)
		    * grub_be_to_cpu32 (apart.block_per_track));
      part.len = ((grub_be_to_cpu32 (apart.highcyl)
		   - grub_be_to_cpu32 (apart.lowcyl) + 1)
		  * grub_be_to_cpu32 (apart.heads)
		  * grub_be_to_cpu32 (apart.block_per_track));

      part.offset = (grub_off_t) next * 512;
      part.number = partno;
      part.index = 0;
      part.partmap = &grub_amiga_partition_map;

      if (hook (disk, &part, closure))
	return grub_errno;

      next = grub_be_to_cpu32 (apart.next);
      partno++;
    }

  return 0;
}


/* Partition map type.  */
struct grub_partition_map grub_amiga_partition_map =
  {
    .name = "amiga",
    .iterate = amiga_partition_map_iterate,
  };

GRUB_MOD_INIT(part_amiga)
{
  grub_partition_map_register (&grub_amiga_partition_map);
}

GRUB_MOD_FINI(part_amiga)
{
  grub_partition_map_unregister (&grub_amiga_partition_map);
}
