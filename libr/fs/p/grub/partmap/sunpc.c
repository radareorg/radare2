/* sunpc.c - Read SUN PC style partition tables.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2006,2007,2009  Free Software Foundation, Inc.
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

#include <grub/partition.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/symbol.h>
#include <grub/types.h>
#include <grub/err.h>

#define GRUB_PARTMAP_SUN_PC_MAGIC 0xDABE
#define GRUB_PARTMAP_SUN_PC_MAX_PARTS 16
#define GRUB_PARTMAP_SUN_PC_WHOLE_DISK_ID 0x05

struct grub_sun_pc_partition_descriptor
{
  grub_uint16_t id;
  grub_uint16_t unused;
  grub_uint32_t start_sector;
  grub_uint32_t num_sectors;
} __attribute__ ((packed));

struct grub_sun_pc_block
{
  grub_uint8_t unused[72];
  struct grub_sun_pc_partition_descriptor partitions[GRUB_PARTMAP_SUN_PC_MAX_PARTS];
  grub_uint8_t unused2[244];
  grub_uint16_t  magic;         /* Magic number.  */
  grub_uint16_t  csum;          /* Label xor'd checksum.  */
} __attribute__ ((packed));

struct grub_partition_map grub_sun_pc_partition_map;

/* Verify checksum (true=ok).  */
static int
grub_sun_is_valid (struct grub_sun_pc_block *label)
{
  grub_uint16_t *pos;
  grub_uint16_t sum = 0;

  for (pos = (grub_uint16_t *) label;
       pos < (grub_uint16_t *) (label + 1);
       pos++)
    sum ^= *pos;

  return ! sum;
}

static grub_err_t
sun_pc_partition_map_iterate (grub_disk_t disk,
			      int (*hook) (grub_disk_t disk,
					   const grub_partition_t partition,
					   void *closure),
			      void *closure)
{
  grub_partition_t p;
  struct grub_sun_pc_block block;
  int partnum;
  grub_err_t err;

  p = (grub_partition_t) grub_zalloc (sizeof (struct grub_partition));
  if (! p)
    return grub_errno;

  p->partmap = &grub_sun_pc_partition_map;
  err = grub_disk_read (disk, 1, 0, sizeof (struct grub_sun_pc_block), &block);
  if (err)
    {
      grub_free (p);
      return err;
    }

  if (GRUB_PARTMAP_SUN_PC_MAGIC != grub_le_to_cpu16 (block.magic))
    {
      grub_free (p);
      return grub_error (GRUB_ERR_BAD_PART_TABLE,
			 "not a sun_pc partition table");
    }

  if (! grub_sun_is_valid (&block))
    {
      grub_free (p);
      return grub_error (GRUB_ERR_BAD_PART_TABLE, "invalid checksum");
    }

  /* Maybe another error value would be better, because partition
     table _is_ recognized but invalid.  */
  for (partnum = 0; partnum < GRUB_PARTMAP_SUN_PC_MAX_PARTS; partnum++)
    {
      struct grub_sun_pc_partition_descriptor *desc;

      if (block.partitions[partnum].id == 0
	  || block.partitions[partnum].id == GRUB_PARTMAP_SUN_PC_WHOLE_DISK_ID)
	continue;

      desc = &block.partitions[partnum];
      p->start = grub_le_to_cpu32 (desc->start_sector);
      p->len = grub_le_to_cpu32 (desc->num_sectors);
      p->number = partnum;
      if (p->len)
	{
	  if (hook (disk, p, closure))
	    partnum = GRUB_PARTMAP_SUN_PC_MAX_PARTS;
	}
    }

  grub_free (p);

  return grub_errno;
}

/* Partition map type.  */
struct grub_partition_map grub_sun_pc_partition_map =
  {
    .name = "sunpc",
    .iterate = sun_pc_partition_map_iterate,
  };

GRUB_MOD_INIT(part_sunpc)
{
  grub_partition_map_register (&grub_sun_pc_partition_map);
}

GRUB_MOD_FINI(part_sunpc)
{
  grub_partition_map_unregister (&grub_sun_pc_partition_map);
}

