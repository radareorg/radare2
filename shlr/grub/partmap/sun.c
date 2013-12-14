/* sun.c - Read SUN style partition tables.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2006,2007  Free Software Foundation, Inc.
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

#define GRUB_PARTMAP_SUN_MAGIC 0xDABE
#define GRUB_PARTMAP_SUN_MAX_PARTS 8
#define GRUB_PARTMAP_SUN_WHOLE_DISK_ID 0x05

struct grub_sun_partition_info
{
  grub_uint8_t spare1;
  grub_uint8_t id;
  grub_uint8_t spare2;
  grub_uint8_t flags;
} __attribute__ ((packed));

struct grub_sun_partition_descriptor
{
  grub_uint32_t start_cylinder;
  grub_uint32_t num_sectors;
} __attribute__ ((packed));

struct grub_sun_block
{
  grub_uint8_t  info[128];      /* Informative text string.  */
  grub_uint8_t  spare0[14];
  struct grub_sun_partition_info infos[8];
  grub_uint8_t  spare1[246];    /* Boot information etc.  */
  grub_uint16_t  rspeed;        /* Disk rotational speed.  */
  grub_uint16_t  pcylcount;     /* Physical cylinder count.  */
  grub_uint16_t  sparecyl;      /* extra sects per cylinder.  */
  grub_uint8_t  spare2[4];      /* More magic...  */
  grub_uint16_t  ilfact;        /* Interleave factor.  */
  grub_uint16_t  ncyl;          /* Data cylinder count.  */
  grub_uint16_t  nacyl;         /* Alt. cylinder count.  */
  grub_uint16_t  ntrks;         /* Tracks per cylinder.  */
  grub_uint16_t  nsect;         /* Sectors per track.  */
  grub_uint8_t  spare3[4];      /* Even more magic...  */
  struct grub_sun_partition_descriptor partitions[8];
  grub_uint16_t  magic;         /* Magic number.  */
  grub_uint16_t  csum;          /* Label xor'd checksum.  */
} __attribute__ ((packed));

struct grub_partition_map grub_sun_partition_map;

/* Verify checksum (true=ok).  */
static int
grub_sun_is_valid (struct grub_sun_block *label)
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
sun_partition_map_iterate (grub_disk_t disk,
                           int (*hook) (grub_disk_t disk,
					const grub_partition_t partition,
					void *closure),
			   void *closure)
{
  grub_partition_t p;
  struct grub_sun_block block;
  int partnum;
  grub_err_t err;

  p = (grub_partition_t) grub_zalloc (sizeof (struct grub_partition));
  if (! p)
    return grub_errno;

  p->partmap = &grub_sun_partition_map;
  err = grub_disk_read (disk, 0, 0, sizeof (struct grub_sun_block),
			&block);
  if (err)
    {
      grub_free (p);
      return err;
    }

  if (GRUB_PARTMAP_SUN_MAGIC != grub_be_to_cpu16 (block.magic))
    {
      grub_free (p);
      return grub_error (GRUB_ERR_BAD_PART_TABLE, "not a sun partition table");
    }

  if (! grub_sun_is_valid (&block))
    {
      grub_free (p);
      return grub_error (GRUB_ERR_BAD_PART_TABLE, "invalid checksum");
    }

  /* Maybe another error value would be better, because partition
     table _is_ recognized but invalid.  */
  for (partnum = 0; partnum < GRUB_PARTMAP_SUN_MAX_PARTS; partnum++)
    {
      struct grub_sun_partition_descriptor *desc;

      if (block.infos[partnum].id == 0
	  || block.infos[partnum].id == GRUB_PARTMAP_SUN_WHOLE_DISK_ID)
	continue;

      desc = &block.partitions[partnum];
      p->start = ((grub_uint64_t) grub_be_to_cpu32 (desc->start_cylinder)
		  * grub_be_to_cpu16 (block.ntrks)
		  * grub_be_to_cpu16 (block.nsect));
      p->len = grub_be_to_cpu32 (desc->num_sectors);
      p->number = p->index = partnum;
      if (p->len)
	{
	  if (hook (disk, p, closure))
	    partnum = GRUB_PARTMAP_SUN_MAX_PARTS;
	}
    }

  grub_free (p);

  return grub_errno;
}

/* Partition map type.  */
struct grub_partition_map grub_sun_partition_map =
  {
    .name = "sun",
    .iterate = sun_partition_map_iterate,
  };

GRUB_MOD_INIT(part_sun)
{
  grub_partition_map_register (&grub_sun_partition_map);
}

GRUB_MOD_FINI(part_sun)
{
  grub_partition_map_unregister (&grub_sun_partition_map);
}

