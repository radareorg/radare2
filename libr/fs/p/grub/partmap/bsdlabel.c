/* bsdlabel.c - Read BSD style partition tables.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2004,2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/bsdlabel.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>

struct grub_partition_map grub_bsdlabel_partition_map;


static grub_err_t
bsdlabel_partition_map_iterate (grub_disk_t disk,
				int (*hook) (grub_disk_t disk,
					     const grub_partition_t partition,
					     void *closure),
				void *closure)
{
  struct grub_partition_bsd_disk_label label;
  struct grub_partition p;
  grub_disk_addr_t delta = 0;
  unsigned pos;

  /* BSDLabel offsets are absolute even when it's embed inside partition.  */
  delta = grub_partition_get_start (disk->partition);

  /* Read the BSD label.  */
  if (grub_disk_read (disk, GRUB_PC_PARTITION_BSD_LABEL_SECTOR,
		      0, sizeof (label), &label))
    return grub_errno;

  /* Check if it is valid.  */
  if (label.magic != grub_cpu_to_le32 (GRUB_PC_PARTITION_BSD_LABEL_MAGIC))
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no signature");

  pos = sizeof (label) + GRUB_PC_PARTITION_BSD_LABEL_SECTOR
    * GRUB_DISK_SECTOR_SIZE;

  for (p.number = 0;
       p.number < grub_cpu_to_le16 (label.num_partitions);
       p.number++)
    {
      struct grub_partition_bsd_entry be;

      p.offset = pos / GRUB_DISK_SECTOR_SIZE;
      p.index = pos % GRUB_DISK_SECTOR_SIZE;

      if (grub_disk_read (disk, p.offset, p.index, sizeof (be),  &be))
	return grub_errno;

      p.start = grub_le_to_cpu32 (be.offset) - delta;
      p.len = grub_le_to_cpu32 (be.size);
      p.partmap = &grub_bsdlabel_partition_map;

      if (be.fs_type != GRUB_PC_PARTITION_BSD_TYPE_UNUSED)
	if (hook (disk, &p, closure))
	  return grub_errno;

      pos += sizeof (struct grub_partition_bsd_entry);
    }

  return GRUB_ERR_NONE;
}


/* Partition map type.  */
struct grub_partition_map grub_bsdlabel_partition_map =
  {
    .name = "bsd",
    .iterate = bsdlabel_partition_map_iterate,
  };

GRUB_MOD_INIT(part_bsd)
{
  grub_partition_map_register (&grub_bsdlabel_partition_map);
}

GRUB_MOD_FINI(part_bsd)
{
  grub_partition_map_unregister (&grub_bsdlabel_partition_map);
}
