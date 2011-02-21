/* acorn.c - Read Linux/ADFS partition tables.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007  Free Software Foundation, Inc.
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
#include <grub/acorn_filecore.h>

#define LINUX_NATIVE_MAGIC grub_cpu_to_le32 (0xdeafa1de)
#define LINUX_SWAP_MAGIC   grub_cpu_to_le32 (0xdeafab1e)
#define LINUX_MAP_ENTRIES  (512 / 12)

#define NONADFS_PARTITION_TYPE_LINUX 9
#define NONADFS_PARTITION_TYPE_MASK 15

struct grub_acorn_boot_block
{
  grub_uint8_t misc[0x1C0];
  struct grub_filecore_disc_record disc_record;
  grub_uint8_t flags;
  grub_uint16_t start_cylinder;
  grub_uint8_t checksum;
} __attribute__ ((packed, aligned));

struct linux_part
{
  grub_uint32_t magic;
  grub_uint32_t start;
  grub_uint32_t size;
};

struct grub_partition_map grub_acorn_partition_map;

static grub_err_t
acorn_partition_map_find (grub_disk_t disk, struct linux_part *m,
			  grub_disk_addr_t *sector)
{
  struct grub_acorn_boot_block boot;
  grub_err_t err;
  unsigned int checksum = 0;
  unsigned int heads;
  unsigned int sectors_per_cylinder;
  int i;

  err = grub_disk_read (disk, 0xC00 / GRUB_DISK_SECTOR_SIZE, 0,
			sizeof (struct grub_acorn_boot_block),
			&boot);
  if (err)
    return err;

  if ((boot.flags & NONADFS_PARTITION_TYPE_MASK) != NONADFS_PARTITION_TYPE_LINUX)
    goto fail;

  for (i = 0; i != 0x1ff; ++i)
    checksum = (checksum & 0xff) + (checksum >> 8) + boot.misc[i];

  if ((grub_uint8_t) checksum != boot.checksum)
    goto fail;

  heads = (boot.disc_record.heads
		    + ((boot.disc_record.lowsector >> 6) & 1));
  sectors_per_cylinder = boot.disc_record.secspertrack * heads;
  *sector = grub_le_to_cpu16 (boot.start_cylinder) * sectors_per_cylinder;

  return grub_disk_read (disk, *sector, 0,
			 sizeof (struct linux_part) * LINUX_MAP_ENTRIES,
			 m);

fail:
  return grub_error (GRUB_ERR_BAD_PART_TABLE,
		     "Linux/ADFS partition map not found");

}


static grub_err_t
acorn_partition_map_iterate (grub_disk_t disk,
			     int (*hook) (grub_disk_t disk,
					  const grub_partition_t partition,
					  void *closure),
			     void *closure)
{
  struct grub_partition part;
  struct linux_part map[LINUX_MAP_ENTRIES];
  int i;
  grub_disk_addr_t sector = 0;
  grub_err_t err;

  err = acorn_partition_map_find (disk, map, &sector);
  if (err)
    return err;

  part.partmap = &grub_acorn_partition_map;

  for (i = 0; i != LINUX_MAP_ENTRIES; ++i)
    {
      if (map[i].magic != LINUX_NATIVE_MAGIC
	  && map[i].magic != LINUX_SWAP_MAGIC)
	return GRUB_ERR_NONE;

      part.start = sector + map[i].start;
      part.len = map[i].size;
      part.offset = 6;
      part.number = part.index = i;

      if (hook (disk, &part, closure))
	return grub_errno;
    }

  return GRUB_ERR_NONE;
}



/* Partition map type.  */
struct grub_partition_map grub_acorn_partition_map =
{
  .name = "acorn",
  .iterate = acorn_partition_map_iterate,
};

GRUB_MOD_INIT(part_acorn)
{
  grub_partition_map_register (&grub_acorn_partition_map);
}

GRUB_MOD_FINI(part_acorn)
{
  grub_partition_map_unregister (&grub_acorn_partition_map);
}
