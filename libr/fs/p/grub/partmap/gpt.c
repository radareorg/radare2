/* gpt.c - Read GUID Partition Tables (GPT).  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2006,2007,2008  Free Software Foundation, Inc.
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
#include <grub/msdos_partition.h>
#include <grub/gpt_partition.h>

static grub_uint8_t grub_gpt_magic[8] =
  {
    0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54
  };

static const grub_gpt_part_type_t grub_gpt_partition_type_empty = GRUB_GPT_PARTITION_TYPE_EMPTY;

#ifdef GRUB_UTIL
static const grub_gpt_part_type_t grub_gpt_partition_type_bios_boot = GRUB_GPT_PARTITION_TYPE_BIOS_BOOT;
#endif

/* 512 << 7 = 65536 byte sectors.  */
#define MAX_SECTOR_LOG 7

struct grub_partition_map grub_gpt_partition_map;



static grub_err_t
gpt_partition_map_iterate (grub_disk_t disk,
			   int (*hook) (grub_disk_t disk,
					const grub_partition_t partition))
{
  struct grub_partition part;
  struct grub_gpt_header gpt;
  struct grub_gpt_partentry entry;
  struct grub_msdos_partition_mbr mbr;
  grub_uint64_t entries;
  unsigned int i;
  int last_offset = 0;
  int sector_log = 0;

  /* Read the protective MBR.  */
  if (grub_disk_read (disk, 0, 0, sizeof (mbr), &mbr))
    return grub_errno;

  /* Check if it is valid.  */
  if (mbr.signature != grub_cpu_to_le16 (GRUB_PC_PARTITION_SIGNATURE))
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no signature");

  /* Make sure the MBR is a protective MBR and not a normal MBR.  */
  if (mbr.entries[0].type != GRUB_PC_PARTITION_TYPE_GPT_DISK)
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no GPT partition map found");

  /* Read the GPT header.  */
  for (sector_log = 0; sector_log < MAX_SECTOR_LOG; sector_log++)
    {
      if (grub_disk_read (disk, 1 << sector_log, 0, sizeof (gpt), &gpt))
	return grub_errno;

      if (grub_memcmp (gpt.magic, grub_gpt_magic, sizeof (grub_gpt_magic)) == 0)
	break;
    }
  if (sector_log == MAX_SECTOR_LOG)
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no valid GPT header");

  grub_dprintf ("gpt", "Read a valid GPT header\n");

  entries = grub_le_to_cpu64 (gpt.partitions) << sector_log;
  for (i = 0; i < grub_le_to_cpu32 (gpt.maxpart); i++)
    {
      if (grub_disk_read (disk, entries, last_offset,
			  sizeof (entry), &entry))
	return grub_errno;

      if (grub_memcmp (&grub_gpt_partition_type_empty, &entry.type,
		       sizeof (grub_gpt_partition_type_empty)))
	{
	  /* Calculate the first block and the size of the partition.  */
	  part.start = grub_le_to_cpu64 (entry.start) << sector_log;
	  part.len = (grub_le_to_cpu64 (entry.end)
		      - grub_le_to_cpu64 (entry.start) + 1)  << sector_log;
	  part.offset = entries;
	  part.number = i;
	  part.index = last_offset;
	  part.partmap = &grub_gpt_partition_map;
	  part.parent = disk->partition;

	  grub_dprintf ("gpt", "GPT entry %d: start=%lld, length=%lld\n", i,
			(unsigned long long) part.start,
			(unsigned long long) part.len);

	  if (hook (disk, &part))
	    return grub_errno;
	}

      last_offset += grub_le_to_cpu32 (gpt.partentry_size);
      if (last_offset == GRUB_DISK_SECTOR_SIZE)
	{
	  last_offset = 0;
	  entries++;
	}
    }

  return GRUB_ERR_NONE;
}

#ifdef GRUB_UTIL
static grub_err_t
gpt_partition_map_embed (struct grub_disk *disk, unsigned int *nsectors,
			 grub_embed_type_t embed_type,
			 grub_disk_addr_t **sectors)
{
  grub_disk_addr_t start = 0, len = 0;
  unsigned i;
  grub_err_t err;

  auto int NESTED_FUNC_ATTR find_usable_region (grub_disk_t disk,
						const grub_partition_t p);
  int NESTED_FUNC_ATTR find_usable_region (grub_disk_t disk __attribute__ ((unused)),
					   const grub_partition_t p)
  {
    struct grub_gpt_partentry gptdata;

    disk->partition = p->parent;
    if (grub_disk_read (disk, p->offset, p->index,
			sizeof (gptdata), &gptdata))
      return 0;

    /* If there's an embed region, it is in a dedicated partition.  */
    if (! grub_memcmp (&gptdata.type, &grub_gpt_partition_type_bios_boot, 16))
      {
	start = p->start;
	len = p->len;
	return 1;
      }

      return 0;
    }

  if (embed_type != GRUB_EMBED_PCBIOS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "GPT curently supports only PC-BIOS embedding");

  err = gpt_partition_map_iterate (disk, find_usable_region);
  if (err)
    return err;

  if (len == 0)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
		       "This GPT partition label has no BIOS Boot Partition;"
		       " embedding won't be possible!");

  if (len < *nsectors)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       "Your BIOS Boot Partition is too small;"
		       " embedding won't be possible!");

  *nsectors = len;
  *sectors = grub_malloc (*nsectors * sizeof (**sectors));
  if (!*sectors)
    return grub_errno;
  for (i = 0; i < *nsectors; i++)
    (*sectors)[i] = start + i;

  return GRUB_ERR_NONE;
}
#endif


/* Partition map type.  */
struct grub_partition_map grub_gpt_partition_map = {
    .name = "gpt",
    .iterate = gpt_partition_map_iterate,
#ifdef GRUB_UTIL
    .embed = gpt_partition_map_embed
#endif
};
