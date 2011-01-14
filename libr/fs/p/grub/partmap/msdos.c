/* pc.c - Read PC style partition tables.  */
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
#include <grub/msdos_partition.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>

struct grub_partition_map grub_msdos_partition_map;


grub_err_t
grub_partition_msdos_iterate (grub_disk_t disk,
			      int (*hook) (grub_disk_t disk,
					   const grub_partition_t partition))
{
  struct grub_partition p;
  struct grub_msdos_partition_mbr mbr;
  int labeln = 0;
  grub_disk_addr_t lastaddr;
  grub_disk_addr_t ext_offset;
  grub_disk_addr_t delta = 0;

  if (disk->partition && disk->partition->partmap == &grub_msdos_partition_map)
    {
      if (disk->partition->msdostype == GRUB_PC_PARTITION_TYPE_LINUX_MINIX)
	delta = disk->partition->start;
      else
	return grub_error (GRUB_ERR_BAD_PART_TABLE, "no embedding supported");
    }

  p.offset = 0;
  ext_offset = 0;
  p.number = -1;
  p.partmap = &grub_msdos_partition_map;

  /* Any value different than `p.offset' will satisfy the check during
     first loop.  */
  lastaddr = !p.offset;

  while (1)
    {
      int i;
      struct grub_msdos_partition_entry *e;

      /* Read the MBR.  */
      if (grub_disk_read (disk, p.offset, 0, sizeof (mbr), &mbr))
	goto finish;

      /* This is our loop-detection algorithm. It works the following way:
	 It saves last position which was a power of two. Then it compares the
	 saved value with a current one. This way it's guaranteed that the loop
	 will be broken by at most third walk.
       */
      if (labeln && lastaddr == p.offset)
	return grub_error (GRUB_ERR_BAD_PART_TABLE, "loop detected");

      labeln++;
      if ((labeln & (labeln - 1)) == 0)
	lastaddr = p.offset;

      /* Check if it is valid.  */
      if (mbr.signature != grub_cpu_to_le16 (GRUB_PC_PARTITION_SIGNATURE))
	return grub_error (GRUB_ERR_BAD_PART_TABLE, "no signature");

      for (i = 0; i < 4; i++)
	if (mbr.entries[i].flag & 0x7f)
	  return grub_error (GRUB_ERR_BAD_PART_TABLE, "bad boot flag");

      /* Analyze DOS partitions.  */
      for (p.index = 0; p.index < 4; p.index++)
	{
	  e = mbr.entries + p.index;

	  p.start = p.offset + grub_le_to_cpu32 (e->start) - delta;
	  p.len = grub_le_to_cpu32 (e->length);
	  p.msdostype = e->type;

	  grub_dprintf ("partition",
			"partition %d: flag 0x%x, type 0x%x, start 0x%llx, len 0x%llx\n",
			p.index, e->flag, e->type,
			(unsigned long long) p.start,
			(unsigned long long) p.len);

	  /* If this is a GPT partition, this MBR is just a dummy.  */
	  if (e->type == GRUB_PC_PARTITION_TYPE_GPT_DISK && p.index == 0)
	    return grub_error (GRUB_ERR_BAD_PART_TABLE, "dummy mbr");

	  /* If this partition is a normal one, call the hook.  */
	  if (! grub_msdos_partition_is_empty (e->type)
	      && ! grub_msdos_partition_is_extended (e->type))
	    {
	      p.number++;

	      if (hook (disk, &p))
		return grub_errno;
	    }
	  else if (p.number < 4)
	    /* If this partition is a logical one, shouldn't increase the
	       partition number.  */
	    p.number++;
	}

      /* Find an extended partition.  */
      for (i = 0; i < 4; i++)
	{
	  e = mbr.entries + i;

	  if (grub_msdos_partition_is_extended (e->type))
	    {
	      p.offset = ext_offset + grub_le_to_cpu32 (e->start);
	      if (! ext_offset)
		ext_offset = p.offset;

	      break;
	    }
	}

      /* If no extended partition, the end.  */
      if (i == 4)
	break;
    }

 finish:
  return grub_errno;
}

#ifdef GRUB_UTIL
static grub_err_t
pc_partition_map_embed (struct grub_disk *disk, unsigned int *nsectors,
			grub_embed_type_t embed_type,
			grub_disk_addr_t **sectors)
{
  grub_disk_addr_t end = ~0ULL;
  struct grub_msdos_partition_mbr mbr;
  int labeln = 0;
  /* Any value different than `p.offset' will satisfy the check during
     first loop.  */
  grub_disk_addr_t lastaddr = 1;
  grub_disk_addr_t ext_offset = 0;
  grub_disk_addr_t offset = 0;

  if (embed_type != GRUB_EMBED_PCBIOS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "PC-style partitions curently support "
		       "only PC-BIOS embedding");

  if (disk->partition)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       "Embedding on MSDOS subpartition isn't supported");

  while (1)
    {
      int i;
      struct grub_msdos_partition_entry *e;
      grub_err_t err;

      /* Read the MBR.  */
      err = grub_disk_read (disk, offset, 0, sizeof (mbr), &mbr);
      if (err)
	return err;

      /* This is our loop-detection algorithm. It works the following way:
	 It saves last position which was a power of two. Then it compares the
	 saved value with a current one. This way it's guaranteed that the loop
	 will be broken by at most third walk.
       */
      if (labeln && lastaddr == offset)
	return grub_error (GRUB_ERR_BAD_PART_TABLE, "loop detected");

      labeln++;
      if ((labeln & (labeln - 1)) == 0)
	lastaddr = offset;

      /* Check if it is valid.  */
      if (mbr.signature != grub_cpu_to_le16 (GRUB_PC_PARTITION_SIGNATURE))
	return grub_error (GRUB_ERR_BAD_PART_TABLE, "no signature");

      for (i = 0; i < 4; i++)
	if (mbr.entries[i].flag & 0x7f)
	  return grub_error (GRUB_ERR_BAD_PART_TABLE, "bad boot flag");

      /* Analyze DOS partitions.  */
      for (i = 0; i < 4; i++)
	{
	  e = mbr.entries + i;

	  if (!grub_msdos_partition_is_empty (e->type)
	      && end > offset + grub_le_to_cpu32 (e->start))
	    end = offset + grub_le_to_cpu32 (e->start);

	  /* If this is a GPT partition, this MBR is just a dummy.  */
	  if (e->type == GRUB_PC_PARTITION_TYPE_GPT_DISK && i == 0)
	    return grub_error (GRUB_ERR_BAD_PART_TABLE, "dummy mbr");
	}

      /* Find an extended partition.  */
      for (i = 0; i < 4; i++)
	{
	  e = mbr.entries + i;

	  if (grub_msdos_partition_is_extended (e->type))
	    {
	      offset = ext_offset + grub_le_to_cpu32 (e->start);
	      if (! ext_offset)
		ext_offset = offset;

	      break;
	    }
	}

      /* If no extended partition, the end.  */
      if (i == 4)
	break;
    }

  if (end >= *nsectors + 1)
    {
      int i;
      *nsectors = end - 1;
      *sectors = grub_malloc (*nsectors * sizeof (**sectors));
      if (!*sectors)
	return grub_errno;
      for (i = 0; i < *nsectors; i++)
	(*sectors)[i] = 1 + i;
      return GRUB_ERR_NONE;
    }

  if (end <= 1)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
		       "This msdos-style partition label has no "
		       "post-MBR gap; embedding won't be possible!");

  if (*nsectors > 62)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       "Your core.img is unusually large.  "
		       "It won't fit in the embedding area.");

  return grub_error (GRUB_ERR_OUT_OF_RANGE,
		     "Your embedding area is unusually small.  "
		     "core.img won't fit in it.");
}
#endif


/* Partition map type.  */
struct grub_partition_map grub_msdos_partition_map = {
    .name = "msdos",
    .iterate = grub_partition_msdos_iterate,
#ifdef GRUB_UTIL
    .embed = pc_partition_map_embed
#endif
};
