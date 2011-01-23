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
#include <grub/msdos_partition.h>

#ifdef GRUB_UTIL
#include <grub/util/misc.h>
#endif

struct grub_partition_map grub_bsdlabel_partition_map;
struct grub_partition_map grub_netbsdlabel_partition_map;
struct grub_partition_map grub_openbsdlabel_partition_map;



static grub_err_t
iterate_real (grub_disk_t disk, grub_disk_addr_t sector, int freebsd,
	      struct grub_partition_map *pmap,
	      int (*hook) (grub_disk_t disk,
			   const grub_partition_t partition))
{
  struct grub_partition_bsd_disk_label label;
  struct grub_partition p;
  grub_disk_addr_t delta = 0;
  grub_disk_addr_t pos;

  /* Read the BSD label.  */
  if (grub_disk_read (disk, sector, 0, sizeof (label), &label))
    return grub_errno;

  /* Check if it is valid.  */
  if (label.magic != grub_cpu_to_le32 (GRUB_PC_PARTITION_BSD_LABEL_MAGIC))
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no signature");

  /* A kludge to determine a base of be.offset.  */
  if (GRUB_PC_PARTITION_BSD_LABEL_WHOLE_DISK_PARTITION
      < grub_cpu_to_le16 (label.num_partitions) && freebsd)
    {
      struct grub_partition_bsd_entry whole_disk_be;

      pos = sizeof (label) + sector * GRUB_DISK_SECTOR_SIZE
	+ sizeof (struct grub_partition_bsd_entry)
	* GRUB_PC_PARTITION_BSD_LABEL_WHOLE_DISK_PARTITION;

      if (grub_disk_read (disk, pos / GRUB_DISK_SECTOR_SIZE,
			  pos % GRUB_DISK_SECTOR_SIZE, sizeof (whole_disk_be),
			  &whole_disk_be))
	return grub_errno;

      delta = grub_le_to_cpu32 (whole_disk_be.offset);
    }

  pos = sizeof (label) + sector * GRUB_DISK_SECTOR_SIZE;

  for (p.number = 0;
       p.number < grub_cpu_to_le16 (label.num_partitions);
       p.number++, pos += sizeof (struct grub_partition_bsd_entry))
    {
      struct grub_partition_bsd_entry be;

      if (p.number == GRUB_PC_PARTITION_BSD_LABEL_WHOLE_DISK_PARTITION)
	continue;

      p.offset = pos / GRUB_DISK_SECTOR_SIZE;
      p.index = pos % GRUB_DISK_SECTOR_SIZE;

      if (grub_disk_read (disk, p.offset, p.index, sizeof (be),  &be))
	return grub_errno;

      p.start = grub_le_to_cpu32 (be.offset);
      p.len = grub_le_to_cpu32 (be.size);
      p.partmap = pmap;

      if (p.len == 0)
	continue;

      if (p.start < delta)
	{
#ifdef GRUB_UTIL
	  char *partname;
	  /* disk->partition != NULL as 0 < delta */
	  partname = grub_partition_get_name (disk->partition);
	  fprintf (stderr, "Discarding improperly nested partition (%s,%s,%s%d)",
			  disk->name, partname, p.partmap->name, p.number + 1);
	  grub_free (partname);
#endif
	  continue;
	}

      p.start -= delta;

      if (hook (disk, &p))
	return grub_errno;
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
bsdlabel_partition_map_iterate (grub_disk_t disk,
				int (*hook) (grub_disk_t disk,
					     const grub_partition_t partition))
{

  if (disk->partition && grub_strcmp (disk->partition->partmap->name, "msdos")
      == 0 && disk->partition->msdostype == GRUB_PC_PARTITION_TYPE_FREEBSD)
    return iterate_real (disk, GRUB_PC_PARTITION_BSD_LABEL_SECTOR, 1,
			 &grub_bsdlabel_partition_map, hook);

  if (disk->partition 
      && (grub_strcmp (disk->partition->partmap->name, "msdos") == 0
	  || disk->partition->partmap == &grub_bsdlabel_partition_map
	  || disk->partition->partmap == &grub_netbsdlabel_partition_map
	  || disk->partition->partmap == &grub_openbsdlabel_partition_map))
      return grub_error (GRUB_ERR_BAD_PART_TABLE, "no embedding supported");

  return iterate_real (disk, GRUB_PC_PARTITION_BSD_LABEL_SECTOR, 0, 
		       &grub_bsdlabel_partition_map, hook);
}

/* This is a total breakage. Even when net-/openbsd label is inside partition
   it actually describes the whole disk.
 */
static grub_err_t
netopenbsdlabel_partition_map_iterate (grub_disk_t disk, grub_uint8_t type,
				       struct grub_partition_map *pmap,
				       int (*hook) (grub_disk_t disk,
						    const grub_partition_t partition))
{
  int count = 0;

  auto int check_msdos (grub_disk_t dsk,
			const grub_partition_t partition);

  int check_msdos (grub_disk_t dsk,
		   const grub_partition_t partition)
  {
    grub_err_t err;

    if (partition->msdostype != type)
      return 0;

    err = iterate_real (dsk, partition->start
			+ GRUB_PC_PARTITION_BSD_LABEL_SECTOR, 0, pmap, hook);
    if (err == GRUB_ERR_NONE)
      {
	count++;
	return 1;
      }
    if (err == GRUB_ERR_BAD_PART_TABLE)
      {
	grub_errno = GRUB_ERR_NONE;
	return 0;
      }
    grub_print_error ();
    return 0;
  }

  if (disk->partition && grub_strcmp (disk->partition->partmap->name, "msdos")
      == 0)
    return grub_error (GRUB_ERR_BAD_PART_TABLE, "no embedding supported");

  {
    grub_err_t err;
    err = grub_partition_msdos_iterate (disk, check_msdos);

    if (err)
      return err;
    if (!count)
      return grub_error (GRUB_ERR_BAD_PART_TABLE, "no bsdlabel found");
  }
  return GRUB_ERR_NONE;
}

static grub_err_t
netbsdlabel_partition_map_iterate (grub_disk_t disk,
				   int (*hook) (grub_disk_t disk,
						const grub_partition_t partition))
{
  return netopenbsdlabel_partition_map_iterate (disk,
						GRUB_PC_PARTITION_TYPE_NETBSD,
						&grub_netbsdlabel_partition_map,
						hook);
}

static grub_err_t
openbsdlabel_partition_map_iterate (grub_disk_t disk,
				   int (*hook) (grub_disk_t disk,
						const grub_partition_t partition))
{
  return netopenbsdlabel_partition_map_iterate (disk,
						GRUB_PC_PARTITION_TYPE_OPENBSD,
						&grub_openbsdlabel_partition_map,
						hook);
}



struct grub_partition_map grub_bsdlabel_partition_map = {
    .name = "bsd",
    .iterate = bsdlabel_partition_map_iterate,
};

struct grub_partition_map grub_openbsdlabel_partition_map = {
    .name = "openbsd",
    .iterate = openbsdlabel_partition_map_iterate,
};

struct grub_partition_map grub_netbsdlabel_partition_map = {
    .name = "netbsd",
    .iterate = netbsdlabel_partition_map_iterate,
};
