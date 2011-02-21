/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2004,2006,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_PART_HEADER
#define GRUB_PART_HEADER	1

#include <grub/dl.h>
#include <grub/list.h>

struct grub_disk;

typedef struct grub_partition *grub_partition_t;

/* Partition map type.  */
struct grub_partition_map
{
  /* The next partition map type.  */
  struct grub_partition_map *next;

  /* The name of the partition map type.  */
  const char *name;

  /* Call HOOK with each partition, until HOOK returns non-zero.  */
  grub_err_t (*iterate) (struct grub_disk *disk,
			 int (*hook) (struct grub_disk *disk,
				      const grub_partition_t partition,
				      void *closure),
			 void *closure);
};
typedef struct grub_partition_map *grub_partition_map_t;

/* Partition description.  */
struct grub_partition
{
  /* The partition number.  */
  int number;

  /* The start sector.  */
  grub_disk_addr_t start;

  /* The length in sector units.  */
  grub_uint64_t len;

  /* The offset of the partition table.  */
  grub_disk_addr_t offset;

  /* The index of this partition in the partition table.  */
  int index;

  /* Parent partition map.  */
  struct grub_partition *parent;

  /* The type partition map.  */
  grub_partition_map_t partmap;

  /* The type of partition when it's on MSDOS.
   * Used for embedding detection.  */
  grub_uint8_t msdostype;
};

grub_partition_t grub_partition_probe (struct grub_disk *disk,
				       const char *str);
int grub_partition_iterate (struct grub_disk *disk,
			    int (*hook) (struct grub_disk *disk,
					 const grub_partition_t partition,
					 void *closure),
			    void *closure);
char * grub_partition_get_name (const grub_partition_t partition);


extern grub_partition_map_t grub_partition_map_list;

static inline void
grub_partition_map_register (grub_partition_map_t partmap)
{
  grub_list_push (GRUB_AS_LIST_P (&grub_partition_map_list),
		  GRUB_AS_LIST (partmap));
  GRUB_MODATTR ("partmap", "");
}

static inline void
grub_partition_map_unregister (grub_partition_map_t partmap)
{
  grub_list_remove (GRUB_AS_LIST_P (&grub_partition_map_list),
		    GRUB_AS_LIST (partmap));
}

#define FOR_PARTITION_MAPS(var) for (var = grub_partition_map_list; var; var = var->next)


static inline grub_disk_addr_t
grub_partition_get_start (const grub_partition_t p)
{
  grub_partition_t part;
  grub_uint64_t part_start = 0;

  for (part = p; part; part = part->parent)
    part_start += part->start;

  return part_start;
}

static inline grub_uint64_t
grub_partition_get_len (const grub_partition_t p)
{
  return p->len;
}

#endif /* ! GRUB_PART_HEADER */
