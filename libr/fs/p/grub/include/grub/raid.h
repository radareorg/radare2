/* raid.h - On disk structures for RAID. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2008  Free Software Foundation, Inc.
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

#ifndef GRUB_RAID_H
#define GRUB_RAID_H	1

#include <grub/types.h>

#define GRUB_RAID_MAX_DEVICES	32

#define GRUB_RAID_LAYOUT_LEFT_ASYMMETRIC	0
#define GRUB_RAID_LAYOUT_RIGHT_ASYMMETRIC	1
#define GRUB_RAID_LAYOUT_LEFT_SYMMETRIC		2
#define GRUB_RAID_LAYOUT_RIGHT_SYMMETRIC	3

#define GRUB_RAID_LAYOUT_RIGHT_MASK		1
#define GRUB_RAID_LAYOUT_SYMMETRIC_MASK		2

struct grub_raid_array
{
  int number;              /* The device number, taken from md_minor so we
			      are consistent with the device name in
			      Linux. */
  int level;               /* RAID levels, only 0, 1 or 5 at the moment. */
  int layout;              /* Layout for RAID 5/6.  */
  unsigned int total_devs; /* Total number of devices in the array. */
  grub_size_t chunk_size;  /* The size of a chunk, in 512 byte sectors. */
  grub_uint64_t disk_size; /* Size of an individual disk, in 512 byte
			      sectors. */
  grub_uint64_t disk_offset;
  int index;               /* Index of current device.  */
  int uuid_len;            /* The length of uuid.  */
  char *uuid;              /* The UUID of the device. */

  /* The following field is setup by the caller.  */
  char *name;              /* That will be "md<number>". */
  unsigned int nr_devs;    /* The number of devices we've found so far. */
  grub_disk_t device[GRUB_RAID_MAX_DEVICES];  /* Array of total_devs devices. */
  grub_uint64_t offset[GRUB_RAID_MAX_DEVICES];

  struct grub_raid_array *next;
};

struct grub_raid
{
  const char *name;

  grub_err_t (*detect) (grub_disk_t disk, struct grub_raid_array *array);

  struct grub_raid *next;
};
typedef struct grub_raid *grub_raid_t;

void grub_raid_register (grub_raid_t raid);
void grub_raid_unregister (grub_raid_t raid);

void grub_raid_block_xor (char *buf1, const char *buf2, int size);

typedef grub_err_t (*grub_raid5_recover_func_t) (struct grub_raid_array *array,
                                                 int disknr, char *buf,
                                                 grub_disk_addr_t sector,
                                                 int size);

typedef grub_err_t (*grub_raid6_recover_func_t) (struct grub_raid_array *array,
                                                 int disknr, int p, char *buf,
                                                 grub_disk_addr_t sector,
                                                 int size);

extern grub_raid5_recover_func_t grub_raid5_recover_func;
extern grub_raid6_recover_func_t grub_raid6_recover_func;

#endif /* ! GRUB_RAID_H */
