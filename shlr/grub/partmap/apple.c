/* apple.c - Read macintosh partition tables.  */
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

#include <grub/disk.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/partition.h>

#define GRUB_APPLE_HEADER_MAGIC	0x4552
#define GRUB_APPLE_PART_MAGIC	0x504D

struct grub_apple_header
{
  /* The magic number to identify the partition map, it should have
     the value `0x4552'.  */
  grub_uint16_t magic;
  grub_uint16_t blocksize;
};

struct grub_apple_part
{
  /* The magic number to identify this as a partition, it should have
     the value `0x504D'.  */
  grub_uint16_t magic;

  /* Reserved.  */
  grub_uint16_t reserved;

  /* The size of the partition map in blocks.  */
  grub_uint32_t partmap_size;

  /* The first physical block of the partition.  */
  grub_uint32_t first_phys_block;

  /* The amount of blocks.  */
  grub_uint32_t blockcnt;

  /* The partition name.  */
  char partname[32];

  /* The partition type.  */
  char parttype[32];

  /* The first datablock of the partition.  */
  grub_uint32_t datablocks_first;

  /* The amount datablocks.  */
  grub_uint32_t datablocks_count;

  /* The status of the partition. (???)  */
  grub_uint32_t status;

  /* The first block on which the bootcode can be found.  */
  grub_uint32_t bootcode_pos;

  /* The size of the bootcode in bytes.  */
  grub_uint32_t bootcode_size;

  /* The load address of the bootcode.  */
  grub_uint32_t bootcode_loadaddr;

  /* Reserved.  */
  grub_uint32_t reserved2;

  /* The entry point of the bootcode.  */
  grub_uint32_t bootcode_entrypoint;

  /* Reserved.  */
  grub_uint32_t reserved3;

  /* A checksum of the bootcode.  */
  grub_uint32_t bootcode_checksum;

  /* The processor type.  */
  char processor[16];

  /* Padding.  */
  grub_uint16_t pad[187];
};

struct grub_partition_map grub_apple_partition_map;


static grub_err_t
apple_partition_map_iterate (grub_disk_t disk,
			     int (*hook) (grub_disk_t disk,
					  const grub_partition_t partition,
					  void *closure),
			     void *closure)
{
  struct grub_partition part;
  struct grub_apple_header aheader;
  struct grub_apple_part apart;
  int partno = 0, partnum = 0;
  unsigned pos;

  part.partmap = &grub_apple_partition_map;

  if (grub_disk_read (disk, 0, 0, sizeof (aheader), &aheader))
    return grub_errno;

  if (grub_be_to_cpu16 (aheader.magic) != GRUB_APPLE_HEADER_MAGIC)
    {
      grub_dprintf ("partition",
		    "bad magic (found 0x%x; wanted 0x%x\n",
		    grub_be_to_cpu16 (aheader.magic),
		    GRUB_APPLE_HEADER_MAGIC);
      goto fail;
    }

  pos = grub_be_to_cpu16 (aheader.blocksize);

  do
    {
      part.offset = pos / GRUB_DISK_SECTOR_SIZE;
      part.index = pos % GRUB_DISK_SECTOR_SIZE;

      if (grub_disk_read (disk, part.offset, part.index,
			  sizeof (struct grub_apple_part),  &apart))
	return grub_errno;

      if (grub_be_to_cpu16 (apart.magic) != GRUB_APPLE_PART_MAGIC)
	{
	  grub_dprintf ("partition",
			"partition %d: bad magic (found 0x%x; wanted 0x%x\n",
			partno, grub_be_to_cpu16 (apart.magic),
			GRUB_APPLE_PART_MAGIC);
	  break;
	}

      if (partnum == 0)
	partnum = grub_be_to_cpu32 (apart.partmap_size);

      part.start = ((grub_disk_addr_t) grub_be_to_cpu32 (apart.first_phys_block)
		    * grub_be_to_cpu16 (aheader.blocksize))
	/ GRUB_DISK_SECTOR_SIZE;
      part.len = ((grub_disk_addr_t) grub_be_to_cpu32 (apart.blockcnt)
		  * grub_be_to_cpu16 (aheader.blocksize))
	/ GRUB_DISK_SECTOR_SIZE;
      part.offset = pos;
      part.index = partno;
      part.number = partno;

      grub_dprintf ("partition",
		    "partition %d: name %s, type %s, start 0x%x, len 0x%x\n",
		    partno, apart.partname, apart.parttype,
		    grub_be_to_cpu32 (apart.first_phys_block),
		    grub_be_to_cpu32 (apart.blockcnt));

      if (hook (disk, &part, closure))
	return grub_errno;

      pos += grub_be_to_cpu16 (aheader.blocksize);
      partno++;
    }
  while (partno < partnum);

  if (partno != 0)
    return 0;

 fail:
  return grub_error (GRUB_ERR_BAD_PART_TABLE,
		     "Apple partition map not found");
}


/* Partition map type.  */
struct grub_partition_map grub_apple_partition_map =
  {
    .name = "apple",
    .iterate = apple_partition_map_iterate,
  };

GRUB_MOD_INIT(part_apple)
{
  grub_partition_map_register (&grub_apple_partition_map);
}

GRUB_MOD_FINI(part_apple)
{
  grub_partition_map_unregister (&grub_apple_partition_map);
}

