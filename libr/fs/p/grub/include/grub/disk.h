/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_DISK_HEADER
#define GRUB_DISK_HEADER	1

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/device.h>

/* These are used to set a device id. When you add a new disk device,
   you must define a new id for it here.  */
enum grub_disk_dev_id
  {
    GRUB_DISK_DEVICE_BIOSDISK_ID,
    GRUB_DISK_DEVICE_OFDISK_ID,
    GRUB_DISK_DEVICE_LOOPBACK_ID,
    GRUB_DISK_DEVICE_EFIDISK_ID,
    GRUB_DISK_DEVICE_RAID_ID,
    GRUB_DISK_DEVICE_LVM_ID,
    GRUB_DISK_DEVICE_HOST_ID,
    GRUB_DISK_DEVICE_ATA_ID,
    GRUB_DISK_DEVICE_MEMDISK_ID,
    GRUB_DISK_DEVICE_NAND_ID,
    GRUB_DISK_DEVICE_UUID_ID,
    GRUB_DISK_DEVICE_PXE_ID,
    GRUB_DISK_DEVICE_SCSI_ID,
    GRUB_DISK_DEVICE_FILE_ID,
    GRUB_DISK_DEVICE_LUKS_ID,
    GRUB_DISK_DEVICE_USB_ID,
    GRUB_DISK_DEVICE_MAP_ID,
  };

struct grub_disk;
#ifdef GRUB_UTIL
struct grub_disk_memberlist;
#endif

/* Disk device.  */
struct grub_disk_dev
{
  /* The device name.  */
  const char *name;

  /* The device id used by the cache manager.  */
  enum grub_disk_dev_id id;

  /* Call HOOK with each device name, until HOOK returns non-zero.  */
  int (*iterate) (int (*hook) (const char *name, void *closure),
		  void *closure);

  /* Open the device named NAME, and set up DISK.  */
  grub_err_t (*open) (const char *name, struct grub_disk *disk);

  /* Close the disk DISK.  */
  void (*close) (struct grub_disk *disk);

  /* Read SIZE sectors from the sector SECTOR of the disk DISK into BUF.  */
  grub_err_t (*read) (struct grub_disk *disk, grub_disk_addr_t sector,
		      grub_size_t size, char *buf);

  /* Write SIZE sectors from BUF into the sector SECTOR of the disk DISK.  */
  grub_err_t (*write) (struct grub_disk *disk, grub_disk_addr_t sector,
		       grub_size_t size, const char *buf);

#ifdef GRUB_UTIL
  struct grub_disk_memberlist *(*memberlist) (struct grub_disk *disk);
#endif

  /* The next disk device.  */
  struct grub_disk_dev *next;
};
typedef struct grub_disk_dev *grub_disk_dev_t;

struct grub_partition;

/* Disk.  */
struct grub_disk
{
  /* The disk name.  */
  const char *name;

  /* The underlying disk device.  */
  grub_disk_dev_t dev;

  /* The total number of sectors.  */
  grub_uint64_t total_sectors;

  /* If partitions can be stored.  */
  int has_partitions;

  /* The id used by the disk cache manager.  */
  unsigned long id;

  /* The partition information. This is machine-specific.  */
  struct grub_partition *partition;

  /* Called when a sector was read. OFFSET is between 0 and
     the sector size minus 1, and LENGTH is between 0 and the sector size.  */
  void (*read_hook) (grub_disk_addr_t sector,
		     unsigned offset, unsigned length, void* closure);
  void* closure;

  /* Device-specific data.  */
  void *data;
};
typedef struct grub_disk *grub_disk_t;

#ifdef GRUB_UTIL
struct grub_disk_memberlist
{
  grub_disk_t disk;
  struct grub_disk_memberlist *next;
};
typedef struct grub_disk_memberlist *grub_disk_memberlist_t;
#endif

/* The sector size.  */
#define GRUB_DISK_SECTOR_SIZE	0x200
#define GRUB_DISK_SECTOR_BITS	9

/* The maximum number of disk caches.  */
#define GRUB_DISK_CACHE_NUM	1021

/* The size of a disk cache in sector units.  */
#define GRUB_DISK_CACHE_SIZE	8
#define GRUB_DISK_CACHE_BITS	3

/* This is called from the memory manager.  */
void grub_disk_cache_invalidate_all (void);

void grub_disk_dev_register (grub_disk_dev_t dev);
void grub_disk_dev_unregister (grub_disk_dev_t dev);
int grub_disk_dev_iterate (int (*hook) (const char *name, void *closure),
			   void *closure);

grub_disk_t grub_disk_open (const char *name);
void grub_disk_close (grub_disk_t disk);
grub_err_t grub_disk_read (grub_disk_t disk,
			   grub_disk_addr_t sector,
			   grub_off_t offset,
			   grub_size_t size,
			   void *buf);
grub_err_t grub_disk_read_ex (grub_disk_t disk,
			      grub_disk_addr_t sector,
			      grub_off_t offset,
			      grub_size_t size,
			      void *buf,
			      int flags);
grub_err_t grub_disk_write (grub_disk_t disk,
			    grub_disk_addr_t sector,
			    grub_off_t offset,
			    grub_size_t size,
			    const void *buf);

grub_uint64_t grub_disk_get_size (grub_disk_t disk);

extern void (* grub_disk_firmware_fini) (void);
extern int grub_disk_firmware_is_tainted;

/* ATA pass through parameters and function.  */
struct grub_disk_ata_pass_through_parms
{
  grub_uint8_t taskfile[8];
  void * buffer;
  int size;
};

extern grub_err_t (* grub_disk_ata_pass_through) (grub_disk_t,
		   struct grub_disk_ata_pass_through_parms *);

#endif /* ! GRUB_DISK_HEADER */
