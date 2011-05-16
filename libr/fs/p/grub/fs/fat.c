/* fat.c - FAT filesystem */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000,2001,2002,2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#include <r_fs.h>
#include <grub/fs.h>
#include <grub/fshelp.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/charset.h>

#define GRUB_FAT_DIR_ENTRY_SIZE	32

#define GRUB_FAT_ATTR_READ_ONLY	0x01
#define GRUB_FAT_ATTR_HIDDEN	0x02
#define GRUB_FAT_ATTR_SYSTEM	0x04
#define GRUB_FAT_ATTR_VOLUME_ID	0x08
#define GRUB_FAT_ATTR_DIRECTORY	0x10
#define GRUB_FAT_ATTR_ARCHIVE	0x20

#define GRUB_FAT_MAXFILE	256

#define GRUB_FAT_ATTR_LONG_NAME	(GRUB_FAT_ATTR_READ_ONLY \
				 | GRUB_FAT_ATTR_HIDDEN \
				 | GRUB_FAT_ATTR_SYSTEM \
				 | GRUB_FAT_ATTR_VOLUME_ID)
#define GRUB_FAT_ATTR_VALID	(GRUB_FAT_ATTR_READ_ONLY \
				 | GRUB_FAT_ATTR_HIDDEN \
				 | GRUB_FAT_ATTR_SYSTEM \
				 | GRUB_FAT_ATTR_DIRECTORY \
				 | GRUB_FAT_ATTR_ARCHIVE \
				 | GRUB_FAT_ATTR_VOLUME_ID)

struct grub_fat_bpb
{
  grub_uint8_t jmp_boot[3];
  grub_uint8_t oem_name[8];
  grub_uint16_t bytes_per_sector;
  grub_uint8_t sectors_per_cluster;
  grub_uint16_t num_reserved_sectors;
  grub_uint8_t num_fats;
  grub_uint16_t num_root_entries;
  grub_uint16_t num_total_sectors_16;
  grub_uint8_t media;
  grub_uint16_t sectors_per_fat_16;
  grub_uint16_t sectors_per_track;
  grub_uint16_t num_heads;
  grub_uint32_t num_hidden_sectors;
  grub_uint32_t num_total_sectors_32;
  union
  {
    struct
    {
      grub_uint8_t num_ph_drive;
      grub_uint8_t reserved;
      grub_uint8_t boot_sig;
      grub_uint32_t num_serial;
      grub_uint8_t label[11];
      grub_uint8_t fstype[8];
    } __attribute__ ((packed)) fat12_or_fat16;
    struct
    {
      grub_uint32_t sectors_per_fat_32;
      grub_uint16_t extended_flags;
      grub_uint16_t fs_version;
      grub_uint32_t root_cluster;
      grub_uint16_t fs_info;
      grub_uint16_t backup_boot_sector;
      grub_uint8_t reserved[12];
      grub_uint8_t num_ph_drive;
      grub_uint8_t reserved1;
      grub_uint8_t boot_sig;
      grub_uint32_t num_serial;
      grub_uint8_t label[11];
      grub_uint8_t fstype[8];
    } __attribute__ ((packed)) fat32;
  } __attribute__ ((packed)) version_specific;
} __attribute__ ((packed));

struct grub_fat_dir_entry
{
  grub_uint8_t name[11];
  grub_uint8_t attr;
  grub_uint8_t nt_reserved;
  grub_uint8_t c_time_tenth;
  grub_uint16_t c_time;
  grub_uint16_t c_date;
  grub_uint16_t a_date;
  grub_uint16_t first_cluster_high;
  grub_uint16_t w_time;
  grub_uint16_t w_date;
  grub_uint16_t first_cluster_low;
  grub_uint32_t file_size;
} __attribute__ ((packed));

struct grub_fat_long_name_entry
{
  grub_uint8_t id;
  grub_uint16_t name1[5];
  grub_uint8_t attr;
  grub_uint8_t reserved;
  grub_uint8_t checksum;
  grub_uint16_t name2[6];
  grub_uint16_t first_cluster;
  grub_uint16_t name3[2];
} __attribute__ ((packed));

struct grub_fat_data
{
  int logical_sector_bits;
  grub_uint32_t num_sectors;

  grub_uint16_t fat_sector;
  grub_uint32_t sectors_per_fat;
  int fat_size;

  grub_uint32_t root_cluster;
  grub_uint32_t root_sector;
  grub_uint32_t num_root_sectors;

  int cluster_bits;
  grub_uint32_t cluster_eof_mark;
  grub_uint32_t cluster_sector;
  grub_uint32_t num_clusters;

  grub_uint8_t attr;
  grub_ssize_t file_size;
  grub_uint32_t file_cluster;
  grub_uint32_t cur_cluster_num;
  grub_uint32_t cur_cluster;

  grub_uint32_t uuid;
};

static grub_dl_t my_mod;

static int
fat_log2 (unsigned x)
{
  int i;

  if (x == 0)
    return -1;

  for (i = 0; (x & 1) == 0; i++)
    x >>= 1;

  if (x != 1)
    return -1;

  return i;
}

static struct grub_fat_data *
grub_fat_mount (grub_disk_t disk)
{
  struct grub_fat_bpb bpb;
  struct grub_fat_data *data = 0;
  grub_uint32_t first_fat, magic;

  if (! disk)
    goto fail;

  data = (struct grub_fat_data *) grub_malloc (sizeof (*data));
  if (! data)
    goto fail;

  /* Read the BPB.  */
  if (grub_disk_read (disk, 0, 0, sizeof (bpb), &bpb))
    goto fail;

  if (grub_strncmp((const char *) bpb.version_specific.fat12_or_fat16.fstype, "FAT12", 5)
      && grub_strncmp((const char *) bpb.version_specific.fat12_or_fat16.fstype, "FAT16", 5)
      && grub_strncmp((const char *) bpb.version_specific.fat32.fstype, "FAT32", 5))
    goto fail;

  /* Get the sizes of logical sectors and clusters.  */
  data->logical_sector_bits =
    fat_log2 (grub_le_to_cpu16 (bpb.bytes_per_sector));
  if (data->logical_sector_bits < GRUB_DISK_SECTOR_BITS)
    goto fail;
  data->logical_sector_bits -= GRUB_DISK_SECTOR_BITS;

  data->cluster_bits = fat_log2 (bpb.sectors_per_cluster);
  if (data->cluster_bits < 0)
    goto fail;
  data->cluster_bits += data->logical_sector_bits;

  /* Get information about FATs.  */
  data->fat_sector = (grub_le_to_cpu16 (bpb.num_reserved_sectors)
		      << data->logical_sector_bits);
  if (data->fat_sector == 0)
    goto fail;

  data->sectors_per_fat = ((bpb.sectors_per_fat_16
			    ? grub_le_to_cpu16 (bpb.sectors_per_fat_16)
			    : grub_le_to_cpu32 (bpb.version_specific.fat32.sectors_per_fat_32))
			   << data->logical_sector_bits);
  if (data->sectors_per_fat == 0)
    goto fail;

  /* Get the number of sectors in this volume.  */
  data->num_sectors = ((bpb.num_total_sectors_16
			? grub_le_to_cpu16 (bpb.num_total_sectors_16)
			: grub_le_to_cpu32 (bpb.num_total_sectors_32))
		       << data->logical_sector_bits);
  if (data->num_sectors == 0)
    goto fail;

  /* Get information about the root directory.  */
  if (bpb.num_fats == 0)
    goto fail;

  data->root_sector = data->fat_sector + bpb.num_fats * data->sectors_per_fat;
  data->num_root_sectors
    = ((((grub_uint32_t) grub_le_to_cpu16 (bpb.num_root_entries)
	 * GRUB_FAT_DIR_ENTRY_SIZE
	 + grub_le_to_cpu16 (bpb.bytes_per_sector) - 1)
	>> (data->logical_sector_bits + GRUB_DISK_SECTOR_BITS))
       << (data->logical_sector_bits));

  data->cluster_sector = data->root_sector + data->num_root_sectors;
  data->num_clusters = (((data->num_sectors - data->cluster_sector)
			 >> (data->cluster_bits + data->logical_sector_bits))
			+ 2);

  if (data->num_clusters <= 2)
    goto fail;

  if (! bpb.sectors_per_fat_16)
    {
      /* FAT32.  */
      grub_uint16_t flags = grub_le_to_cpu16 (bpb.version_specific.fat32.extended_flags);

      data->root_cluster = grub_le_to_cpu32 (bpb.version_specific.fat32.root_cluster);
      data->fat_size = 32;
      data->cluster_eof_mark = 0x0ffffff8;

      if (flags & 0x80)
	{
	  /* Get an active FAT.  */
	  unsigned active_fat = flags & 0xf;

	  if (active_fat > bpb.num_fats)
	    goto fail;

	  data->fat_sector += active_fat * data->sectors_per_fat;
	}

      if (bpb.num_root_entries != 0 || bpb.version_specific.fat32.fs_version != 0)
	goto fail;
    }
  else
    {
      /* FAT12 or FAT16.  */
      data->root_cluster = ~0U;

      if (data->num_clusters <= 4085 + 2)
	{
	  /* FAT12.  */
	  data->fat_size = 12;
	  data->cluster_eof_mark = 0x0ff8;
	}
      else
	{
	  /* FAT16.  */
	  data->fat_size = 16;
	  data->cluster_eof_mark = 0xfff8;
	}
    }

  /* More sanity checks.  */
  if (data->num_sectors <= data->fat_sector)
    goto fail;

  if (grub_disk_read (disk,
		      data->fat_sector,
		      0,
		      sizeof (first_fat),
		      &first_fat))
    goto fail;

  first_fat = grub_le_to_cpu32 (first_fat);

  if (data->fat_size == 32)
    {
      first_fat &= 0x0fffffff;
      magic = 0x0fffff00;
    }
  else if (data->fat_size == 16)
    {
      first_fat &= 0x0000ffff;
      magic = 0xff00;
    }
  else
    {
      first_fat &= 0x00000fff;
      magic = 0x0f00;
    }

  /* Serial number.  */
  if (bpb.sectors_per_fat_16)
    data->uuid = grub_le_to_cpu32 (bpb.version_specific.fat12_or_fat16.num_serial);
  else
    data->uuid = grub_le_to_cpu32 (bpb.version_specific.fat32.num_serial);

  /* Ignore the 3rd bit, because some BIOSes assigns 0xF0 to the media
     descriptor, even if it is a so-called superfloppy (e.g. an USB key).
     The check may be too strict for this kind of stupid BIOSes, as
     they overwrite the media descriptor.  */
  if ((first_fat | 0x8) != (magic | bpb.media | 0x8))
    goto fail;

  /* Start from the root directory.  */
  data->file_cluster = data->root_cluster;
  data->cur_cluster_num = ~0U;
  data->attr = GRUB_FAT_ATTR_DIRECTORY;
  return data;

 fail:

  grub_free (data);
  grub_error (GRUB_ERR_BAD_FS, "not a FAT filesystem");
  return 0;
}

static grub_ssize_t
grub_fat_read_data (grub_disk_t disk, struct grub_fat_data *data,
		    void (*read_hook) (grub_disk_addr_t sector,
				       unsigned offset, unsigned length,
				       void *closure),
		    void *closure, int flags,
		    grub_off_t offset, grub_size_t len, char *buf)
{
  grub_size_t size;
  grub_uint32_t logical_cluster;
  unsigned logical_cluster_bits;
  grub_ssize_t ret = 0;
  unsigned long sector;

  /* This is a special case. FAT12 and FAT16 doesn't have the root directory
     in clusters.  */
  if (data->file_cluster == ~0U)
    {
      size = (data->num_root_sectors << GRUB_DISK_SECTOR_BITS) - offset;
      if (size > len)
	size = len;

      if (grub_disk_read (disk, data->root_sector, offset, size, buf))
	return -1;

      return size;
    }

  /* Calculate the logical cluster number and offset.  */
  logical_cluster_bits = (data->cluster_bits
			  + data->logical_sector_bits
			  + GRUB_DISK_SECTOR_BITS);
  logical_cluster = offset >> logical_cluster_bits;
  offset &= (1 << logical_cluster_bits) - 1;

  if (logical_cluster < data->cur_cluster_num)
    {
      data->cur_cluster_num = 0;
      data->cur_cluster = data->file_cluster;
    }

  while (len)
    {
      while (logical_cluster > data->cur_cluster_num)
	{
	  /* Find next cluster.  */
	  grub_uint32_t next_cluster;
	  unsigned long fat_offset;

	  switch (data->fat_size)
	    {
	    case 32:
	      fat_offset = data->cur_cluster << 2;
	      break;
	    case 16:
	      fat_offset = data->cur_cluster << 1;
	      break;
	    default:
	      /* case 12: */
	      fat_offset = data->cur_cluster + (data->cur_cluster >> 1);
	      break;
	    }

	  /* Read the FAT.  */
	  if (grub_disk_read (disk, data->fat_sector, fat_offset,
			      (data->fat_size + 7) >> 3,
			      (char *) &next_cluster))
	    return -1;

	  next_cluster = grub_le_to_cpu32 (next_cluster);
	  switch (data->fat_size)
	    {
	    case 16:
	      next_cluster &= 0xFFFF;
	      break;
	    case 12:
	      if (data->cur_cluster & 1)
		next_cluster >>= 4;

	      next_cluster &= 0x0FFF;
	      break;
	    }

	  grub_dprintf ("fat", "fat_size=%d, next_cluster=%u\n",
			data->fat_size, next_cluster);

	  /* Check the end.  */
	  if (next_cluster >= data->cluster_eof_mark)
	    return ret;

	  if (next_cluster < 2 || next_cluster >= data->num_clusters)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "invalid cluster %u",
			  next_cluster);
	      return -1;
	    }

	  data->cur_cluster = next_cluster;
	  data->cur_cluster_num++;
	}

      /* Read the data here.  */
      sector = (data->cluster_sector
		+ ((data->cur_cluster - 2)
		   << (data->cluster_bits + data->logical_sector_bits)));
      size = (1 << logical_cluster_bits) - offset;
      if (size > len)
	size = len;

      disk->read_hook = read_hook;
      disk->closure = closure;
      grub_disk_read_ex (disk, sector, offset, size, buf, flags);
      disk->read_hook = 0;
      if (grub_errno)
	return -1;

      len -= size;
      if (buf)
	buf += size;
      ret += size;
      logical_cluster++;
      offset = 0;
    }

  return ret;
}

static grub_err_t
grub_fat_iterate_dir (grub_disk_t disk, struct grub_fat_data *data,
		      int (*hook) (const char *filename,
				   struct grub_fat_dir_entry *dir,
				   void *closure),
		      void *closure)
{
  struct grub_fat_dir_entry dir;
  char *filename, *filep = 0;
  grub_uint16_t *unibuf;
  int slot = -1, slots = -1;
  int checksum = -1;
  grub_ssize_t offset;

  if (! (data->attr & GRUB_FAT_ATTR_DIRECTORY))
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");

  /* Allocate space enough to hold a long name.  */
  filename = grub_malloc (0x40 * 13 * 4 + 1);
  unibuf = (grub_uint16_t *) grub_malloc (0x40 * 13 * 2);
  if (! filename || ! unibuf)
    {
      grub_free (filename);
      grub_free (unibuf);
      return 0;
    }

  //while (1)
    for (offset = 0; ; offset += sizeof (dir)) {
      unsigned i;

      /* Adjust the offset.  */
      //offset += sizeof (dir);

      /* Read a directory entry.  */
      if ((grub_fat_read_data (disk, data, 0, 0, 0,
			       offset, sizeof (dir), (char *) &dir)
	   != sizeof (dir) || dir.name[0] == 0))
	break;
      /* Handle long name entries.  */
      if (dir.attr == GRUB_FAT_ATTR_LONG_NAME)
	{
	  struct grub_fat_long_name_entry *long_name
	    = (struct grub_fat_long_name_entry *) &dir;
	  grub_uint8_t id = long_name->id;

	  if (id & 0x40)
	    {
	      id &= 0x3f;
	      slots = slot = id;
	      checksum = long_name->checksum;
	    }

	  if (id != slot || slot == 0 || checksum != long_name->checksum)
	    {
	      checksum = -1;
	      continue;
	    }

	  slot--;
	  grub_memcpy (unibuf + slot * 13, long_name->name1, 5 * 2);
	  grub_memcpy (unibuf + slot * 13 + 5, long_name->name2, 6 * 2);
	  grub_memcpy (unibuf + slot * 13 + 11, long_name->name3, 2 * 2);
	  continue;
	}

      /* Check if this entry is valid.  */
if (!(grub_fshelp_view & R_FS_VIEW_DELETED))
      if (dir.name[0] == 0xe5 || (dir.attr & ~GRUB_FAT_ATTR_VALID))
	continue;

      /* This is a workaround for Japanese.  */
      if (dir.name[0] == 0x05)
	dir.name[0] = 0xe5;

      if (checksum != -1 && slot == 0)
	{
	  grub_uint8_t sum;

	  for (sum = 0, i = 0; i < sizeof (dir.name); i++)
	    sum = ((sum >> 1) | (sum << 7)) + dir.name[i];

	  if (sum == checksum)
	    {
	      int u;

	      for (u = 0; u < slots * 13; u++)
		unibuf[u] = grub_le_to_cpu16 (unibuf[u]);

	      *grub_utf16_to_utf8 ((grub_uint8_t *) filename, unibuf,
				   slots * 13) = '\0';

	      if (hook && hook (filename, &dir, closure))
		break;

	      checksum = -1;
	      continue;
	    }

	  checksum = -1;
	}

      /* Convert the 8.3 file name.  */
      filep = filename;
      if (dir.attr & GRUB_FAT_ATTR_VOLUME_ID)
	{
	  for (i = 0; i < sizeof (dir.name) && dir.name[i]
		 && ! grub_isspace (dir.name[i]); i++)
	    *filep++ = dir.name[i];
	}
      else
	{
	  for (i = 0; i < 8 && dir.name[i] && ! grub_isspace (dir.name[i]); i++)
	    *filep++ = grub_tolower (dir.name[i]);

	  *filep = '.';

	  for (i = 8; i < 11 && dir.name[i] && ! grub_isspace (dir.name[i]); i++)
	    *++filep = grub_tolower (dir.name[i]);

	  if (*filep != '.')
	    filep++;
	}
      *filep = '\0';

      if (hook (filename, &dir, closure))
	break;
    }

  grub_free (filename);
  grub_free (unibuf);

  return grub_errno;
}

struct grub_fat_find_dir_closure
{
  struct grub_fat_data *data;
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info,
	       void *closure);
  void *closure;
  char *dirname;
  int call_hook;
  int found;
};

static int
grub_fat_find_dir_hook (const char *filename, struct grub_fat_dir_entry *dir,
			void *closure)
{
  struct grub_fat_find_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));

  info.dir = !! (dir->attr & GRUB_FAT_ATTR_DIRECTORY);
  info.case_insensitive = 1;

  if (dir->attr & GRUB_FAT_ATTR_VOLUME_ID)
    return 0;
  if (*(c->dirname) == '\0' && (c->call_hook))
    return c->hook (filename, &info, c->closure);

  if (grub_strcasecmp (c->dirname, filename) == 0)
    {
      struct grub_fat_data *data = c->data;

      c->found = 1;
      data->attr = dir->attr;
      data->file_size = grub_le_to_cpu32 (dir->file_size);
      data->file_cluster = ((grub_le_to_cpu16 (dir->first_cluster_high) << 16)
			       | grub_le_to_cpu16 (dir->first_cluster_low));
      data->cur_cluster_num = ~0U;

      if (c->call_hook)
	c->hook (filename, &info, c->closure);

      return 1;
    }
  return 0;
}

/* Find the underlying directory or file in PATH and return the
   next path. If there is no next path or an error occurs, return NULL.
   If HOOK is specified, call it with each file name.  */
static char *
grub_fat_find_dir (grub_disk_t disk, struct grub_fat_data *data,
		   const char *path,
		   int (*hook) (const char *filename,
				const struct grub_dirhook_info *info,
				void *closure),
		   void *closure)
{
  char *dirname, *dirp;
  struct grub_fat_find_dir_closure c;

  if (! (data->attr & GRUB_FAT_ATTR_DIRECTORY))
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
      return 0;
    }

  /* Extract a directory name.  */
  while (*path == '/')
    path++;

  dirp = grub_strchr (path, '/');
  if (dirp)
    {
      unsigned len = dirp - path;

      dirname = grub_malloc (len + 1);
      if (! dirname)
	return 0;

      grub_memcpy (dirname, path, len);
      dirname[len] = '\0';
    }
  else
    /* This is actually a file.  */
    dirname = grub_strdup (path);

  c.data = data;
  c.hook = hook;
  c.closure = closure;
  c.dirname =dirname;
  c.found = 0;
  c.call_hook = (! dirp && hook);
  grub_fat_iterate_dir (disk, data, grub_fat_find_dir_hook, &c);
  if (grub_errno == GRUB_ERR_NONE && ! c.found && !c.call_hook)
    grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");

  grub_free (dirname);

  return c.found ? dirp : 0;
}

static grub_err_t
grub_fat_dir (grub_device_t device, const char *path,
	      int (*hook) (const char *filename,
			   const struct grub_dirhook_info *info, void *closure),
	      void *closure)
{
  struct grub_fat_data *data = 0;
  grub_disk_t disk = device->disk;
  grub_size_t len;
  char *dirname = 0;
  char *p;

  grub_dl_ref (my_mod);

  data = grub_fat_mount (disk);
  if (! data)
    goto fail;

  /* Make sure that DIRNAME terminates with '/'.  */
  len = grub_strlen (path);
  dirname = grub_malloc (len + 1 + 1);
  if (! dirname)
    goto fail;
  grub_memcpy (dirname, path, len);
  p = dirname + len;
  if (len>0 && path[len - 1] != '/')
    *p++ = '/';
  *p = '\0';
  p = dirname;

  do
    {
      p = grub_fat_find_dir (disk, data, p, hook, closure);
    }
  while (p && grub_errno == GRUB_ERR_NONE);

 fail:

  grub_free (dirname);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_fat_open (grub_file_t file, const char *name)
{
  struct grub_fat_data *data = 0;
  char *p = (char *) name;

  grub_dl_ref (my_mod);

  data = grub_fat_mount (file->device->disk);
  if (! data)
    goto fail;

  do
    {
      p = grub_fat_find_dir (file->device->disk, data, p, 0, 0);
      if (grub_errno != GRUB_ERR_NONE)
	goto fail;
    }
  while (p);

  if (data->attr & GRUB_FAT_ATTR_DIRECTORY)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a file");
      goto fail;
    }

  file->data = data;
  file->size = data->file_size;

  return GRUB_ERR_NONE;

 fail:

  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_ssize_t
grub_fat_read (grub_file_t file, char *buf, grub_size_t len)
{
  return grub_fat_read_data (file->device->disk, file->data, file->read_hook,
			     file->closure, file->flags,
			     file->offset, len, buf);
}

static grub_err_t
grub_fat_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static int
grub_fat_label_hook (const char *filename, struct grub_fat_dir_entry *dir,
		     void *closure)
{
  char **label = closure;

  if (dir->attr == GRUB_FAT_ATTR_VOLUME_ID)
    {
      *label = grub_strdup (filename);
      return 1;
    }
  return 0;
}

static grub_err_t
grub_fat_label (grub_device_t device, char **label)
{
  struct grub_fat_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_fat_mount (disk);
  if (! data)
    goto fail;

  if (! (data->attr & GRUB_FAT_ATTR_DIRECTORY))
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
      return 0;
    }

  *label = 0;

  grub_fat_iterate_dir (disk, data, grub_fat_label_hook, label);

 fail:

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

static grub_err_t
grub_fat_uuid (grub_device_t device, char **uuid)
{
  struct grub_fat_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_fat_mount (disk);
  if (data)
    {
      *uuid = grub_xasprintf ("%04x-%04x",
			     (grub_uint16_t) (data->uuid >> 16),
			     (grub_uint16_t) data->uuid);
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

struct grub_fs grub_fat_fs =
  {
    .name = "fat",
    .dir = grub_fat_dir,
    .open = grub_fat_open,
    .read = grub_fat_read,
    .close = grub_fat_close,
    .label = grub_fat_label,
    .uuid = grub_fat_uuid,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
#endif
    .next = 0
  };
