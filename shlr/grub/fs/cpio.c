/* cpio.c - cpio and tar filesystem.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007,2008,2009 Free Software Foundation, Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>

#ifndef MODE_USTAR
/* cpio support */
#define	MAGIC_BCPIO	070707
struct head
{
  grub_uint16_t magic;
  grub_uint16_t dev;
  grub_uint16_t ino;
  grub_uint16_t mode;
  grub_uint16_t uid;
  grub_uint16_t gid;
  grub_uint16_t nlink;
  grub_uint16_t rdev;
  grub_uint16_t mtime_1;
  grub_uint16_t mtime_2;
  grub_uint16_t namesize;
  grub_uint16_t filesize_1;
  grub_uint16_t filesize_2;
} __attribute__ ((packed));
#else
/* tar support */
#define MAGIC_USTAR	"ustar"
struct head
{
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char chksum[8];
  char typeflag;
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
} __attribute__ ((packed));
#endif

struct grub_cpio_data
{
  grub_disk_t disk;
  grub_uint32_t hofs;
  grub_uint32_t dofs;
  grub_uint32_t size;
};

static grub_dl_t my_mod;

#ifndef MODE_USTAR

static void
grub_cpio_convert_header (struct head *head)
{
  if (head->magic != MAGIC_BCPIO)
    {
      head->magic = grub_swap_bytes16 (head->magic);
      head->namesize = grub_swap_bytes16 (head->namesize);
      head->filesize_1 = grub_swap_bytes16 (head->filesize_1);
      head->filesize_2 = grub_swap_bytes16 (head->filesize_2);
    }
}

#endif

static grub_err_t
grub_cpio_find_file (struct grub_cpio_data *data, char **name,
		     grub_uint32_t * ofs)
{
#ifndef MODE_USTAR
      struct head hd;

      if (grub_disk_read
	  (data->disk, 0, data->hofs, sizeof (hd), &hd))
	return grub_errno;
      grub_cpio_convert_header (&hd);

      if (hd.magic != MAGIC_BCPIO)
	return grub_error (GRUB_ERR_BAD_FS, "invalid cpio archive");

      data->size = (((grub_uint32_t) hd.filesize_1) << 16) + hd.filesize_2;

      if (hd.namesize & 1)
	hd.namesize++;

      if ((*name = grub_malloc (hd.namesize)) == NULL)
	return grub_errno;

      if (grub_disk_read (data->disk, 0, data->hofs + sizeof (hd),
			  hd.namesize, *name))
	{
	  grub_free (*name);
	  return grub_errno;
	}

      if (data->size == 0 && hd.mode == 0 && hd.namesize == 11 + 1
	  && ! grub_memcmp(*name, "TRAILER!!!", 11))
	{
	  *ofs = 0;
	  return GRUB_ERR_NONE;
	}

      data->dofs = data->hofs + sizeof (hd) + hd.namesize;
      *ofs = data->dofs + data->size;
      if (data->size & 1)
	(*ofs)++;
#else
      struct head hd;

      if (grub_disk_read
	  (data->disk, 0, data->hofs, sizeof (hd), &hd))
	return grub_errno;

      if (!hd.name[0])
	{
	  *ofs = 0;
	  return GRUB_ERR_NONE;
	}

      if (grub_memcmp (hd.magic, MAGIC_USTAR, sizeof (MAGIC_USTAR) - 1))
	return grub_error (GRUB_ERR_BAD_FS, "invalid tar archive");

      if ((*name = grub_strdup (hd.name)) == NULL)
	return grub_errno;

      data->size = grub_strtoul (hd.size, NULL, 8);
      data->dofs = data->hofs + GRUB_DISK_SECTOR_SIZE;
      *ofs = data->dofs + ((data->size + GRUB_DISK_SECTOR_SIZE - 1) &
			   ~(GRUB_DISK_SECTOR_SIZE - 1));
#endif
  return GRUB_ERR_NONE;
}

static struct grub_cpio_data *
grub_cpio_mount (grub_disk_t disk)
{
  struct head hd;
  struct grub_cpio_data *data;

  if (grub_disk_read (disk, 0, 0, sizeof (hd), &hd))
    goto fail;

#ifndef MODE_USTAR
  grub_cpio_convert_header (&hd);
  if (hd.magic != MAGIC_BCPIO)
#else
  if (grub_memcmp (hd.magic, MAGIC_USTAR,
		   sizeof (MAGIC_USTAR) - 1))
#endif
    goto fail;

  data = (struct grub_cpio_data *) grub_malloc (sizeof (*data));
  if (!data)
    goto fail;

  data->disk = disk;

  return data;

fail:
  grub_error (GRUB_ERR_BAD_FS, "not a "
#ifdef MODE_USTAR
	      "tar"
#else
	      "cpio"
#endif
	      " filesystem");
  return 0;
}

static grub_err_t
grub_cpio_dir (grub_device_t device, const char *path,
	       int (*hook) (const char *filename,
			    const struct grub_dirhook_info *info,
			    void *closure),
	       void *closure)
{
  struct grub_cpio_data *data;
  grub_uint32_t ofs;
  char *prev, *name;
  const char *np;
  int len;

  grub_dl_ref (my_mod);

  prev = 0;

  data = grub_cpio_mount (device->disk);
  if (!data)
    goto fail;

  np = path + 1;
  len = grub_strlen (path) - 1;

  data->hofs = 0;
  if (hook)
  while (1)
    {
      if (grub_cpio_find_file (data, &name, &ofs))
	goto fail;

      if (!ofs)
	break;

      if (grub_memcmp (np, name, len) == 0)
	{
	  char *p, *n;

	  n = name + len;
	  if (*n == '/')
	    n++;

	  p = grub_strchr (name + len, '/');
	  if (p)
	    *p = 0;

	  if ((!prev) || (grub_strcmp (prev, name) != 0))
	    {
	      struct grub_dirhook_info info;
	      grub_memset (&info, 0, sizeof (info));
	      info.dir = (p != NULL);

	      hook (name + len, &info, closure);
	      if (prev) {
			grub_free (prev);
			prev = NULL;
		  }
	      prev = name;
	    }
	  else {
	    grub_free (name);
		name = NULL;
	  }
	}
      data->hofs = ofs;
    }

fail:

  if (prev)
    grub_free (prev);

  if (data)
    grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_cpio_open (grub_file_t file, const char *name)
{
  struct grub_cpio_data *data;
  grub_uint32_t ofs;
  char *fn = NULL;
  int i, j;

  grub_dl_ref (my_mod);

  data = grub_cpio_mount (file->device->disk);
  if (!data)
    goto fail;

  data->hofs = 0;
  while (1)
    {
      if (grub_cpio_find_file (data, &fn, &ofs))
	goto fail;

      if (!ofs)
	{
	  grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
	  break;
	}

      /* Compare NAME and FN by hand in order to cope with duplicate
	 slashes.  */
      i = 0;
      j = 0;
      while (name[i] == '/')
	i++;
      while (1)
	{
	  if (fn && name[i] != fn[j])
	    goto no_match;

	  if (name[i] == '\0')
	    break;

	  while (name[i] == '/' && name[i+1] == '/')
	    i++;

	  i++;
	  j++;
	}

      if (fn && name[i] != fn[j])
	goto no_match;

      file->data = data;
      file->size = data->size;
      grub_free (fn);

      return GRUB_ERR_NONE;

    no_match:

      grub_free (fn);
      fn = NULL;
      data->hofs = ofs;
    }

fail:

  if (data)
    grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_ssize_t
grub_cpio_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_cpio_data *data;

  data = file->data;
  return (grub_disk_read (data->disk, 0, data->dofs + file->offset,
			  len, buf)) ? -1 : (grub_ssize_t) len;
}

static grub_err_t
grub_cpio_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

#ifndef MODE_USTAR
struct grub_fs grub_cpio_fs = { 
  .name = "cpiofs",
  .dir = grub_cpio_dir,
  .open = grub_cpio_open,
  .read = grub_cpio_read,
  .close = grub_cpio_close,
};
#else
struct grub_fs grub_tar_fs = {
  .name = "tarfs",
  .dir = grub_cpio_dir,
  .open = grub_cpio_open,
  .read = grub_cpio_read,
  .close = grub_cpio_close,
};
#endif
