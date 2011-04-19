/*
 *  BURG - Brand-new Universal loadeR from GRUB
 *  Copyright 2010 Bean Lee - All Rights Reserved
 *
 *  BURG is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BURG is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with BURG.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/dl.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/fbfs.h>

struct grub_fb_data
{
  grub_uint32_t ofs;
  grub_uint32_t pri_size;
  struct fbm_file *ptr;
  char fb_list[0];
};

static struct grub_fb_data *
grub_fbfs_mount (grub_disk_t disk)
{
  struct fb_mbr *m;
  struct fb_data *d;
  char buf[512];
  struct grub_fb_data *data;
  int boot_base, boot_size, list_used, pri_size, ofs, i;
  char *fb_list, *p1, *p2;

  if (grub_disk_read (disk, 0, 0, sizeof (buf), buf))
    goto fail;

  m = (struct fb_mbr *) buf;
  d = (struct fb_data *) buf;
  if (*((grub_uint32_t *) &buf[0]) == FB_AR_MAGIC_LONG)
    {
      ofs = 0;
      boot_base = 0;
      boot_size = 0;
      pri_size = 0;
    }
  else
    {
      if ((m->fb_magic != FB_MAGIC_LONG) || (m->end_magic != 0xaa55))
	goto fail;

      ofs = m->lba;
      boot_base = m->boot_base;

      if (grub_disk_read (disk, boot_base + 1 - ofs, 0, sizeof (buf), buf))
	goto fail;

      boot_size = d->boot_size;
      pri_size = d->pri_size;
    }

  if ((d->ver_major != FB_VER_MAJOR) || (d->ver_minor != FB_VER_MINOR))
    goto fail;

  list_used = d->list_used;
  data = grub_malloc (sizeof (*data) + (list_used << 9));
  if (! data)
    goto fail;

  fb_list = data->fb_list;
  if (grub_disk_read (disk, boot_base + 1 + boot_size - ofs, 0,
		      (list_used << 9), fb_list))
    {
      grub_free (data);
      goto fail;
    }

  p1 = p2 = fb_list;
  for (i = 0; i < list_used - 1; i++)
    {
      p1 += 510;
      p2 += 512;
      grub_memcpy (p1, p2, 510);
    }

  data->ofs = ofs;
  data->pri_size = pri_size;
  return data;

 fail:
  grub_error (GRUB_ERR_BAD_FS, "not a fb filesystem");
  return 0;
}

static grub_err_t
grub_fbfs_dir (grub_device_t device, const char *path,
	       int (*hook) (const char *filename,
			    const struct grub_dirhook_info *info,
			    void *closure),
	       void *closure)
{
  struct grub_dirhook_info info;
  struct fbm_file *p;
  char *fn;
  int len, ofs;
  struct grub_fb_data *data;

  data = grub_fbfs_mount (device->disk);
  if (! data)
    return grub_errno;
  if (! hook)
    return GRUB_ERR_NONE;

  while (*path == '/')
    path++;
  len = grub_strlen (path);
  fn = grub_strrchr (path, '/');
  ofs = (fn) ? (fn + 1 - path) : 0;

  grub_memset (&info, 0, sizeof (info));
  info.mtimeset = 1;
  p = (struct fbm_file *) data->fb_list;
  while (p->size)
    {
      info.mtime = grub_le_to_cpu32 (p->data_time);
      if ((! grub_memcmp (path, p->name, len)) &&
	  (hook (p->name + ofs, &info, closure)))
	break;

      p = (struct fbm_file *) ((char *) p + p->size + 2);
    }

  grub_free (data);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_fbfs_open (struct grub_file *file, const char *name)
{
  struct fbm_file *p;
  struct grub_fb_data *data;

  data = grub_fbfs_mount (file->device->disk);
  if (! data)
    return grub_errno;

  while (*name == '/')
    name++;

  p = (struct fbm_file *) data->fb_list;
  while (p->size)
    {
      if (! grub_strcasecmp (name, p->name))
	{
	  file->data = data;
	  data->ptr = p;
	  file->size = p->data_size;
	  return GRUB_ERR_NONE;
	}

      p = (struct fbm_file *) ((char *) p + p->size + 2);
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
}

static grub_ssize_t
grub_fbfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct fbm_file *p;
  grub_disk_t disk;
  grub_uint32_t sector;
  grub_size_t saved_len, ofs;
  struct grub_fb_data *data;

  disk = file->device->disk;
  disk->read_hook = file->read_hook;
  disk->closure = file->closure;

  data = file->data;
  p = data->ptr;
  if (p->data_start >= data->pri_size)
    {
      grub_err_t err;

      err = grub_disk_read_ex (disk, p->data_start - data->ofs,
			       file->offset, len, buf, file->flags);
      disk->read_hook = 0;
      return (err) ? -1 : (grub_ssize_t) len;
    }

  sector = p->data_start + ((grub_uint32_t) file->offset / 510) - data->ofs;
  ofs = ((grub_uint32_t) file->offset % 510);
  saved_len = len;
  while (len)
    {
      int n;

      n = len;
      if (ofs + n > 510)
	n = 510 - ofs;
      if (grub_disk_read (disk, sector, ofs, n, buf))
	{
	  saved_len = -1;
	  break;
	}
      sector++;
      if (buf)
	buf += n;
      len -= n;
      ofs = 0;
    }

  disk->read_hook = 0;
  return saved_len;
}

static grub_err_t
grub_fbfs_close (grub_file_t file)
{
  grub_free (file->data);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_fbfs_label (grub_device_t device __attribute ((unused)),
		 char **label __attribute ((unused)))
{
  *label = 0;
  return GRUB_ERR_NONE;
}

struct grub_fs grub_fb_fs =
  {
    .name = "fbfs",
    .dir = grub_fbfs_dir,
    .open = grub_fbfs_open,
    .read = grub_fbfs_read,
    .close = grub_fbfs_close,
    .label = grub_fbfs_label,
    .next = 0
  };

