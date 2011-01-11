/* file.c - file I/O functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2006,2007,2009  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/fs.h>
#include <grub/device.h>

grub_file_filter_t grub_file_filters_all[GRUB_FILE_FILTER_MAX];
grub_file_filter_t grub_file_filters_enabled[GRUB_FILE_FILTER_MAX];

/* Get the device part of the filename NAME. It is enclosed by parentheses.  */
char *
grub_file_get_device_name (const char *name)
{
  if (name[0] == '(')
    {
      char *p = grub_strchr (name, ')');
      char *ret;

      if (! p)
	{
	  grub_error (GRUB_ERR_BAD_FILENAME, "missing `)'");
	  return 0;
	}

      ret = (char *) grub_malloc (p - name);
      if (! ret)
	return 0;

      grub_memcpy (ret, name + 1, p - name - 1);
      ret[p - name - 1] = '\0';
      return ret;
    }

  return 0;
}

grub_file_t
grub_file_open (const char *name)
{
  grub_device_t device = 0;
  grub_file_t file = 0, last_file = 0;
  char *device_name;
  char *file_name;
  grub_file_filter_id_t filter;

  device_name = grub_file_get_device_name (name);
  if (grub_errno)
    goto fail;

  /* Get the file part of NAME.  */
  file_name = grub_strchr (name, ')');
  if (file_name)
    file_name++;
  else
    file_name = (char *) name;

  device = grub_device_open (device_name);
  grub_free (device_name);
  if (! device)
    goto fail;

  file = (grub_file_t) grub_zalloc (sizeof (*file));
  if (! file)
    goto fail;

  file->device = device;

  if (device->disk && file_name[0] != '/')
    /* This is a block list.  */
    file->fs = &grub_fs_blocklist;
  else
    {
      file->fs = grub_fs_probe (device);
      if (! file->fs)
	goto fail;
    }

  if ((file->fs->open) (file, file_name) != GRUB_ERR_NONE)
    goto fail;

  for (filter = 0; file && filter < ARRAY_SIZE (grub_file_filters_enabled);
       filter++)
    if (grub_file_filters_enabled[filter])
      {
	last_file = file;
	file = grub_file_filters_enabled[filter] (file);
      }
  if (!file)
    grub_file_close (last_file);
    
  grub_memcpy (grub_file_filters_enabled, grub_file_filters_all,
	       sizeof (grub_file_filters_enabled));

  return file;

 fail:
  if (device)
    grub_device_close (device);

  /* if (net) grub_net_close (net);  */

  grub_free (file);

  grub_memcpy (grub_file_filters_enabled, grub_file_filters_all,
	       sizeof (grub_file_filters_enabled));

  return 0;
}

grub_ssize_t
grub_file_read (grub_file_t file, void *buf, grub_size_t len)
{
  grub_ssize_t res;

  if (file->offset > file->size)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
		  "attempt to read past the end of file");
      return -1;
    }

  if (len == 0 || len > file->size - file->offset)
    len = file->size - file->offset;

  /* Prevent an overflow.  */
  if ((grub_ssize_t) len < 0)
    len >>= 1;

  if (len == 0)
    return 0;

  res = (file->fs->read) (file, buf, len);
  if (res > 0)
    file->offset += res;

  return res;
}

grub_err_t
grub_file_close (grub_file_t file)
{
  if (file->fs->close)
    (file->fs->close) (file);

  if (file->device)
    grub_device_close (file->device);
  grub_free (file);
  return grub_errno;
}

grub_off_t
grub_file_seek (grub_file_t file, grub_off_t offset)
{
  grub_off_t old;

  if (offset > file->size)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
		  "attempt to seek outside of the file");
      return -1;
    }

  old = file->offset;
  file->offset = offset;
  return old;
}
