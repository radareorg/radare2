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
#include <grub/term.h>

GRUB_EXPORT(grub_file_get_device_name);
GRUB_EXPORT(grub_file_open);
GRUB_EXPORT(grub_file_read);
GRUB_EXPORT(grub_file_seek);
GRUB_EXPORT(grub_file_close);

GRUB_EXPORT(grub_file_pb_init);
GRUB_EXPORT(grub_file_pb_fini);
GRUB_EXPORT(grub_file_pb_show);
GRUB_EXPORT(grub_file_pb_read);

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
  grub_device_t device;
  grub_file_t file = 0;
  char *device_name;
  char *file_name;

  device_name = grub_file_get_device_name (name);
  if (grub_errno)
    return 0;

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

  return file;

 fail:
  if (device)
    grub_device_close (device);

  /* if (net) grub_net_close (net);  */

  grub_free (file);

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

static void
grub_file_pb_show_default (int num __attribute__((unused)),
			   int total __attribute__((unused)))
{
  grub_printf (".");
  grub_refresh ();
}

static void
grub_file_pb_fini_default (void)
{
  grub_printf ("\n");
}

void (*grub_file_pb_init) (void);
void (*grub_file_pb_fini) (void) = grub_file_pb_fini_default;
void (*grub_file_pb_show) (int num, int total) = grub_file_pb_show_default;

grub_ssize_t
grub_file_pb_read (grub_file_t file, void *b, grub_size_t len, int total)
{
  grub_ssize_t ret;
  grub_size_t bsize;
  int num;
  char *buf = b;

  if ((len < GRUB_FILE_PB_MIN_SIZE) || (total == 0))
    return grub_file_read (file, buf, len);

  ret = 0;
  if (grub_file_pb_init)
    grub_file_pb_init ();

  bsize = ((len / total) + 511) & (~511);
  num = 0;
  while (len > 0)
    {
      grub_size_t n;
      grub_ssize_t r;

      grub_file_pb_show (num, total);

      n = (len > bsize) ? bsize : len;
      r = grub_file_read (file, buf, n);
      if (r <= 0)
	{
	  if (ret == 0)
	    ret = -1;
	  break;
	}

      buf += r;
      len -= r;
      ret += r;
      num++;
    }

  if (grub_file_pb_fini)
    grub_file_pb_fini ();
  return ret;
}

