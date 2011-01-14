/* fs.c - filesystem manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007  Free Software Foundation, Inc.
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
#include <grub/net.h>
#include <grub/fs.h>
#include <grub/file.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/mm.h>
#include <grub/term.h>

grub_fs_t grub_fs_list = 0;
grub_fs_autoload_hook_t grub_fs_autoload_hook = 0;

static int dummy_func (const char *filename __attribute__ ((unused)),
		  const struct grub_dirhook_info *info  __attribute__ ((unused))) {
	return 1;
}

grub_fs_t grub_fs_probe (grub_device_t device) {
  grub_fs_t p;

  if (device->disk) {
      /* Make it sure not to have an infinite recursive calls.  */
      static int count = 0;

      for (p = grub_fs_list; p; p = p->next)
	{
	  grub_dprintf ("fs", "Detecting %s...\n", p->name);
	  (p->dir) (device, "/", dummy_func);
	  if (grub_errno == GRUB_ERR_NONE)
	    return p;

	  grub_error_push ();
	  grub_dprintf ("fs", "%s detection failed.\n", p->name);
	  grub_error_pop ();

	  if (grub_errno != GRUB_ERR_BAD_FS)
	    return 0;

	  grub_errno = GRUB_ERR_NONE;
	}

      /* Let's load modules automatically.  */
      if (grub_fs_autoload_hook && count == 0)
	{
	  count++;

	  while (grub_fs_autoload_hook ())
	    {
	      p = grub_fs_list;

	      (p->dir) (device, "/", dummy_func);
	      if (grub_errno == GRUB_ERR_NONE)
		{
		  count--;
		  return p;
		}

	      if (grub_errno != GRUB_ERR_BAD_FS)
		{
		  count--;
		  return 0;
		}

	      grub_errno = GRUB_ERR_NONE;
	    }

	  count--;
	}
    }
  else if (device->net->fs)
    return device->net->fs;

  grub_error (GRUB_ERR_UNKNOWN_FS, "unknown filesystem");
  return 0;
}



/* Block list support routines.  */

struct grub_fs_block
{
  grub_disk_addr_t offset;
  unsigned long length;
};

static grub_err_t
grub_fs_blocklist_open (grub_file_t file, const char *name)
{
  char *p = (char *) name;
  unsigned num = 0;
  unsigned i;
  grub_disk_t disk = file->device->disk;
  struct grub_fs_block *blocks;

  /* First, count the number of blocks.  */
  do
    {
      num++;
      p = grub_strchr (p, ',');
      if (p)
	p++;
    }
  while (p);

  /* Allocate a block list.  */
  blocks = grub_zalloc (sizeof (struct grub_fs_block) * (num + 1));
  if (! blocks)
    return 0;

  file->size = 0;
  p = (char *) name;
  for (i = 0; i < num; i++)
    {
      if (*p != '+')
	{
	  blocks[i].offset = grub_strtoull (p, &p, 0);
	  if (grub_errno != GRUB_ERR_NONE || *p != '+')
	    {
	      grub_error (GRUB_ERR_BAD_FILENAME,
			  "invalid file name `%s'", name);
	      goto fail;
	    }
	}

      p++;
      blocks[i].length = grub_strtoul (p, &p, 0);
      if (grub_errno != GRUB_ERR_NONE
	  || blocks[i].length == 0
	  || (*p && *p != ',' && ! grub_isspace (*p)))
	{
	  grub_error (GRUB_ERR_BAD_FILENAME,
		      "invalid file name `%s'", name);
	  goto fail;
	}

      if (disk->total_sectors < blocks[i].offset + blocks[i].length)
	{
	  grub_error (GRUB_ERR_BAD_FILENAME, "beyond the total sectors");
	  goto fail;
	}

      file->size += (blocks[i].length << GRUB_DISK_SECTOR_BITS);
      p++;
    }

  file->data = blocks;

  return GRUB_ERR_NONE;

 fail:
  grub_free (blocks);
  return grub_errno;
}

static grub_ssize_t
grub_fs_blocklist_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_fs_block *p;
  grub_disk_addr_t sector;
  grub_off_t offset;
  grub_ssize_t ret = 0;

  if (len > file->size - file->offset)
    len = file->size - file->offset;

  sector = (file->offset >> GRUB_DISK_SECTOR_BITS);
  offset = (file->offset & (GRUB_DISK_SECTOR_SIZE - 1));
  for (p = file->data; p->length && len > 0; p++)
    {
      if (sector < p->length)
	{
	  grub_size_t size;

	  size = len;
	  if (((size + offset + GRUB_DISK_SECTOR_SIZE - 1)
	       >> GRUB_DISK_SECTOR_BITS) > p->length - sector)
	    size = ((p->length - sector) << GRUB_DISK_SECTOR_BITS) - offset;

	  if (grub_disk_read (file->device->disk, p->offset + sector, offset,
			      size, buf) != GRUB_ERR_NONE)
	    return -1;

	  ret += size;
	  len -= size;
	  sector -= ((size + offset) >> GRUB_DISK_SECTOR_BITS);
	  offset = ((size + offset) & (GRUB_DISK_SECTOR_SIZE - 1));
	}
      else
	sector -= p->length;
    }

  return ret;
}

struct grub_fs grub_fs_blocklist =
  {
    .name = "blocklist",
    .dir = 0,
    .open = grub_fs_blocklist_open,
    .read = grub_fs_blocklist_read,
    .close = 0,
    .next = 0
  };
