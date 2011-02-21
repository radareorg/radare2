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
#include <grub/partition.h>

GRUB_EXPORT(grub_fs_autoload_hook);
GRUB_EXPORT(grub_fs_list);
GRUB_EXPORT(grub_fs_probe);
GRUB_EXPORT(grub_blocklist_convert);
GRUB_EXPORT(grub_blocklist_write);

grub_fs_t grub_fs_list;

grub_fs_autoload_hook_t grub_fs_autoload_hook = 0;

static int
dummy_func (const char *filename __attribute__ ((unused)),
	    const struct grub_dirhook_info *info  __attribute__ ((unused)),
	    void *closure __attribute__ ((unused)))
{
  return 1;
}

grub_fs_t
grub_fs_probe (grub_device_t device)
{
  grub_fs_t p;

  if (device->disk)
    {
      /* Make it sure not to have an infinite recursive calls.  */
      static int count = 0;

      for (p = grub_fs_list; p; p = p->next)
	{
	  grub_dprintf ("fs", "Detecting %s...\n", p->name);
	  (p->dir) (device, "/", dummy_func, 0);
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

	      (p->dir) (device, "/", dummy_func, 0);
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
  if (! *p)
    {
      blocks[0].offset = 0;
      blocks[0].length = (disk->total_sectors == GRUB_ULONG_MAX) ?
	GRUB_ULONG_MAX : (disk->total_sectors << 9);
      file->size = blocks[0].length;
    }
  else for (i = 0; i < num; i++)
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

      blocks[i].offset <<= GRUB_DISK_SECTOR_BITS;
      blocks[i].length <<= GRUB_DISK_SECTOR_BITS;
      file->size += blocks[i].length;
      p++;
    }

  file->data = blocks;

  return GRUB_ERR_NONE;

 fail:
  grub_free (blocks);
  return grub_errno;
}

static grub_err_t
grub_fs_blocklist_close (grub_file_t file)
{
  grub_free (file->data);
  return grub_errno;
}

static grub_ssize_t
grub_fs_blocklist_rw (int write, grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_fs_block *p;
  grub_off_t offset;
  grub_ssize_t ret = 0;

  if (len > file->size - file->offset)
    len = file->size - file->offset;

  offset = file->offset;
  for (p = file->data; p->length && len > 0; p++)
    {
      if (offset < p->length)
	{
	  grub_size_t size;

	  size = len;
	  if (offset + size > p->length)
	    size = p->length - offset;

	  if ((write) ?
	       grub_disk_write (file->device->disk, 0, p->offset + offset,
				size, buf) :
	       grub_disk_read_ex (file->device->disk, 0, p->offset + offset,
				  size, buf, file->flags) != GRUB_ERR_NONE)
	    return -1;

	  ret += size;
	  len -= size;
	  if (buf)
	    buf += size;
	  offset += size;
	}
      offset -= p->length;
    }

  return ret;
}

static grub_ssize_t
grub_fs_blocklist_read (grub_file_t file, char *buf, grub_size_t len)
{
  grub_ssize_t ret;
  file->device->disk->read_hook = file->read_hook;
  file->device->disk->closure = file->closure;
  ret = grub_fs_blocklist_rw (0, file, buf, len);
  file->device->disk->read_hook = 0;
  return ret;
}

grub_ssize_t
grub_blocklist_write (grub_file_t file, const char *buf, grub_size_t len)
{
  return (file->fs != &grub_fs_blocklist) ? -1 :
    grub_fs_blocklist_rw (1, file, (char *) buf, len);
}

#define BLOCKLIST_INC_STEP	8

struct read_blocklist_closure
{
  int num;
  struct grub_fs_block *blocks;
  grub_off_t total_size;
  grub_disk_addr_t part_start;
};

static void
read_blocklist (grub_disk_addr_t sector, unsigned offset,
		unsigned length, void *closure)
{
  struct read_blocklist_closure *c = closure;

  sector = ((sector - c->part_start) << GRUB_DISK_SECTOR_BITS) + offset;

  if ((c->num) &&
      (c->blocks[c->num - 1].offset + c->blocks[c->num - 1].length == sector))
    {
      c->blocks[c->num - 1].length += length;
      goto quit;
    }

  if ((c->num & (BLOCKLIST_INC_STEP - 1)) == 0)
    {
      c->blocks = grub_realloc (c->blocks, (c->num + BLOCKLIST_INC_STEP) *
				sizeof (struct grub_fs_block));
      if (! c->blocks)
	return;
    }

  c->blocks[c->num].offset = sector;
  c->blocks[c->num].length = length;
  c->num++;

 quit:
  c->total_size += length;
}

void
grub_blocklist_convert (grub_file_t file)
{
  struct read_blocklist_closure c;

  if ((file->fs == &grub_fs_blocklist) || (! file->device->disk) ||
      (! file->size))
    return;

  file->offset = 0;
  file->flags = 1;

  c.num = 0;
  c.blocks = 0;
  c.total_size = 0;
  c.part_start = grub_partition_get_start (file->device->disk->partition);
  file->read_hook = read_blocklist;
  file->closure = &c;
  grub_file_read (file, 0, file->size);
  file->read_hook = 0;
  if ((grub_errno) || (c.total_size != file->size))
    {
      grub_errno = 0;
      grub_free (c.blocks);
    }
  else
    {
      if (file->fs->close)
	(file->fs->close) (file);
      file->fs = &grub_fs_blocklist;
      file->data = c.blocks;
    }

  file->offset = 0;
}

struct grub_fs grub_fs_blocklist =
  {
    .name = "blocklist",
    .dir = 0,
    .open = grub_fs_blocklist_open,
    .read = grub_fs_blocklist_read,
    .close = grub_fs_blocklist_close,
    .next = 0
  };
