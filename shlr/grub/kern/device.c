/* device.c - device manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#include <grub/device.h>
#include <grub/disk.h>
#include <grub/net.h>
#include <grub/fs.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/partition.h>

GRUB_EXPORT(grub_device_open);
GRUB_EXPORT(grub_device_close);
GRUB_EXPORT(grub_device_iterate);

grub_device_t
grub_device_open (const char *name)
{
  grub_disk_t disk = 0;
  grub_device_t dev = 0;

  if (! name)
    {
      name = grub_env_get ("root");
      if (*name == '\0')
	{
	  grub_error (GRUB_ERR_BAD_DEVICE, "no device is set");
	  goto fail;
	}
    }

  dev = grub_malloc (sizeof (*dev));
  if (! dev)
    goto fail;

  /* Try to open a disk.  */
  disk = grub_disk_open (name);
  if (! disk)
    goto fail;

  dev->disk = disk;
  dev->net = 0;	/* FIXME */

  return dev;

 fail:
  if (disk)
    grub_disk_close (disk);

  grub_free (dev);

  return 0;
}

grub_err_t
grub_device_close (grub_device_t device)
{
  if (device->disk)
    grub_disk_close (device->disk);

  grub_free (device);

  return grub_errno;
}

struct grub_device_iterate_closure
{
  int (*hook) (const char *name, void *closure);
  void *closure;
  struct part_ent
  {
    struct part_ent *next;
    char *name;
  } *ents;
};


static int
iterate_partition (grub_disk_t disk, const grub_partition_t partition,
		   void *closure)
{
  struct grub_device_iterate_closure *c = closure;
  char *partition_name;
  struct part_ent *p;

  partition_name = grub_partition_get_name (partition);
  if (! partition_name)
    return 1;

  p = grub_malloc (sizeof (*p));
  if (!p)
    {
      grub_free (partition_name);
      return 1;
    }

  p->name = grub_xasprintf ("%s,%s", disk->name, partition_name);
  if (!p->name)
    {
      grub_free (partition_name);
      grub_free (p);
      return 1;
    }
  grub_free (partition_name);

  p->next = c->ents;
  c->ents = p;

  return 0;
}

static int
iterate_disk (const char *disk_name, void *closure)
{
  struct grub_device_iterate_closure *c = closure;
  grub_device_t dev;

  if (c->hook (disk_name, c->closure))
    return 1;

  dev = grub_device_open (disk_name);
  if (! dev)
    {
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }

  if (dev->disk && dev->disk->has_partitions)
    {
      struct part_ent *p;
      int ret = 0;

      c->ents = NULL;
      (void) grub_partition_iterate (dev->disk, iterate_partition, c);
      grub_device_close (dev);

      grub_errno = GRUB_ERR_NONE;

      p = c->ents;
      while (p != NULL)
	{
	  struct part_ent *next = p->next;

	  if (!ret)
	    ret = c->hook (p->name, c->closure);
	  grub_free (p->name);
	  grub_free (p);
	  p = next;
	}

      return ret;
    }

  grub_device_close (dev);
  return 0;
}

int
grub_device_iterate (int (*hook) (const char *name, void *closure),
		     void *closure)
{
  struct grub_device_iterate_closure c;

  c.hook = hook;
  c.closure = closure;
  /* Only disk devices are supported at the moment.  */
  return grub_disk_dev_iterate (iterate_disk, &c);
}
