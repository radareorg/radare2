/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2007  Free Software Foundation, Inc.
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
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/disk.h>

GRUB_EXPORT(grub_partition_map_list);
GRUB_EXPORT(grub_partition_get_name);
GRUB_EXPORT(grub_partition_iterate);
GRUB_EXPORT(grub_partition_probe);

grub_partition_map_t grub_partition_map_list;

struct find_func_closure
{
  int partnum;
  grub_partition_t p;
};

static int
find_func (grub_disk_t d __attribute__ ((unused)),
	   const grub_partition_t partition, void *closure)
{
  struct find_func_closure *c = closure;
  if (c->partnum == partition->number)
    {
      c->p = (grub_partition_t) grub_malloc (sizeof (*c->p));
      if (! c->p)
	return 1;

      grub_memcpy (c->p, partition, sizeof (*c->p));
      return 1;
    }

  return 0;
}

static grub_partition_t
grub_partition_map_probe (const grub_partition_map_t partmap,
			  grub_disk_t disk, int partnum)
{
  struct find_func_closure c;

  c.partnum = partnum;
  c.p = 0;
  partmap->iterate (disk, find_func, &c);
  if (grub_errno)
    goto fail;

  return c.p;

 fail:
  grub_free (c.p);
  return 0;
}

grub_partition_t
grub_partition_probe (struct grub_disk *disk, const char *str)
{
  grub_partition_t part = 0;
  grub_partition_t curpart = 0;
  grub_partition_t tail;
  const char *ptr;

  part = tail = disk->partition;

  for (ptr = str; *ptr;)
    {
      grub_partition_map_t partmap;
      int num;
      const char *partname, *partname_end;

      partname = ptr;
      while (*ptr && grub_isalpha (*ptr))
	ptr++;
      partname_end = ptr;
      num = grub_strtoul (ptr, (char **) &ptr, 0) - 1;

      curpart = 0;
      /* Use the first partition map type found.  */
      FOR_PARTITION_MAPS(partmap)
      {
	if (partname_end != partname &&
	    (grub_strncmp (partmap->name, partname, partname_end - partname)
	     != 0 || partmap->name[partname_end - partname] != 0))
	  continue;

	disk->partition = part;
	curpart = grub_partition_map_probe (partmap, disk, num);
	disk->partition = tail;
	if (curpart)
	  break;

	if (grub_errno == GRUB_ERR_BAD_PART_TABLE)
	  {
	    /* Continue to next partition map type.  */
	    grub_errno = GRUB_ERR_NONE;
	    continue;
	  }

	break;
      }

      if (! curpart)
	{
	  while (part)
	    {
	      curpart = part->parent;
	      grub_free (part);
	      part = curpart;
	    }
	  return 0;
	}
      curpart->parent = part;
      part = curpart;
      if (! ptr || *ptr != ',')
	break;
      ptr++;
    }

  return part;
}

struct part_iterate_closure
{
  int (*hook) (grub_disk_t disk, const grub_partition_t partition,
	       void *closure);
  void *closure;
  int ret;
};

static int
part_iterate (grub_disk_t dsk,
	      const grub_partition_t partition, void *closure)
{
  struct part_iterate_closure *c = closure;
  struct grub_partition p = *partition;
  p.parent = dsk->partition;
  dsk->partition = 0;
  if (c->hook (dsk, &p, c->closure))
    {
      c->ret = 1;
      return 1;
    }
  if (p.start != 0)
    {
      const struct grub_partition_map *partmap;
      dsk->partition = &p;
      FOR_PARTITION_MAPS(partmap)
	{
	  grub_err_t err;
	  err = partmap->iterate (dsk, part_iterate, closure);
	  if (err)
	    grub_errno = GRUB_ERR_NONE;
	  if (c->ret)
	    break;
	}
    }
  dsk->partition = p.parent;
  return c->ret;
}

int
grub_partition_iterate (struct grub_disk *disk,
			int (*hook) (grub_disk_t disk,
				     const grub_partition_t partition,
				     void *closure),
			void *closure)
{
  struct part_iterate_closure c;
  const struct grub_partition_map *partmap;

  c.hook = hook;
  c.closure = closure;
  c.ret = 0;
  FOR_PARTITION_MAPS(partmap)
    {
      grub_err_t err;
      err = partmap->iterate (disk, part_iterate, &c);
      if (err)
	grub_errno = GRUB_ERR_NONE;
      if (c.ret)
	break;
    }

  return c.ret;
}

char *
grub_partition_get_name (const grub_partition_t partition)
{
  char *out = 0;
  int curlen = 0;
  grub_partition_t part;
  for (part = partition; part; part = part->parent)
    {
      /* Even on 64-bit machines this buffer is enough to hold
	 longest number.  */
      char buf[grub_strlen (part->partmap->name) + 25];
      int strl;
      grub_snprintf (buf, sizeof (buf), "%s%d", part->partmap->name,
		     part->number + 1);
      strl = grub_strlen (buf);
      if (curlen)
	{
	  out = grub_realloc (out, curlen + strl + 2);
	  grub_memcpy (out + strl + 1, out, curlen);
	  out[curlen + 1 + strl] = 0;
	  grub_memcpy (out, buf, strl);
	  out[strl] = ',';
	  curlen = curlen + 1 + strl;
	}
      else
	{
		if (out){
		  grub_free(out);
		  out = NULL;
		}
	  curlen = strl;
	  out = grub_strdup (buf);
	}
    }
  return out;
}
