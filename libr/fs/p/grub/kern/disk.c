/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/partition.h>
#include <grub/misc.h>
#include <grub/time.h>
#include <grub/file.h>

GRUB_EXPORT(grub_disk_dev_register);
GRUB_EXPORT(grub_disk_dev_unregister);
GRUB_EXPORT(grub_disk_dev_iterate);

GRUB_EXPORT(grub_disk_open);
GRUB_EXPORT(grub_disk_close);
GRUB_EXPORT(grub_disk_read);
GRUB_EXPORT(grub_disk_read_ex);
GRUB_EXPORT(grub_disk_write);

GRUB_EXPORT(grub_disk_get_size);
GRUB_EXPORT(grub_disk_firmware_fini);
GRUB_EXPORT(grub_disk_firmware_is_tainted);

GRUB_EXPORT(grub_disk_ata_pass_through);

#define	GRUB_CACHE_TIMEOUT	2

/* The last time the disk was used.  */
static grub_uint64_t grub_last_time = 0;


/* Disk cache.  */
struct grub_disk_cache
{
  enum grub_disk_dev_id dev_id;
  unsigned long disk_id;
  grub_disk_addr_t sector;
  char *data;
  int lock;
};

static struct grub_disk_cache grub_disk_cache_table[GRUB_DISK_CACHE_NUM];

void (*grub_disk_firmware_fini) (void);
int grub_disk_firmware_is_tainted;

grub_err_t (* grub_disk_ata_pass_through) (grub_disk_t,
	    struct grub_disk_ata_pass_through_parms *);


#if 0
static unsigned long grub_disk_cache_hits;
static unsigned long grub_disk_cache_misses;

void
grub_disk_cache_get_performance (unsigned long *hits, unsigned long *misses)
{
  *hits = grub_disk_cache_hits;
  *misses = grub_disk_cache_misses;
}
#endif

static unsigned
grub_disk_cache_get_index (unsigned long dev_id, unsigned long disk_id,
			   grub_disk_addr_t sector)
{
  return ((dev_id * 524287UL + disk_id * 2606459UL
	   + ((unsigned) (sector >> GRUB_DISK_CACHE_BITS)))
	  % GRUB_DISK_CACHE_NUM);
}

static void
grub_disk_cache_invalidate (unsigned long dev_id, unsigned long disk_id,
			    grub_disk_addr_t sector)
{
  unsigned index;
  struct grub_disk_cache *cache;

  sector &= ~(GRUB_DISK_CACHE_SIZE - 1);
  index = grub_disk_cache_get_index (dev_id, disk_id, sector);
  cache = grub_disk_cache_table + index;

  if (cache->dev_id == dev_id && cache->disk_id == disk_id
      && cache->sector == sector && cache->data)
    {
      cache->lock = 1;
      grub_free (cache->data);
      cache->data = 0;
      cache->lock = 0;
    }
}

void
grub_disk_cache_invalidate_all (void)
{
  unsigned i;

  for (i = 0; i < GRUB_DISK_CACHE_NUM; i++)
    {
      struct grub_disk_cache *cache = grub_disk_cache_table + i;

      if (cache->data && ! cache->lock)
	{
	  grub_free (cache->data);
	  cache->data = 0;
	}
    }
}

static char *
grub_disk_cache_fetch (unsigned long dev_id, unsigned long disk_id,
		       grub_disk_addr_t sector)
{
  struct grub_disk_cache *cache;
  unsigned index;

  index = grub_disk_cache_get_index (dev_id, disk_id, sector);
  cache = grub_disk_cache_table + index;

  if (cache->dev_id == dev_id && cache->disk_id == disk_id
      && cache->sector == sector)
    {
      cache->lock = 1;
#if 0
      grub_disk_cache_hits++;
#endif
      return cache->data;
    }

#if 0
  grub_disk_cache_misses++;
#endif

  return 0;
}

static void
grub_disk_cache_unlock (unsigned long dev_id, unsigned long disk_id,
			grub_disk_addr_t sector)
{
  struct grub_disk_cache *cache;
  unsigned index;

  index = grub_disk_cache_get_index (dev_id, disk_id, sector);
  cache = grub_disk_cache_table + index;

  if (cache->dev_id == dev_id && cache->disk_id == disk_id
      && cache->sector == sector)
    cache->lock = 0;
}

static grub_err_t
grub_disk_cache_store (unsigned long dev_id, unsigned long disk_id,
		       grub_disk_addr_t sector, const char *data)
{
  unsigned index;
  struct grub_disk_cache *cache;

  index = grub_disk_cache_get_index (dev_id, disk_id, sector);
  cache = grub_disk_cache_table + index;

  cache->lock = 1;
  grub_free (cache->data);
  cache->data = 0;
  cache->lock = 0;

  cache->data = grub_malloc (GRUB_DISK_SECTOR_SIZE << GRUB_DISK_CACHE_BITS);
  if (! cache->data)
    return grub_errno;

  grub_memcpy (cache->data, data,
	       GRUB_DISK_SECTOR_SIZE << GRUB_DISK_CACHE_BITS);
  cache->dev_id = dev_id;
  cache->disk_id = disk_id;
  cache->sector = sector;

  return GRUB_ERR_NONE;
}



static grub_disk_dev_t grub_disk_dev_list;

void
grub_disk_dev_register (grub_disk_dev_t dev)
{
  dev->next = grub_disk_dev_list;
  grub_disk_dev_list = dev;
}

void
grub_disk_dev_unregister (grub_disk_dev_t dev)
{
  grub_disk_dev_t *p, q;

  for (p = &grub_disk_dev_list, q = *p; q; p = &(q->next), q = q->next)
    if (q == dev)
      {
        *p = q->next;
	break;
      }
}

int
grub_disk_dev_iterate (int (*hook) (const char *name, void *closure),
		       void *closure)
{
  grub_disk_dev_t p;

  for (p = grub_disk_dev_list; p; p = p->next)
    if (p->iterate && (p->iterate) (hook, closure))
      return 1;

  return 0;
}

/* Return the location of the first ',', if any, which is not
   escaped by a '\'.  */
static const char *
find_part_sep (const char *name)
{
  const char *p = name;
  char c;

  while ((c = *p++) != '\0')
    {
      if (c == '\\' && *p == ',')
	p++;
      else if (c == ',')
	return p - 1;
    }
  return NULL;
}

grub_disk_t
grub_disk_open (const char *name)
{
  const char *p;
  grub_disk_t disk;
  grub_disk_dev_t dev;
  char *raw = (char *) name;
  grub_uint64_t current_time;

  grub_dprintf ("disk", "Opening `%s'...\n", name);

  disk = (grub_disk_t) grub_zalloc (sizeof (*disk));
  if (! disk)
    return 0;

  disk->name = grub_strdup (name);
  if (! disk->name)
    goto fail;

  p = find_part_sep (name);
  if (p)
    {
      grub_size_t len = p - name;

      raw = grub_malloc (len + 1);
      if (! raw)
	goto fail;

      grub_memcpy (raw, name, len);
      raw[len] = '\0';
    }

  for (dev = grub_disk_dev_list; dev; dev = dev->next)
    {
      if ((dev->open) (raw, disk) == GRUB_ERR_NONE)
	break;
      else if (grub_errno == GRUB_ERR_UNKNOWN_DEVICE)
	grub_errno = GRUB_ERR_NONE;
      else
	goto fail;
    }

  if (! dev)
    {
      grub_error (GRUB_ERR_UNKNOWN_DEVICE, "no such disk");
      goto fail;
    }

  if (p && ! disk->has_partitions)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "no partition on this disk");
      goto fail;
    }

  disk->dev = dev;

  if (p)
    {
      disk->partition = grub_partition_probe (disk, p + 1);
      if (! disk->partition)
	{
	  grub_error (GRUB_ERR_UNKNOWN_DEVICE, "no such partition");
	  goto fail;
	}
    }

  /* The cache will be invalidated about 2 seconds after a device was
     closed.  */
  current_time = grub_get_time_ms ();

  if (current_time > (grub_last_time
		      + GRUB_CACHE_TIMEOUT * 1000))
    grub_disk_cache_invalidate_all ();

  grub_last_time = current_time;

 fail:

  if (raw && raw != name)
    grub_free (raw);

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_error_push ();
      grub_dprintf ("disk", "Opening `%s' failed.\n", name);
      grub_error_pop ();

      grub_disk_close (disk);
      return 0;
    }

  return disk;
}

void
grub_disk_close (grub_disk_t disk)
{
  grub_partition_t part;
  grub_dprintf ("disk", "Closing `%s'.\n", disk->name);

  if (disk->dev && disk->dev->close)
    (disk->dev->close) (disk);

  /* Reset the timer.  */
  grub_last_time = grub_get_time_ms ();

  while (disk->partition)
    {
      part = disk->partition->parent;
      grub_free (disk->partition);
      disk->partition = part;
    }
  grub_free ((void *) disk->name);
  grub_free (disk);
}

/* This function performs three tasks:
   - Make sectors disk relative from partition relative.
   - Normalize offset to be less than the sector size.
   - Verify that the range is inside the partition.  */
static grub_err_t
grub_disk_adjust_range (grub_disk_t disk, grub_disk_addr_t *sector,
			grub_off_t *offset, grub_size_t size)
{
  *sector += *offset >> GRUB_DISK_SECTOR_BITS;
  *offset &= GRUB_DISK_SECTOR_SIZE - 1;
/*
  grub_partition_t part;
  for (part = disk->partition; part; part = part->parent)
    {
      grub_disk_addr_t start;
      grub_uint64_t len;

      start = part->start;
      len = part->len;

      if (*sector >= len
	  || len - *sector < ((*offset + size + GRUB_DISK_SECTOR_SIZE - 1)
			      >> GRUB_DISK_SECTOR_BITS))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "out of partition");

      *sector += start;
    }

  if (disk->total_sectors <= *sector
      || ((*offset + size + GRUB_DISK_SECTOR_SIZE - 1)
	  >> GRUB_DISK_SECTOR_BITS) > disk->total_sectors - *sector)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "out of disk");
*/
  return GRUB_ERR_NONE;

}

/* Read data from the disk.  */
grub_err_t
grub_disk_read (grub_disk_t disk, grub_disk_addr_t sector,
		grub_off_t offset, grub_size_t size, void *buf)
{
  char *tmp_buf;
  unsigned real_offset;

  /* First of all, check if the region is within the disk.  */
  if (grub_disk_adjust_range (disk, &sector, &offset, size) != GRUB_ERR_NONE)
    {
      grub_error_push ();
      grub_dprintf ("disk", "Read out of range: sector 0x%llx (%s).\n",
		    (unsigned long long) sector, grub_errmsg);
      grub_error_pop ();
      return grub_errno;
    }

  real_offset = offset;

  /* Allocate a temporary buffer.  */
  tmp_buf = grub_malloc (GRUB_DISK_SECTOR_SIZE << GRUB_DISK_CACHE_BITS);
  if (! tmp_buf)
    return grub_errno;

  /* Until SIZE is zero...  */
  while (size)
    {
      char *data;
      grub_disk_addr_t start_sector;
      grub_size_t len;
      grub_size_t pos;

      /* For reading bulk data.  */
      start_sector = sector & ~(GRUB_DISK_CACHE_SIZE - 1);
      pos = (sector - start_sector) << GRUB_DISK_SECTOR_BITS;
      len = ((GRUB_DISK_SECTOR_SIZE << GRUB_DISK_CACHE_BITS)
	     - pos - real_offset);
      if (len > size)
	len = size;

      /* Fetch the cache.  */
      data = grub_disk_cache_fetch (disk->dev->id, disk->id, start_sector);
      if (data)
	{
	  /* Just copy it!  */
	  if (buf)
	    grub_memcpy (buf, data + pos + real_offset, len);
	  grub_disk_cache_unlock (disk->dev->id, disk->id, start_sector);
	}
      else
	{
	  /* Otherwise read data from the disk actually.  */
	  if (start_sector + GRUB_DISK_CACHE_SIZE > disk->total_sectors
	      || (disk->dev->read) (disk, start_sector,
				    GRUB_DISK_CACHE_SIZE, tmp_buf)
	      != GRUB_ERR_NONE)
	    {
	      /* Uggh... Failed. Instead, just read necessary data.  */
	      unsigned num;
	      char *p;

	      grub_errno = GRUB_ERR_NONE;

	      num = ((size + real_offset + GRUB_DISK_SECTOR_SIZE - 1)
		     >> GRUB_DISK_SECTOR_BITS);

	      p = grub_realloc (tmp_buf, num << GRUB_DISK_SECTOR_BITS);
	      if (!p)
		goto finish;

	      tmp_buf = p;

	      if ((disk->dev->read) (disk, sector, num, tmp_buf))
		{
		  grub_error_push ();
		  grub_dprintf ("disk", "%s read failed\n", disk->name);
		  grub_error_pop ();
		  goto finish;
		}

	      if (buf)
		grub_memcpy (buf, tmp_buf + real_offset, size);

	      /* Call the read hook, if any.  */
	      if (disk->read_hook)
		while (size)
		  {
		    grub_size_t to_read;

		    to_read = size;
		    if (real_offset + to_read > GRUB_DISK_SECTOR_SIZE)
		      to_read = GRUB_DISK_SECTOR_SIZE - real_offset;
		    (disk->read_hook) (sector, real_offset,
				       to_read, disk->closure);
		    if (grub_errno != GRUB_ERR_NONE)
		      goto finish;

		    sector++;
		    size -= to_read;
		    real_offset = 0;
		  }

	      /* This must be the end.  */
	      goto finish;
	    }

	  /* Copy it and store it in the disk cache.  */
	  if (buf)
	    grub_memcpy (buf, tmp_buf + pos + real_offset, len);
	  grub_disk_cache_store (disk->dev->id, disk->id,
				 start_sector, tmp_buf);
	}

      /* Call the read hook, if any.  */
      if (disk->read_hook)
	{
	  grub_disk_addr_t s = sector;
	  grub_size_t l = len;

	  while (l)
	    {
	      (disk->read_hook) (s, real_offset,
				 ((l > GRUB_DISK_SECTOR_SIZE)
				  ? GRUB_DISK_SECTOR_SIZE
				  : l), disk->closure);

	      if (l < GRUB_DISK_SECTOR_SIZE - real_offset)
		break;

	      s++;
	      l -= GRUB_DISK_SECTOR_SIZE - real_offset;
	      real_offset = 0;
	    }
	}

      sector = start_sector + GRUB_DISK_CACHE_SIZE;
      if (buf)
	buf = (char *) buf + len;
      size -= len;
      real_offset = 0;
    }

 finish:

  grub_free (tmp_buf);

  return grub_errno;
}

grub_err_t
grub_disk_read_ex (grub_disk_t disk, grub_disk_addr_t sector,
		   grub_off_t offset, grub_size_t size, void *buf, int flags)
{
  unsigned real_offset;

  if (! flags)
    return grub_disk_read (disk, sector, offset, size, buf);

  if (grub_disk_adjust_range (disk, &sector, &offset, size) != GRUB_ERR_NONE)
    return grub_errno;

  real_offset = offset;
  while (size)
    {
      char tmp_buf[GRUB_DISK_SECTOR_SIZE];
      grub_size_t len;

      if ((real_offset != 0) || (size < GRUB_DISK_SECTOR_SIZE))
	{
	  len = GRUB_DISK_SECTOR_SIZE - real_offset;
	  if (len > size)
	    len = size;

	  if (buf)
	    {
	      if ((disk->dev->read) (disk, sector, 1, tmp_buf) != GRUB_ERR_NONE)
		break;
	      grub_memcpy (buf, tmp_buf + real_offset, len);
	    }

	  if (disk->read_hook)
	    (disk->read_hook) (sector, real_offset, len, disk->closure);

	  sector++;
	  real_offset = 0;
	}
      else
	{
	  grub_size_t n;

	  len = size & ~(GRUB_DISK_SECTOR_SIZE - 1);
	  n = size >> GRUB_DISK_SECTOR_BITS;

	  if ((buf) &&
	      ((disk->dev->read) (disk, sector, n, buf) != GRUB_ERR_NONE))
	    break;

	  if (disk->read_hook)
	    {
	      while (n)
		{
		  (disk->read_hook) (sector++, 0, GRUB_DISK_SECTOR_SIZE,
				     disk->closure);
		  n--;
		}
	    }
	  else
	    sector += n;
	}

      if (buf)
	buf = (char *) buf + len;
      size -= len;
    }

  return grub_errno;
}

grub_err_t
grub_disk_write (grub_disk_t disk, grub_disk_addr_t sector,
		 grub_off_t offset, grub_size_t size, const void *buf)
{
  unsigned real_offset;

  grub_dprintf ("disk", "Writing `%s'...\n", disk->name);

  if (grub_disk_adjust_range (disk, &sector, &offset, size) != GRUB_ERR_NONE)
    return grub_errno;

  real_offset = offset;

  while (size)
    {
      if (real_offset != 0 || (size < GRUB_DISK_SECTOR_SIZE && size != 0))
	{
	  char tmp_buf[GRUB_DISK_SECTOR_SIZE];
	  grub_size_t len;
	  grub_partition_t part;

	  part = disk->partition;
	  disk->partition = 0;
	  if (grub_disk_read (disk, sector, 0, GRUB_DISK_SECTOR_SIZE, tmp_buf)
	      != GRUB_ERR_NONE)
	    {
	      disk->partition = part;
	      goto finish;
	    }
	  disk->partition = part;

	  len = GRUB_DISK_SECTOR_SIZE - real_offset;
	  if (len > size)
	    len = size;

	  grub_memcpy (tmp_buf + real_offset, buf, len);

	  grub_disk_cache_invalidate (disk->dev->id, disk->id, sector);

	  if ((disk->dev->write) (disk, sector, 1, tmp_buf) != GRUB_ERR_NONE)
	    goto finish;

	  sector++;
	  buf = (char *) buf + len;
	  size -= len;
	  real_offset = 0;
	}
      else
	{
	  grub_size_t len;
	  grub_size_t n;

	  len = size & ~(GRUB_DISK_SECTOR_SIZE - 1);
	  n = size >> GRUB_DISK_SECTOR_BITS;

	  if ((disk->dev->write) (disk, sector, n, buf) != GRUB_ERR_NONE)
	    goto finish;

	  while (n--)
	    grub_disk_cache_invalidate (disk->dev->id, disk->id, sector++);

	  buf = (char *) buf + len;
	  size -= len;
	}
    }

 finish:

  return grub_errno;
}

grub_uint64_t
grub_disk_get_size (grub_disk_t disk)
{
  if (disk->partition)
    return grub_partition_get_len (disk->partition);
  else
    return disk->total_sectors;
}
