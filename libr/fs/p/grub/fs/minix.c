/* minix.c - The minix filesystem, version 1 and 2.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2005,2006,2007,2008  Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>

#define GRUB_MINIX_MAGIC	0x137F
#define GRUB_MINIX2_MAGIC	0x2468
#define GRUB_MINIX_MAGIC_30	0x138F
#define GRUB_MINIX2_MAGIC_30	0x2478
#define GRUB_MINIX_BSIZE	1024U
#define GRUB_MINIX_LOG2_BSIZE	1
#define GRUB_MINIX_ROOT_INODE	1
#define GRUB_MINIX_MAX_SYMLNK_CNT	8
#define GRUB_MINIX_SBLOCK	2

#define GRUB_MINIX_IFDIR	0040000U
#define GRUB_MINIX_IFLNK	0120000U

#define GRUB_MINIX_INODE(data,field) (data->version == 1 ? \
                           data->inode.  field : data->inode2.  field)
#define GRUB_MINIX_INODE_ENDIAN(data,field,bits1,bits2) (data->version == 1 ?	\
                        grub_le_to_cpu##bits1 (data->inode.field) :		\
                        grub_le_to_cpu##bits2 (data->inode2.field))
#define GRUB_MINIX_INODE_SIZE(data) GRUB_MINIX_INODE_ENDIAN (data,size,16,32)
#define GRUB_MINIX_INODE_MODE(data) GRUB_MINIX_INODE_ENDIAN (data,mode,16,16)
#define GRUB_MINIX_INODE_DIR_ZONES(data,blk) GRUB_MINIX_INODE_ENDIAN		\
                                               (data,dir_zones[blk],16,32)
#define GRUB_MINIX_INODE_INDIR_ZONE(data)				\
                        GRUB_MINIX_INODE_ENDIAN (data,indir_zone,16,32)
#define GRUB_MINIX_INODE_DINDIR_ZONE(data)					\
                        GRUB_MINIX_INODE_ENDIAN (data,double_indir_zone,16,32)
#define GRUB_MINIX_INODE_BLKSZ(data) (data->version == 1 ? 2 : 4)
#define GRUB_MINIX_LOG2_ZONESZ	(GRUB_MINIX_LOG2_BSIZE				\
				 + grub_le_to_cpu16 (sblock->log2_zone_size))
#define GRUB_MINIX_ZONESZ	(GRUB_MINIX_BSIZE 				\
				 << grub_le_to_cpu16 (sblock->log2_zone_size))

struct grub_minix_sblock
{
  grub_uint16_t inode_cnt;
  grub_uint16_t zone_cnt;
  grub_uint16_t inode_bmap_size;
  grub_uint16_t zone_bmap_size;
  grub_uint16_t first_data_zone;
  grub_uint16_t log2_zone_size;
  grub_uint32_t max_file_size;
  grub_uint16_t magic;
};

struct grub_minix_inode
{
  grub_uint16_t mode;
  grub_uint16_t uid;
  grub_uint16_t size;
  grub_uint32_t ctime;
  grub_uint8_t gid;
  grub_uint8_t nlinks;
  grub_uint16_t dir_zones[7];
  grub_uint16_t indir_zone;
  grub_uint16_t double_indir_zone;
};

struct grub_minix2_inode
{
  grub_uint16_t mode;
  grub_uint16_t nlinks;
  grub_uint16_t uid;
  grub_uint16_t gid;
  grub_uint32_t size;
  grub_uint32_t atime;
  grub_uint32_t mtime;
  grub_uint32_t ctime;
  grub_uint32_t dir_zones[7];
  grub_uint32_t indir_zone;
  grub_uint32_t double_indir_zone;
  grub_uint32_t unused;

};

/* Information about a "mounted" minix filesystem.  */
struct grub_minix_data
{
  struct grub_minix_sblock sblock;
  struct grub_minix_inode inode;
  struct grub_minix2_inode inode2;
  int ino;
  int linknest;
  grub_disk_t disk;
  int version;
  int filename_size;
};


static grub_err_t grub_minix_find_file (struct grub_minix_data *data,
					const char *path);

/* Read the block pointer in ZONE, on the offset NUM.  */
static int
grub_get_indir (int zone, int num, struct grub_minix_data *data)
{
  struct grub_minix_sblock *sblock = &data->sblock;
  if (data->version == 1)
    {
      grub_uint16_t indir16;
      grub_disk_read (data->disk,
		      zone << GRUB_MINIX_LOG2_ZONESZ,
		      sizeof (grub_uint16_t) * num,
		      sizeof (grub_uint16_t), (char *) &indir16);
      return grub_le_to_cpu16 (indir16);
    }
  else
    {
      grub_uint32_t indir32;
      grub_disk_read (data->disk,
		      zone << GRUB_MINIX_LOG2_ZONESZ,
		      sizeof (grub_uint32_t) * num,
		      sizeof (grub_uint32_t), (char *) &indir32);
      return grub_le_to_cpu32 (indir32);
    }
}

static int
grub_minix_get_file_block (struct grub_minix_data *data, unsigned int blk)
{
  struct grub_minix_sblock *sblock = &data->sblock;
  int indir;

  /* Direct block.  */
  if (blk < 7)
    return GRUB_MINIX_INODE_DIR_ZONES (data, blk);

  /* Indirect block.  */
  blk -= 7;
  if (blk < GRUB_MINIX_ZONESZ / GRUB_MINIX_INODE_BLKSZ (data))
    {
      indir = grub_get_indir (GRUB_MINIX_INODE_INDIR_ZONE (data), blk, data);
      return indir;
    }

  /* Double indirect block.  */
  blk -= GRUB_MINIX_ZONESZ / GRUB_MINIX_INODE_BLKSZ (data);
  if (blk < (GRUB_MINIX_ZONESZ / GRUB_MINIX_INODE_BLKSZ (data))
      * (GRUB_MINIX_ZONESZ / GRUB_MINIX_INODE_BLKSZ (data)))
    {
      indir = grub_get_indir (GRUB_MINIX_INODE_DINDIR_ZONE (data),
			      blk / GRUB_MINIX_ZONESZ, data);

      indir = grub_get_indir (indir, blk % GRUB_MINIX_ZONESZ, data);

      return indir;
    }

  /* This should never happen.  */
  grub_error (GRUB_ERR_OUT_OF_RANGE, "file bigger than maximum size");

  return 0;
}


/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_minix_read_file (struct grub_minix_data *data,
		      void (*read_hook) (grub_disk_addr_t sector,
					 unsigned offset, unsigned length,
					 void *closure),
		      void *closure,
		      int pos, grub_disk_addr_t len, char *buf)
{
  struct grub_minix_sblock *sblock = &data->sblock;
  int i;
  int blockcnt;

  /* Adjust len so it we can't read past the end of the file.  */
  if (len + pos > GRUB_MINIX_INODE_SIZE (data))
    len = GRUB_MINIX_INODE_SIZE (data) - pos;

  blockcnt = (len + pos + GRUB_MINIX_BSIZE - 1) / GRUB_MINIX_BSIZE;

  for (i = pos / GRUB_MINIX_BSIZE; i < blockcnt; i++)
    {
      int blknr;
      int blockoff = pos % GRUB_MINIX_BSIZE;
      int blockend = GRUB_MINIX_BSIZE;

      int skipfirst = 0;

      blknr = grub_minix_get_file_block (data, i);
      if (grub_errno)
	return -1;

      /* Last block.  */
      if (i == blockcnt - 1)
	{
	  blockend = (len + pos) % GRUB_MINIX_BSIZE;

	  if (!blockend)
	    blockend = GRUB_MINIX_BSIZE;
	}

      /* First block.  */
      if (i == (pos / (int) GRUB_MINIX_BSIZE))
	{
	  skipfirst = blockoff;
	  blockend -= skipfirst;
	}

      data->disk->read_hook = read_hook;
      data->disk->closure =  closure;
      grub_disk_read (data->disk, blknr << GRUB_MINIX_LOG2_ZONESZ,
		      skipfirst, blockend, buf);

      data->disk->read_hook = 0;
      if (grub_errno)
	return -1;

      buf += GRUB_MINIX_BSIZE - skipfirst;
    }

  return len;
}


/* Read inode INO from the mounted filesystem described by DATA.  This
   inode is used by default now.  */
static grub_err_t
grub_minix_read_inode (struct grub_minix_data *data, int ino)
{
  struct grub_minix_sblock *sblock = &data->sblock;

  /* Block in which the inode is stored.  */
  int block;
  data->ino = ino;

  /* The first inode in minix is inode 1.  */
  ino--;

  block = ((2 + grub_le_to_cpu16 (sblock->inode_bmap_size)
	    + grub_le_to_cpu16 (sblock->zone_bmap_size))
	   << GRUB_MINIX_LOG2_BSIZE);

  if (data->version == 1)
    {
      block += ino / (GRUB_DISK_SECTOR_SIZE / sizeof (struct grub_minix_inode));
      int offs = (ino % (GRUB_DISK_SECTOR_SIZE
			 / sizeof (struct grub_minix_inode))
		  * sizeof (struct grub_minix_inode));

      grub_disk_read (data->disk, block, offs,
		      sizeof (struct grub_minix_inode), &data->inode);
    }
  else
    {
      block += ino / (GRUB_DISK_SECTOR_SIZE
		      / sizeof (struct grub_minix2_inode));
      int offs = (ino
		  % (GRUB_DISK_SECTOR_SIZE / sizeof (struct grub_minix2_inode))
		  * sizeof (struct grub_minix2_inode));

      grub_disk_read (data->disk, block, offs,
		      sizeof (struct grub_minix2_inode),&data->inode2);
    }

  return GRUB_ERR_NONE;
}


/* Lookup the symlink the current inode points to.  INO is the inode
   number of the directory the symlink is relative to.  */
static grub_err_t
grub_minix_lookup_symlink (struct grub_minix_data *data, int ino)
{
  char symlink[GRUB_MINIX_INODE_SIZE (data) + 1];

  if (++data->linknest > GRUB_MINIX_MAX_SYMLNK_CNT)
    return grub_error (GRUB_ERR_SYMLINK_LOOP, "too deep nesting of symlinks");

  if (grub_minix_read_file (data, 0, 0, 0,
			    GRUB_MINIX_INODE_SIZE (data), symlink) < 0)
    return grub_errno;

  symlink[GRUB_MINIX_INODE_SIZE (data)] = '\0';

  /* The symlink is an absolute path, go back to the root inode.  */
  if (symlink[0] == '/')
    ino = GRUB_MINIX_ROOT_INODE;

  /* Now load in the old inode.  */
  if (grub_minix_read_inode (data, ino))
    return grub_errno;

  grub_minix_find_file (data, symlink);
  if (grub_errno)
    grub_error (grub_errno, "cannot follow symlink `%s'", symlink);

  return grub_errno;
}


/* Find the file with the pathname PATH on the filesystem described by
   DATA.  */
static grub_err_t
grub_minix_find_file (struct grub_minix_data *data, const char *path)
{
  char fpath[grub_strlen (path) + 1];
  char *name = fpath;
  char *next;
  unsigned int pos = 0;
  int dirino;

  grub_strcpy (fpath, path);

  /* Skip the first slash.  */
  if (name[0] == '/')
    {
      name++;
      if (!*name)
	return 0;
    }

  /* Extract the actual part from the pathname.  */
  next = grub_strchr (name, '/');
  if (next)
    {
      next[0] = '\0';
      next++;
    }

  do
    {
      grub_uint16_t ino;
      char filename[data->filename_size + 1];

      if (grub_strlen (name) == 0)
	return GRUB_ERR_NONE;

      if (grub_minix_read_file (data, 0, 0, pos, sizeof (ino),
				(char *) &ino) < 0)
	return grub_errno;
      if (grub_minix_read_file (data, 0, 0, pos + sizeof (ino),
				data->filename_size, (char *) filename)< 0)
	return grub_errno;

      filename[data->filename_size] = '\0';

      /* Check if the current direntry matches the current part of the
	 pathname.  */
      if (!grub_strcmp (name, filename))
	{
	  dirino = data->ino;
	  grub_minix_read_inode (data, grub_le_to_cpu16 (ino));

	  /* Follow the symlink.  */
	  if ((GRUB_MINIX_INODE_MODE (data)
	       & GRUB_MINIX_IFLNK) == GRUB_MINIX_IFLNK)
	    {
	      grub_minix_lookup_symlink (data, dirino);
	      if (grub_errno)
		return grub_errno;
	    }

	  if (!next)
	    return 0;

	  pos = 0;

	  name = next;
	  next = grub_strchr (name, '/');
	  if (next)
	    {
	      next[0] = '\0';
	      next++;
	    }

     	  if ((GRUB_MINIX_INODE_MODE (data)
	       & GRUB_MINIX_IFDIR) != GRUB_MINIX_IFDIR)
	    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");

	  continue;
	}

      pos += sizeof (ino) + data->filename_size;
    } while (pos < GRUB_MINIX_INODE_SIZE (data));

  grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
  return grub_errno;
}


/* Mount the filesystem on the disk DISK.  */
static struct grub_minix_data *
grub_minix_mount (grub_disk_t disk)
{
  struct grub_minix_data *data;

  data = grub_malloc (sizeof (struct grub_minix_data));
  if (!data)
    return 0;

  /* Read the superblock.  */
  grub_disk_read (disk, GRUB_MINIX_SBLOCK, 0,
		  sizeof (struct grub_minix_sblock),&data->sblock);
  if (grub_errno)
    goto fail;

  if (grub_le_to_cpu16 (data->sblock.magic) == GRUB_MINIX_MAGIC)
    {
      data->version = 1;
      data->filename_size = 14;
    }
  else if (grub_le_to_cpu16 (data->sblock.magic) == GRUB_MINIX2_MAGIC)
    {
      data->version = 2;
      data->filename_size = 14;
    }
  else if (grub_le_to_cpu16 (data->sblock.magic) == GRUB_MINIX_MAGIC_30)
    {
      data->version = 1;
      data->filename_size = 30;
    }
  else if (grub_le_to_cpu16 (data->sblock.magic) == GRUB_MINIX2_MAGIC_30)
    {
      data->version = 2;
      data->filename_size = 30;
    }
  else
    goto fail;

  data->disk = disk;
  data->linknest = 0;

  return data;

 fail:
  grub_free (data);
  grub_error (GRUB_ERR_BAD_FS, "not a minix filesystem");
  return 0;
}

static grub_err_t
grub_minix_dir (grub_device_t device, const char *path,
		  int (*hook) (const char *filename,
			       const struct grub_dirhook_info *info,
			       void *closure),
		void *closure)
{
  struct grub_minix_data *data = 0;
  unsigned int pos = 0;

  data = grub_minix_mount (device->disk);
  if (!data)
    return grub_errno;

  grub_minix_read_inode (data, GRUB_MINIX_ROOT_INODE);
  if (grub_errno)
    goto fail;

  grub_minix_find_file (data, path);
  if (grub_errno)
    goto fail;

  if ((GRUB_MINIX_INODE_MODE (data) & GRUB_MINIX_IFDIR) != GRUB_MINIX_IFDIR)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
      goto fail;
    }

  if (hook)
  while (pos < GRUB_MINIX_INODE_SIZE (data))
    {
      grub_uint16_t ino;
      char filename[data->filename_size + 1];
      int dirino = data->ino;
      struct grub_dirhook_info info;
      grub_memset (&info, 0, sizeof (info));


      if (grub_minix_read_file (data, 0, 0, pos, sizeof (ino),
				(char *) &ino) < 0)
	return grub_errno;

      if (grub_minix_read_file (data, 0, 0, pos + sizeof (ino),
				data->filename_size,
				(char *) filename) < 0)
	return grub_errno;
      filename[data->filename_size] = '\0';

      /* The filetype is not stored in the dirent.  Read the inode to
	 find out the filetype.  This *REALLY* sucks.  */
      grub_minix_read_inode (data, grub_le_to_cpu16 (ino));
      info.dir = ((GRUB_MINIX_INODE_MODE (data)
		   & GRUB_MINIX_IFDIR) == GRUB_MINIX_IFDIR);
      if (hook (filename, &info, closure))
	break;

      /* Load the old inode back in.  */
      grub_minix_read_inode (data, dirino);

      pos += sizeof (ino) + data->filename_size;
    }

 fail:
  grub_free (data);
  return grub_errno;
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_minix_open (struct grub_file *file, const char *name)
{
  struct grub_minix_data *data;
  data = grub_minix_mount (file->device->disk);
  if (!data)
    return grub_errno;

  /* Open the inode op the root directory.  */
  grub_minix_read_inode (data, GRUB_MINIX_ROOT_INODE);
  if (grub_errno)
    {
      grub_free (data);
      return grub_errno;
    }

  if (!name || name[0] != '/')
    {
      grub_error (GRUB_ERR_BAD_FILENAME, "bad filename");
      return grub_errno;
    }

  /* Traverse the directory tree to the node that should be
     opened.  */
  grub_minix_find_file (data, name);
  if (grub_errno)
    {
      grub_free (data);
      return grub_errno;
    }

  file->data = data;
  file->size = GRUB_MINIX_INODE_SIZE (data);

  return GRUB_ERR_NONE;
}


static grub_ssize_t
grub_minix_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_minix_data *data =
    (struct grub_minix_data *) file->data;

  return grub_minix_read_file (data, file->read_hook, file->closure,
			       file->offset, len, buf);
}


static grub_err_t
grub_minix_close (grub_file_t file)
{
  grub_free (file->data);

  return GRUB_ERR_NONE;
}


static grub_err_t
grub_minix_label (grub_device_t device __attribute ((unused)),
		char **label __attribute ((unused)))
{
  return GRUB_ERR_NONE;
}



struct grub_fs grub_minix_fs =
{
    .name = "minix",
    .dir = grub_minix_dir,
    .open = grub_minix_open,
    .read = grub_minix_read,
    .close = grub_minix_close,
    .label = grub_minix_label,
    .next = 0
};

