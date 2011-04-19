/* affs.c - Amiga Fast FileSystem.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/fshelp.h>

/* The affs bootblock.  */
struct grub_affs_bblock
{
  grub_uint8_t type[3];
  grub_uint8_t flags;
  grub_uint32_t checksum;
  grub_uint32_t rootblock;
} __attribute__ ((packed));

/* Set if the filesystem is a AFFS filesystem.  Otherwise this is an
   OFS filesystem.  */
#define GRUB_AFFS_FLAG_FFS	1

/* The affs rootblock.  */
struct grub_affs_rblock
{
  grub_uint8_t type[4];
  grub_uint8_t unused1[8];
  grub_uint32_t htsize;
  grub_uint32_t unused2;
  grub_uint32_t checksum;
  grub_uint32_t hashtable[1];
} __attribute__ ((packed));

/* The second part of a file header block.  */
struct grub_affs_file
{
  grub_uint8_t unused1[12];
  grub_uint32_t size;
  grub_uint8_t unused2[104];
  grub_uint8_t namelen;
  grub_uint8_t name[30];
  grub_uint8_t unused3[33];
  grub_uint32_t next;
  grub_uint32_t parent;
  grub_uint32_t extension;
  grub_int32_t type;
} __attribute__ ((packed));

/* The location of `struct grub_affs_file' relative to the end of a
   file header block.  */
#define	GRUB_AFFS_FILE_LOCATION		200

/* The offset in both the rootblock and the file header block for the
   hashtable, symlink and block pointers (all synonyms).  */
#define GRUB_AFFS_HASHTABLE_OFFSET	24
#define GRUB_AFFS_BLOCKPTR_OFFSET	24
#define GRUB_AFFS_SYMLINK_OFFSET	24

#define GRUB_AFFS_SYMLINK_SIZE(blocksize) ((blocksize) - 225)

#define GRUB_AFFS_FILETYPE_DIR		-3
#define GRUB_AFFS_FILETYPE_REG		2
#define GRUB_AFFS_FILETYPE_SYMLINK	3


struct grub_fshelp_node
{
  struct grub_affs_data *data;
  int block;
  int size;
  int parent;
};

/* Information about a "mounted" affs filesystem.  */
struct grub_affs_data
{
  struct grub_affs_bblock bblock;
  struct grub_fshelp_node diropen;
  grub_disk_t disk;

  /* Blocksize in sectors.  */
  int blocksize;

  /* The number of entries in the hashtable.  */
  int htsize;
};

static grub_dl_t my_mod;


static grub_disk_addr_t
grub_affs_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  int links;
  grub_uint32_t pos;
  int block = node->block;
  struct grub_affs_file file;
  struct grub_affs_data *data = node->data;
  grub_uint32_t mod;

  /* Find the block that points to the fileblock we are looking up by
     following the chain until the right table is reached.  */
  for (links = grub_divmod64 (fileblock, data->htsize, &mod); links; links--)
    {
      grub_disk_read (data->disk, block + data->blocksize - 1,
		      data->blocksize * (GRUB_DISK_SECTOR_SIZE
					 - GRUB_AFFS_FILE_LOCATION),
		      sizeof (file), &file);
      if (grub_errno)
	return 0;

      block = grub_be_to_cpu32 (file.extension);
    }

  /* Translate the fileblock to the block within the right table.  */
  fileblock = mod;
  grub_disk_read (data->disk, block,
		  GRUB_AFFS_BLOCKPTR_OFFSET
		  + (data->htsize - fileblock - 1) * sizeof (pos),
		  sizeof (pos), &pos);
  if (grub_errno)
    return 0;

  return grub_be_to_cpu32 (pos);
}


/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_affs_read_file (grub_fshelp_node_t node,
		     void (*read_hook) (grub_disk_addr_t sector,
					unsigned offset, unsigned length,
					void *closure),
		     void *closure, int flags,
		     int pos, grub_size_t len, char *buf)
{
  return grub_fshelp_read_file (node->data->disk, node, read_hook, closure,
				flags, pos, len, buf, grub_affs_read_block,
				node->size, 0);
}


static struct grub_affs_data *
grub_affs_mount (grub_disk_t disk)
{
  struct grub_affs_data *data;
  grub_uint32_t *rootblock = 0;
  struct grub_affs_rblock *rblock;

  int checksum = 0;
  int checksumr = 0;
  int blocksize = 0;

  data = grub_malloc (sizeof (struct grub_affs_data));
  if (!data)
    return 0;

  /* Read the bootblock.  */
  grub_disk_read (disk, 0, 0, sizeof (struct grub_affs_bblock),
		  &data->bblock);
  if (grub_errno)
    goto fail;

  /* Make sure this is an affs filesystem.  */
  if (grub_strncmp ((char *) (data->bblock.type), "DOS", 3))
    {
      grub_error (GRUB_ERR_BAD_FS, "not an AFFS filesystem");
      goto fail;
    }

  /* Test if the filesystem is a OFS filesystem.  */
  if (! (data->bblock.flags & GRUB_AFFS_FLAG_FFS))
    {
      grub_error (GRUB_ERR_BAD_FS, "OFS not yet supported");
      goto fail;
    }

  /* Read the bootblock.  */
  grub_disk_read (disk, 0, 0, sizeof (struct grub_affs_bblock),
		  &data->bblock);
  if (grub_errno)
    goto fail;

  /* No sane person uses more than 8KB for a block.  At least I hope
     for that person because in that case this won't work.  */
  rootblock = grub_malloc (GRUB_DISK_SECTOR_SIZE * 16);
  if (!rootblock)
    goto fail;

  rblock = (struct grub_affs_rblock *) rootblock;

  /* Read the rootblock.  */
  grub_disk_read (disk, (disk->total_sectors >> 1) + blocksize, 0,
		  GRUB_DISK_SECTOR_SIZE * 16, rootblock);
  if (grub_errno)
    goto fail;

  /* The filesystem blocksize is not stored anywhere in the filesystem
     itself.  One way to determine it is reading blocks for the
     rootblock until the checksum is correct.  */
  checksumr = grub_be_to_cpu32 (rblock->checksum);
  rblock->checksum = 0;
  for (blocksize = 0; blocksize < 8; blocksize++)
    {
      grub_uint32_t *currblock = rootblock + GRUB_DISK_SECTOR_SIZE * blocksize;
      unsigned int i;

      for (i = 0; i < GRUB_DISK_SECTOR_SIZE / sizeof (*currblock); i++)
	checksum += grub_be_to_cpu32 (currblock[i]);

      if (checksumr == -checksum)
	break;
    }
  if (-checksum != checksumr)
    {
      grub_error (GRUB_ERR_BAD_FS, "AFFS blocksize couldn't be determined");
      goto fail;
    }
  blocksize++;

  data->blocksize = blocksize;
  data->disk = disk;
  data->htsize = grub_be_to_cpu32 (rblock->htsize);
  data->diropen.data = data;
  data->diropen.block = (disk->total_sectors >> 1);

  grub_free (rootblock);

  return data;

 fail:
  if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
    grub_error (GRUB_ERR_BAD_FS, "not an AFFS filesystem");

  grub_free (data);
  grub_free (rootblock);
  return 0;
}


static char *
grub_affs_read_symlink (grub_fshelp_node_t node)
{
  struct grub_affs_data *data = node->data;
  char *symlink;

  symlink = grub_malloc (GRUB_AFFS_SYMLINK_SIZE (data->blocksize));
  if (!symlink)
    return 0;

  grub_disk_read (data->disk, node->block, GRUB_AFFS_SYMLINK_OFFSET,
		  GRUB_AFFS_SYMLINK_SIZE (data->blocksize), symlink);
  if (grub_errno)
    {
      grub_free (symlink);
      return 0;
    }
  grub_dprintf ("affs", "Symlink: `%s'\n", symlink);
  return symlink;
}

struct grub_affs_iterate_dir_closure
{
  int (*hook) (const char *filename,
	       enum grub_fshelp_filetype filetype,
	       grub_fshelp_node_t node, void *closure);
  void *closure;
  struct grub_fshelp_node *node;
  struct grub_affs_data *data;
  struct grub_affs_file *file;
  grub_uint32_t *hashtable;
};

static int
grub_affs_create_node (const char *name, int block,
		       int size, int type,
		       struct grub_affs_iterate_dir_closure *c)
{
  struct grub_fshelp_node *node;

  node = grub_malloc (sizeof (*node));
  c->node = node;
  if (!node)
    {
      grub_free (c->hashtable);
      return 1;
    }

  node->data = c->data;
  node->size = size;
  node->block = block;
  node->parent = grub_be_to_cpu32 (c->file->parent);

  if (c->hook (name, type, node, c->closure))
    {
      grub_free (c->hashtable);
      return 1;
    }
  return 0;
}

static int
grub_affs_iterate_dir (grub_fshelp_node_t dir,
		       int (*hook) (const char *filename,
				    enum grub_fshelp_filetype filetype,
				    grub_fshelp_node_t node, void *closure),
		       void *closure)
{
  int i;
  struct grub_affs_file file;
  struct grub_affs_data *data = dir->data;
  grub_uint32_t *hashtable;
  struct grub_affs_iterate_dir_closure c;

  c.hook = hook;
  c.closure = closure;
  c.node = 0;
  c.data = data;
  c.file = &file;

  hashtable = grub_malloc (data->htsize * sizeof (*hashtable));
  c.hashtable = hashtable;
  if (!hashtable)
    return 1;

  grub_disk_read (data->disk, dir->block, GRUB_AFFS_HASHTABLE_OFFSET,
		  data->htsize * sizeof (*hashtable), (char *) hashtable);
  if (grub_errno)
    goto fail;

  /* Create the directory entries for `.' and `..'.  */
  if (grub_affs_create_node (".", dir->block, dir->size, GRUB_FSHELP_DIR, &c))
    return 1;
  if (grub_affs_create_node ("..", dir->parent ? dir->parent : dir->block,
			     dir->size, GRUB_FSHELP_DIR, &c))
    return 1;

  for (i = 0; i < data->htsize; i++)
    {
      enum grub_fshelp_filetype type;
      grub_uint64_t next;

      if (!hashtable[i])
	continue;

      /* Every entry in the hashtable can be chained.  Read the entire
	 chain.  */
      next = grub_be_to_cpu32 (hashtable[i]);

      while (next)
	{
	  grub_disk_read (data->disk, next + data->blocksize - 1,
			  data->blocksize * GRUB_DISK_SECTOR_SIZE
			  - GRUB_AFFS_FILE_LOCATION,
			  sizeof (file), (char *) &file);
	  if (grub_errno)
	    goto fail;

	  file.name[file.namelen] = '\0';

	  if ((int) grub_be_to_cpu32 (file.type) == GRUB_AFFS_FILETYPE_DIR)
	    type = GRUB_FSHELP_REG;
	  else if (grub_be_to_cpu32 (file.type) == GRUB_AFFS_FILETYPE_REG)
	    type = GRUB_FSHELP_DIR;
	  else if (grub_be_to_cpu32 (file.type) == GRUB_AFFS_FILETYPE_SYMLINK)
	    type = GRUB_FSHELP_SYMLINK;
	  else
	    type = GRUB_FSHELP_UNKNOWN;

	  if (grub_affs_create_node ((char *) (file.name), next,
				     grub_be_to_cpu32 (file.size), type, &c))
	    return 1;

	  next = grub_be_to_cpu32 (file.next);
	}
    }

  grub_free (hashtable);
  return 0;

 fail:
  grub_free (c.node);
  grub_free (hashtable);
  return 0;
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_affs_open (struct grub_file *file, const char *name)
{
  struct grub_affs_data *data;
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  data = grub_affs_mount (file->device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (name, &data->diropen, &fdiro, grub_affs_iterate_dir, 0,
			 grub_affs_read_symlink, GRUB_FSHELP_REG);
  if (grub_errno)
    goto fail;

  file->size = fdiro->size;
  data->diropen = *fdiro;
  grub_free (fdiro);

  file->data = data;
  file->offset = 0;

  return 0;

 fail:
  if (data && fdiro != &data->diropen)
    grub_free (fdiro);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


static grub_err_t
grub_affs_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}


/* Read LEN bytes data from FILE into BUF.  */
static grub_ssize_t
grub_affs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_affs_data *data =
    (struct grub_affs_data *) file->data;

  int size = grub_affs_read_file (&data->diropen, file->read_hook,
				  file->closure, file->flags,
				  file->offset, len, buf);

  return size;
}

struct grub_affs_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info, void *closure);
  void *closure;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node,
	 void *closure)
{
  struct grub_affs_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook?c->hook (filename, &info, c->closure):NULL;
}

static grub_err_t
grub_affs_dir (grub_device_t device, const char *path,
	       int (*hook) (const char *filename,
			    const struct grub_dirhook_info *info, void *closure),
	       void *closure)
{
  struct grub_affs_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;
  struct grub_affs_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_affs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (path, &data->diropen, &fdiro, grub_affs_iterate_dir, 0,
			 grub_affs_read_symlink, GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;

  c.hook = hook;
  c.closure = closure;
  grub_affs_iterate_dir (fdiro, iterate, &c);

 fail:
  if (data && fdiro != &data->diropen)
    grub_free (fdiro);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


static grub_err_t
grub_affs_label (grub_device_t device, char **label)
{
  struct grub_affs_data *data;
  struct grub_affs_file file;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_affs_mount (disk);
  if (data)
    {
      /* The rootblock maps quite well on a file header block, it's
	 something we can use here.  */
      grub_disk_read (data->disk, disk->total_sectors >> 1,
		      data->blocksize * (GRUB_DISK_SECTOR_SIZE
					 - GRUB_AFFS_FILE_LOCATION),
		      sizeof (file), &file);
      if (grub_errno)
	return 0;

      *label = grub_strndup ((char *) (file.name), file.namelen);
    }
  else
    *label = 0;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}


struct grub_fs grub_affs_fs =
  {
    .name = "affs",
    .dir = grub_affs_dir,
    .open = grub_affs_open,
    .read = grub_affs_read,
    .close = grub_affs_close,
    .label = grub_affs_label,
    .next = 0
  };
