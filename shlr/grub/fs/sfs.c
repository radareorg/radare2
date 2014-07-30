/* sfs.c - Amiga Smart FileSystem.  */
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

/* The common header for a block.  */
struct grub_sfs_bheader
{
  grub_uint8_t magic[4];
  grub_uint32_t chksum;
  grub_uint32_t ipointtomyself;
} __attribute__ ((packed));

/* The sfs rootblock.  */
struct grub_sfs_rblock
{
  struct grub_sfs_bheader header;
  grub_uint32_t version;
  grub_uint8_t unused1[36];
  grub_uint32_t blocksize;
  grub_uint8_t unused2[40];
  grub_uint8_t unused3[8];
  grub_uint32_t rootobject;
  grub_uint32_t btree;
} __attribute__ ((packed));

/* A SFS object container.  */
struct grub_sfs_obj
{
  grub_uint8_t unused1[4];
  grub_uint32_t nodeid;
  grub_uint8_t unused2[4];
  union
  {
    struct
    {
      grub_uint32_t first_block;
      grub_uint32_t size;
    } file __attribute__ ((packed));
    struct
    {
      grub_uint32_t hashtable;
      grub_uint32_t dir_objc;
    } dir __attribute__ ((packed));
  } file_dir;
  grub_uint8_t unused3[4];
  grub_uint8_t type;
  grub_uint8_t filename[1];
  grub_uint8_t comment[1];
} __attribute__ ((packed));

#define	GRUB_SFS_TYPE_DELETED	32
#define	GRUB_SFS_TYPE_SYMLINK	64
#define	GRUB_SFS_TYPE_DIR	128

/* A SFS object container.  */
struct grub_sfs_objc
{
  struct grub_sfs_bheader header;
  grub_uint32_t parent;
  grub_uint32_t next;
  grub_uint32_t prev;
  /* The amount of objects depends on the blocksize.  */
  struct grub_sfs_obj objects[1];
} __attribute__ ((packed));

struct grub_sfs_btree_node
{
  grub_uint32_t key;
  grub_uint32_t data;
} __attribute__ ((packed));

struct grub_sfs_btree_extent
{
  grub_uint32_t key;
  grub_uint32_t next;
  grub_uint32_t prev;
  grub_uint16_t size;
} __attribute__ ((packed));

struct grub_sfs_btree
{
  struct grub_sfs_bheader header;
  grub_uint16_t nodes;
  grub_uint8_t leaf;
  grub_uint8_t nodesize;
  /* Normally this can be kind of node, but just extents are
     supported.  */
  struct grub_sfs_btree_node node[1];
} __attribute__ ((packed));



struct grub_fshelp_node
{
  struct grub_sfs_data *data;
  int block;
  int size;
};

/* Information about a "mounted" sfs filesystem.  */
struct grub_sfs_data
{
  struct grub_sfs_rblock rblock;
  struct grub_fshelp_node diropen;
  grub_disk_t disk;

  /* Blocksize in sectors.  */
  unsigned int blocksize;

  /* Label of the filesystem.  */
  char *label;
};

static grub_dl_t my_mod;


/* Lookup the extent starting with BLOCK in the filesystem described
   by DATA.  Return the extent size in SIZE and the following extent
   in NEXTEXT.  */
static grub_err_t
grub_sfs_read_extent (struct grub_sfs_data *data, unsigned int block,
		      int *size, int *nextext)
{
  char *treeblock;
  struct grub_sfs_btree *tree;
  int i;
  int next;

  if (!block)
    return 0;

  treeblock = grub_malloc (data->blocksize);

  next = grub_be_to_cpu32 (data->rblock.btree);
  tree = (struct grub_sfs_btree *) treeblock;

  /* Handle this level in the btree.  */
  do
    {
      grub_disk_read (data->disk, next, 0, data->blocksize, treeblock);
      if (grub_errno)
	{
	  grub_free (treeblock);
	  return grub_errno;
	}

      for (i = grub_be_to_cpu16 (tree->nodes) - 1; i >= 0; i--)
	{

#define EXTNODE(tree, index)						\
	((struct grub_sfs_btree_node *) (((char *) &(tree)->node[0])	\
					 + (index) * (tree)->nodesize))

	  /* Follow the tree down to the leaf level.  */
	  if ((grub_be_to_cpu32 (EXTNODE(tree, i)->key) <= block)
	      && !tree->leaf)
	    {
	      next = grub_be_to_cpu32 (EXTNODE (tree, i)->data);
	      break;
	    }

	  /* If the leaf level is reached, just find the correct extent.  */
	  if (grub_be_to_cpu32 (EXTNODE (tree, i)->key) == block && tree->leaf)
	    {
	      struct grub_sfs_btree_extent *extent;
	      extent = (struct grub_sfs_btree_extent *) EXTNODE (tree, i);

	      /* We found a correct leaf.  */
	      *size = grub_be_to_cpu16 (extent->size);
	      *nextext = grub_be_to_cpu32 (extent->next);

	      grub_free (treeblock);
	      return 0;
	    }

#undef EXTNODE

	}
    } while (!tree->leaf);

  grub_free (treeblock);

  return grub_error (GRUB_ERR_FILE_READ_ERROR, "SFS extent not found");
}

static grub_disk_addr_t
grub_sfs_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  int blk = node->block;
  int size = 0;
  int next = 0;

  while (blk)
    {
      grub_err_t err;

      /* In case of the first block we don't have to lookup the
	 extent, the minimum size is always 1.  */
      if (fileblock == 0)
	return blk;

      err = grub_sfs_read_extent (node->data, blk, &size, &next);
      if (err)
	return 0;

      if (fileblock < (unsigned int) size)
	return fileblock + blk;

      fileblock -= size;

      blk = next;
    }

  grub_error (GRUB_ERR_FILE_READ_ERROR,
	      "reading a SFS block outside the extent");

  return 0;
}


/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_sfs_read_file (grub_fshelp_node_t node,
		    void (*read_hook) (grub_disk_addr_t sector,
				       unsigned offset, unsigned length,
				       void *closure),
		    void *closure, int flags,
		    int pos, grub_size_t len, char *buf)
{
  return grub_fshelp_read_file (node->data->disk, node, read_hook, closure,
				flags, pos, len, buf, grub_sfs_read_block,
				node->size, 0);
}


static struct grub_sfs_data *
grub_sfs_mount (grub_disk_t disk)
{
  struct grub_sfs_data *data;
  struct grub_sfs_objc *rootobjc;
  char *rootobjc_data = 0;
  unsigned int blk;

  data = grub_malloc (sizeof (*data));
  if (!data)
    return 0;

  /* Read the rootblock.  */
  grub_disk_read (disk, 0, 0, sizeof (struct grub_sfs_rblock),
		  &data->rblock);
  if (grub_errno)
    goto fail;

  /* Make sure this is a sfs filesystem.  */
  if (grub_strncmp ((char *) (data->rblock.header.magic), "SFS", 4))
    {
      grub_error (GRUB_ERR_BAD_FS, "not a SFS filesystem");
      goto fail;
    }

  data->blocksize = grub_be_to_cpu32 (data->rblock.blocksize);
  rootobjc_data = grub_malloc (data->blocksize);
  if (! rootobjc_data)
    goto fail;

  /* Read the root object container.  */
  grub_disk_read (disk, grub_be_to_cpu32 (data->rblock.rootobject), 0,
		  data->blocksize, rootobjc_data);
  if (grub_errno)
    goto fail;

  rootobjc = (struct grub_sfs_objc *) rootobjc_data;

  blk = grub_be_to_cpu32 (rootobjc->objects[0].file_dir.dir.dir_objc);
  data->diropen.size = 0;
  data->diropen.block = blk;
  data->diropen.data = data;
  data->disk = disk;
  data->label = grub_strdup ((char *) (rootobjc->objects[0].filename));

  return data;

 fail:
  if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
    grub_error (GRUB_ERR_BAD_FS, "not an SFS filesystem");

  grub_free (data);
  grub_free (rootobjc_data);
  return 0;
}


static char *
grub_sfs_read_symlink (grub_fshelp_node_t node)
{
  struct grub_sfs_data *data = node->data;
  char *symlink;
  char *block;

  block = grub_malloc (data->blocksize);
  if (!block)
    return 0;

  grub_disk_read (data->disk, node->block, 0, data->blocksize, block);
  if (grub_errno)
    {
      grub_free (block);
      return 0;
    }

  /* This is just a wild guess, but it always worked for me.  How the
     SLNK block looks like is not documented in the SFS docs.  */
  symlink = grub_strdup (&block[24]);
  grub_free (block);
  if (!symlink)
    return 0;

  return symlink;
}

static int
grub_sfs_create_node (const char *name, int block,
		      int size, int type,
		      struct grub_sfs_data *data,
		      int (*hook) (const char *filename,
				   enum grub_fshelp_filetype filetype,
				   grub_fshelp_node_t node, void *closure),
		      void *closure)
{
  struct grub_fshelp_node *node;

  node = grub_malloc (sizeof (*node));
  if (!node)
    return 1;

  node->data = data;
  node->size = size;
  node->block = block;

  return hook (name, type, node, closure);
}

static int
grub_sfs_iterate_dir (grub_fshelp_node_t dir,
		      int (*hook) (const char *filename,
				   enum grub_fshelp_filetype filetype,
				   grub_fshelp_node_t node, void *closure),
		      void *closure)
{
  struct grub_sfs_data *data = dir->data;
  char *objc_data;
  struct grub_sfs_objc *objc;
  unsigned int next = dir->block;
  int pos;

  objc_data = grub_malloc (data->blocksize);
  if (!objc_data)
    goto fail;

  /* The Object container can consist of multiple blocks, iterate over
     every block.  */
  while (next)
    {
      grub_disk_read (data->disk, next, 0, data->blocksize, objc_data);
      if (grub_errno)
	goto fail;

      objc = (struct grub_sfs_objc *) objc_data;

      pos = (char *) &objc->objects[0] - (char *) objc;

      /* Iterate over all entries in this block.  */
      while (pos + sizeof (struct grub_sfs_obj) < data->blocksize)
	{
	  struct grub_sfs_obj *obj;
	  obj = (struct grub_sfs_obj *) ((char *) objc + pos);
	  char *filename = (char *) (obj->filename);
	  int len;
	  enum grub_fshelp_filetype type;
	  unsigned int block;

	  /* The filename and comment dynamically increase the size of
	     the object.  */
	  len = grub_strlen (filename);
	  len += grub_strlen (filename + len + 1);

	  pos += sizeof (*obj) + len;
	  /* Round up to a multiple of two bytes.  */
	  pos = ((pos + 1) >> 1) << 1;

	  if (grub_strlen (filename) == 0)
	    continue;

	  /* First check if the file was not deleted.  */
	  if (obj->type & GRUB_SFS_TYPE_DELETED)
	    continue;
	  else if (obj->type & GRUB_SFS_TYPE_SYMLINK)
	    type = GRUB_FSHELP_SYMLINK;
	  else if (obj->type & GRUB_SFS_TYPE_DIR)
	    type = GRUB_FSHELP_DIR;
	  else
	    type = GRUB_FSHELP_REG;

	  if (type == GRUB_FSHELP_DIR)
	    block = grub_be_to_cpu32 (obj->file_dir.dir.dir_objc);
	  else
	    block = grub_be_to_cpu32 (obj->file_dir.file.first_block);

	  if (grub_sfs_create_node (filename, block,
				    grub_be_to_cpu32 (obj->file_dir.file.size),
				    type, data, hook, closure))
	    {
	      grub_free (objc_data);
	      return 1;
	    }
	}

      next = grub_be_to_cpu32 (objc->next);
    }

 fail:
  grub_free (objc_data);
  return 0;
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_sfs_open (struct grub_file *file, const char *name)
{
  struct grub_sfs_data *data;
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  data = grub_sfs_mount (file->device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (name, &data->diropen, &fdiro, grub_sfs_iterate_dir, 0,
			 grub_sfs_read_symlink, GRUB_FSHELP_REG);
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
  if (data)
    grub_free (data->label);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


static grub_err_t
grub_sfs_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}


/* Read LEN bytes data from FILE into BUF.  */
static grub_ssize_t
grub_sfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_sfs_data *data = (struct grub_sfs_data *) file->data;

  int size = grub_sfs_read_file (&data->diropen, file->read_hook,
				 file->closure, file->flags,
				 file->offset, len, buf);

  return size;
}

struct grub_sfs_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info,
	       void *closure);
  void *closure;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node,
	 void *closure)
{
  struct grub_sfs_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook? c->hook (filename, &info, c->closure):0;
}

static grub_err_t
grub_sfs_dir (grub_device_t device, const char *path,
	      int (*hook) (const char *filename,
			   const struct grub_dirhook_info *info,
			   void *closure),
	      void *closure)
{
  struct grub_sfs_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;
  struct grub_sfs_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_sfs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (path, &data->diropen, &fdiro, grub_sfs_iterate_dir, 0,
			grub_sfs_read_symlink, GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;

  c.hook = hook;
  c.closure = closure;
  grub_sfs_iterate_dir (fdiro, iterate, &c);

 fail:
  if (data && fdiro != &data->diropen)
    grub_free (fdiro);
  if (data)
    grub_free (data->label);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


static grub_err_t
grub_sfs_label (grub_device_t device, char **label)
{
  struct grub_sfs_data *data;
  grub_disk_t disk = device->disk;

  data = grub_sfs_mount (disk);
  if (data)
    *label = data->label;

  grub_free (data);

  return grub_errno;
}


struct grub_fs grub_sfs_fs =
  {
    .name = "sfs",
    .dir = grub_sfs_dir,
    .open = grub_sfs_open,
    .read = grub_sfs_read,
    .close = grub_sfs_close,
    .label = grub_sfs_label,
    .next = 0
  };

