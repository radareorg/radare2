/* afs.c - The native AtheOS file-system.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008,2009  Free Software Foundation, Inc.
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

#ifdef MODE_BIGENDIAN
#define GRUB_AFS_FSNAME_SUFFIX "_be"
#else
#define GRUB_AFS_FSNAME_SUFFIX ""
#endif

#ifdef MODE_BFS
#define GRUB_AFS_FSNAME "befs" GRUB_AFS_FSNAME_SUFFIX
#else
#define GRUB_AFS_FSNAME "afs" GRUB_AFS_FSNAME_SUFFIX
#endif

#define	GRUB_AFS_DIRECT_BLOCK_COUNT	12
#define	GRUB_AFS_BLOCKS_PER_DI_RUN	4

#ifdef MODE_BFS
#define GRUB_AFS_SBLOCK_SECTOR 1
#define	GRUB_AFS_SBLOCK_MAGIC1	0x42465331 /* BFS1.  */
#else
#define GRUB_AFS_SBLOCK_SECTOR 2
#define	GRUB_AFS_SBLOCK_MAGIC1	0x41465331 /* AFS1.  */
#endif

#define	GRUB_AFS_SBLOCK_MAGIC2	0xdd121031
#define	GRUB_AFS_SBLOCK_MAGIC3	0x15b6830e

#define	GRUB_AFS_INODE_MAGIC	0x64358428

#ifdef MODE_BFS
#define GRUB_AFS_BTREE_MAGIC	0x69f6c2e8
#else
#define GRUB_AFS_BTREE_MAGIC	0x65768995
#endif

#define GRUB_AFS_BNODE_SIZE	1024

#define GRUB_AFS_S_IFMT		00170000
#define GRUB_AFS_S_IFLNK	0120000

#define GRUB_AFS_S_IFREG	0100000
#define GRUB_AFS_S_IFDIR	0040000
#define GRUB_AFS_S_IFIFO	0010000

#define GRUB_AFS_NULL_VAL	((grub_afs_bvalue_t)-1)

#ifdef MODE_BIGENDIAN
#define grub_afs_to_cpu16(x) grub_be_to_cpu16 (x)
#define grub_afs_to_cpu32(x) grub_be_to_cpu32 (x)
#define grub_afs_to_cpu64(x) grub_be_to_cpu64 (x)
#else
#define grub_afs_to_cpu16(x) grub_le_to_cpu16 (x)
#define grub_afs_to_cpu32(x) grub_le_to_cpu32 (x)
#define grub_afs_to_cpu64(x) grub_le_to_cpu64 (x)
#endif

#ifdef MODE_BFS
#define B_KEY_INDEX_ALIGN 8
#else
#define B_KEY_INDEX_ALIGN 4
#endif

#define B_KEY_INDEX_OFFSET(node) ((grub_uint16_t *) \
				  ((char *) (node) \
				   + ALIGN_UP (sizeof (struct grub_afs_bnode) \
					       + node->key_size, \
					       B_KEY_INDEX_ALIGN)))

#define B_KEY_VALUE_OFFSET(node) ((grub_afs_bvalue_t *) \
                                   ((char *) B_KEY_INDEX_OFFSET (node) + \
                                    node->key_count * 2))

typedef grub_uint64_t grub_afs_off_t;
typedef grub_uint64_t grub_afs_bigtime;
typedef grub_uint64_t grub_afs_bvalue_t;

struct grub_afs_blockrun
{
  grub_uint32_t group;
  grub_uint16_t start;
  grub_uint16_t len;
} __attribute__ ((packed));

struct grub_afs_datastream
{
  struct grub_afs_blockrun direct[GRUB_AFS_DIRECT_BLOCK_COUNT];
  grub_afs_off_t max_direct_range;
  struct grub_afs_blockrun indirect;
  grub_afs_off_t max_indirect_range;
  struct grub_afs_blockrun double_indirect;
  grub_afs_off_t max_double_indirect_range;
  grub_afs_off_t size;
} __attribute__ ((packed));

struct grub_afs_bnode
{
  grub_afs_bvalue_t left;
  grub_afs_bvalue_t right;
  grub_afs_bvalue_t overflow;
#ifdef MODE_BFS
  grub_uint16_t key_count;
  grub_uint16_t key_size;
#else
  grub_uint32_t key_count;
  grub_uint32_t key_size;
#endif
  char key_data[0];
} __attribute__ ((packed));

#ifdef MODE_BFS
struct grub_afs_btree
{
  grub_uint32_t magic;
  grub_uint32_t unused1;
  grub_uint32_t tree_depth;
  grub_uint32_t unused2;
  grub_afs_bvalue_t root;
  grub_uint32_t unused3[4];
} __attribute__ ((packed));
#else
struct grub_afs_btree
{
  grub_uint32_t magic;
  grub_afs_bvalue_t root;
  grub_uint32_t tree_depth;
  grub_afs_bvalue_t last_node;
  grub_afs_bvalue_t first_free;
} __attribute__ ((packed));
#endif

/* Beware that following structure describes AtheFS and if you write code
   which uses currently unused fields check it with both AtheFS and BeFS.
 */
struct grub_afs_sblock
{
  char name[32];
  grub_uint32_t magic1;
  grub_uint32_t byte_order;
  grub_uint32_t	block_size;
  grub_uint32_t block_shift;
  grub_afs_off_t num_blocks;
  grub_afs_off_t used_blocks;
  grub_uint32_t	inode_size;
  grub_uint32_t	magic2;
  grub_uint32_t	block_per_group; /* Number of blocks per allocation
				    group. (Max 65536)  */
  grub_uint32_t	alloc_group_shift; /* Number of bits to shift a group
				      number to get a byte address.  */
  grub_uint32_t	alloc_group_count;
  grub_uint32_t	flags;
  struct grub_afs_blockrun log_block;
  grub_afs_off_t log_start;
  grub_uint32_t valid_log_blocks;
  grub_uint32_t log_size;
  grub_uint32_t	magic3;
  struct grub_afs_blockrun root_dir; /* Root dir inode.  */
  struct grub_afs_blockrun deleted_files; /* Directory containing files
					     scheduled for deletion.  */
  struct grub_afs_blockrun index_dir; /* Directory of index files.  */
  grub_uint32_t boot_loader_size;
  grub_uint32_t	pad[7];
}  __attribute__ ((packed));

struct grub_afs_inode
{
  grub_uint32_t magic1;
  struct grub_afs_blockrun inode_num;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t mode;
  grub_uint32_t flags;
#ifndef MODE_BFS
  grub_uint32_t link_count;
#endif
  grub_afs_bigtime create_time;
  grub_afs_bigtime modified_time;
  struct grub_afs_blockrun parent;
  struct grub_afs_blockrun attrib_dir;
  grub_uint32_t index_type; /* Key data-key only used for index files. */
  grub_uint32_t inode_size;
  grub_uint32_t unused;
  struct grub_afs_datastream stream;
  grub_uint32_t	pad[4];
  grub_uint32_t small_data[1];
} __attribute__ ((packed));

struct grub_fshelp_node
{
  struct grub_afs_data *data;
  struct grub_afs_inode inode;
};

struct grub_afs_data
{
  grub_disk_t disk;
  struct grub_afs_sblock sblock;
  struct grub_afs_inode *inode;
  struct grub_fshelp_node diropen;
};

static grub_dl_t my_mod;

static grub_afs_off_t
grub_afs_run_to_num (struct grub_afs_sblock *sb,
                     struct grub_afs_blockrun *run)
{
  return ((grub_afs_off_t) grub_afs_to_cpu32 (run->group)
	  * sb->block_per_group + grub_afs_to_cpu16 (run->start));
}

static grub_err_t
grub_afs_read_inode (struct grub_afs_data *data,
                     grub_uint32_t ino, struct grub_afs_inode *inode)
{
  return grub_disk_read (data->disk,
                         ino *
                         (data->sblock.block_size >> GRUB_DISK_SECTOR_BITS),
                         0, sizeof (struct grub_afs_inode),
                         inode);
}

static grub_disk_addr_t
grub_afs_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  struct grub_afs_sblock *sb = &node->data->sblock;
  struct grub_afs_datastream *ds = &node->inode.stream;

  if (fileblock < grub_afs_to_cpu64 (ds->max_direct_range))
    {
      int i;

      for (i = 0; i < GRUB_AFS_DIRECT_BLOCK_COUNT; i++)
        {
          if (fileblock < grub_afs_to_cpu16 (ds->direct[i].len))
            return grub_afs_run_to_num (sb, &ds->direct[i]) + fileblock;
          fileblock -= grub_afs_to_cpu16 (ds->direct[i].len);
        }
    }
  else if (fileblock < grub_afs_to_cpu64 (ds->max_indirect_range))
    {
      int ptrs_per_blk = sb->block_size / sizeof (struct grub_afs_blockrun);
      struct grub_afs_blockrun indir[ptrs_per_blk];
      grub_afs_off_t blk = grub_afs_run_to_num (sb, &ds->indirect);
      int i;

      fileblock -= grub_afs_to_cpu64 (ds->max_direct_range);
      for (i = 0; i < ds->indirect.len; i++, blk++)
        {
          int j;

          if (grub_disk_read (node->data->disk,
                              blk * (sb->block_size >> GRUB_DISK_SECTOR_BITS),
                              0, sizeof (indir),
                              indir))
            return 0;

          for (j = 0; j < ptrs_per_blk; j++)
            {
              if (fileblock < grub_afs_to_cpu16 (indir[j].len))
                return grub_afs_run_to_num (sb, &indir[j]) + fileblock;

              fileblock -= grub_afs_to_cpu16 (indir[j].len);
            }
        }
    }
  else
    {
      int ptrs_per_blk = sb->block_size / sizeof (struct grub_afs_blockrun);
      struct grub_afs_blockrun indir[ptrs_per_blk];

      /* ([idblk][idptr]) ([dblk][dptr]) [blk]  */
      int cur_pos = fileblock - grub_afs_to_cpu64 (ds->max_indirect_range);

      int dptr_size = GRUB_AFS_BLOCKS_PER_DI_RUN;
      int dblk_size = dptr_size * ptrs_per_blk;
      int idptr_size = dblk_size * GRUB_AFS_BLOCKS_PER_DI_RUN;
      int idblk_size = idptr_size * ptrs_per_blk;

      int off = cur_pos % GRUB_AFS_BLOCKS_PER_DI_RUN;
      int dptr = (cur_pos / dptr_size) % ptrs_per_blk;
      int dblk = (cur_pos / dblk_size) % GRUB_AFS_BLOCKS_PER_DI_RUN;
      int idptr = (cur_pos / idptr_size) % ptrs_per_blk;
      int idblk = (cur_pos / idblk_size);

      if (grub_disk_read (node->data->disk,
                          (grub_afs_run_to_num (sb, &ds->double_indirect)
                           + idblk) *
                          (sb->block_size >> GRUB_DISK_SECTOR_BITS),
                          0, sizeof (indir),
                          indir))
        return 0;

      if (grub_disk_read (node->data->disk,
                          (grub_afs_run_to_num (sb, &indir[idptr]) + dblk) *
                          (sb->block_size >> GRUB_DISK_SECTOR_BITS),
                          0, sizeof (indir),
                          indir))
        return 0;

      return grub_afs_run_to_num (sb, &indir[dptr]) + off;
    }

  return 0;
}

static grub_ssize_t
grub_afs_read_file (grub_fshelp_node_t node,
                    void (*read_hook) (grub_disk_addr_t sector,
				       unsigned offset, unsigned length,
				       void *closure),
		    void *closure, int flags,
                    int pos, grub_size_t len, char *buf)
{
  return grub_fshelp_read_file (node->data->disk, node, read_hook, closure,
				flags, pos, len, buf, grub_afs_read_block,
                                grub_afs_to_cpu64 (node->inode.stream.size),
				node->data->sblock.block_shift
                                - GRUB_DISK_SECTOR_BITS);
}

static char *
grub_afs_read_symlink (grub_fshelp_node_t node)
{
  char *ret;
  grub_afs_off_t size = grub_afs_to_cpu64 (node->inode.stream.size);

  if (size == 0)
    {
      size = sizeof (node->inode.stream);
      ret = grub_zalloc (size + 1);
      if (! ret)
	return 0;
      grub_memcpy (ret, (char *) &(node->inode.stream),
		   sizeof (node->inode.stream));
      return ret;
    }
  ret = grub_zalloc (size + 1);
  if (! ret)
    return 0;
  grub_afs_read_file (node, 0, 0, 0, 0, size, ret);
  return ret;
}

static int
grub_afs_iterate_dir (grub_fshelp_node_t dir,
                      int (*hook) (const char *filename,
				   enum grub_fshelp_filetype filetype,
				   grub_fshelp_node_t node, void *closure),
		      void *closure)
{
  struct grub_afs_btree head;
  char node_data [GRUB_AFS_BNODE_SIZE];
  struct grub_afs_bnode *node = (struct grub_afs_bnode *) node_data;
  int i;

  if ((dir->inode.stream.size == 0)
      || ((grub_afs_to_cpu32 (dir->inode.mode) & GRUB_AFS_S_IFMT)
	  != GRUB_AFS_S_IFDIR))
    return 0;

  grub_afs_read_file (dir, 0, 0, 0, 0, sizeof (head), (char *) &head);
  if (grub_errno)
    return 0;

  grub_afs_read_file (dir, 0, 0, 0, grub_afs_to_cpu64 (head.root),
                      GRUB_AFS_BNODE_SIZE, (char *) node);
  if (grub_errno)
    return 0;

  for (i = 0; i < (int) grub_afs_to_cpu32 (head.tree_depth) - 1; i++)
    {
      grub_afs_bvalue_t blk;

      blk = grub_afs_to_cpu64(B_KEY_VALUE_OFFSET (node) [0]);
      grub_afs_read_file (dir, 0, 0, 0, blk, GRUB_AFS_BNODE_SIZE, (char *) node);
      if (grub_errno)
        return 0;
    }

  if (node->key_count)
    {
      grub_uint32_t cur_key = 0;

      while (1)
        {
          int key_start, key_size;
          grub_uint16_t *index;

          index = B_KEY_INDEX_OFFSET (node);

	  key_start = (cur_key > 0)
	    ? grub_afs_to_cpu16 (index[cur_key - 1]) : 0;
          key_size = grub_afs_to_cpu16 (index[cur_key]) - key_start;
          if (key_size > 0)
            {
              char filename [key_size + 1];
              struct grub_fshelp_node *fdiro;
              int mode, type;

              fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
              if (! fdiro)
                return 0;

              fdiro->data = dir->data;
              if (grub_afs_read_inode (dir->data,
                                       grub_afs_to_cpu64
				       (B_KEY_VALUE_OFFSET (node) [cur_key]),
                                       &fdiro->inode))
                return 0;

              grub_memcpy (filename, &node->key_data[key_start], key_size);
              filename [key_size] = 0;

              mode = (grub_afs_to_cpu32 (fdiro->inode.mode) & GRUB_AFS_S_IFMT);
              if (mode == GRUB_AFS_S_IFDIR)
                type = GRUB_FSHELP_DIR;
              else if (mode == GRUB_AFS_S_IFREG)
                type = GRUB_FSHELP_REG;
	      else if (mode == GRUB_AFS_S_IFLNK)
		type = GRUB_FSHELP_SYMLINK;
              else
                type = GRUB_FSHELP_UNKNOWN;

              if (hook (filename, type, fdiro, closure))
                return 1;
            }

          cur_key++;
          if (cur_key >= grub_afs_to_cpu32 (node->key_count))
            {
              if (node->right == GRUB_AFS_NULL_VAL)
                break;

              grub_afs_read_file (dir, 0, 0, 0, grub_afs_to_cpu64 (node->right),
                                  GRUB_AFS_BNODE_SIZE, (char *) node);
              if (grub_errno)
                return 0;

              cur_key = 0;
            }
        }
    }

  return 0;
}

static int
grub_afs_validate_sblock (struct grub_afs_sblock *sb)
{
  if (grub_afs_to_cpu32 (sb->magic1) == GRUB_AFS_SBLOCK_MAGIC1)
    {
      sb->magic2 = grub_afs_to_cpu32 (sb->magic2);
      sb->magic3 = grub_afs_to_cpu32 (sb->magic3);
      sb->block_shift = grub_afs_to_cpu32 (sb->block_shift);
      sb->block_size = grub_afs_to_cpu32 (sb->block_size);
      sb->used_blocks = grub_afs_to_cpu64 (sb->used_blocks);
      sb->num_blocks = grub_afs_to_cpu64 (sb->num_blocks);
      sb->inode_size = grub_afs_to_cpu32 (sb->inode_size);
      sb->alloc_group_count = grub_afs_to_cpu32 (sb->alloc_group_count);
      sb->alloc_group_shift = grub_afs_to_cpu32 (sb->alloc_group_shift);
      sb->block_per_group = grub_afs_to_cpu32 (sb->block_per_group);
      sb->alloc_group_count = grub_afs_to_cpu32 (sb->alloc_group_count);
      sb->log_size = grub_afs_to_cpu32 (sb->log_size);
    }
  else
    return 0;

  if ((sb->magic2 != GRUB_AFS_SBLOCK_MAGIC2) ||
      (sb->magic3 != GRUB_AFS_SBLOCK_MAGIC3))
    return 0;

#ifdef MODE_BFS
  sb->block_per_group = 1 << (sb->alloc_group_shift);
#endif

  if (((grub_uint32_t) (1 << sb->block_shift) != sb->block_size)
      || (sb->used_blocks > sb->num_blocks )
      || (sb->inode_size != sb->block_size)
      || (0 == sb->block_size)
#ifndef MODE_BFS
      || ((grub_uint32_t) (1 << sb->alloc_group_shift) !=
	  sb->block_per_group * sb->block_size)
      || (sb->alloc_group_count * sb->block_per_group < sb->num_blocks)
      || (grub_afs_to_cpu16 (sb->log_block.len) != sb->log_size)
      || (grub_afs_to_cpu32 (sb->valid_log_blocks) > sb->log_size)
#endif
      )
    return 0;

  return 1;
}

static struct grub_afs_data *
grub_afs_mount (grub_disk_t disk)
{
  struct grub_afs_data *data = 0;

  data = grub_malloc (sizeof (struct grub_afs_data));
  if (!data)
    return 0;

  /* Read the superblock.  */
  if (grub_disk_read (disk, GRUB_AFS_SBLOCK_SECTOR, 0,
		      sizeof (struct grub_afs_sblock), &data->sblock))
    goto fail;

  if (! grub_afs_validate_sblock (&data->sblock))
    goto fail;

  data->diropen.data = data;
  data->inode = &data->diropen.inode;
  data->disk = disk;

  if (grub_afs_read_inode (data,
                           grub_afs_run_to_num (&data->sblock,
                                                &data->sblock.root_dir),
                           data->inode))
    goto fail;

  return data;

fail:
  grub_error (GRUB_ERR_BAD_FS, "not an " GRUB_AFS_FSNAME " filesystem");

  grub_free (data);
  return 0;
}

static grub_err_t
grub_afs_open (struct grub_file *file, const char *name)
{
  struct grub_afs_data *data;
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  data = grub_afs_mount (file->device->disk);
  if (! data)
    goto fail;

  grub_fshelp_find_file (name, &data->diropen, &fdiro, grub_afs_iterate_dir, 0,
			 grub_afs_read_symlink, GRUB_FSHELP_REG);
  if (grub_errno)
    goto fail;

  grub_memcpy (data->inode, &fdiro->inode, sizeof (struct grub_afs_inode));
  grub_free (fdiro);

  file->size = grub_afs_to_cpu64 (data->inode->stream.size);
  file->data = data;
  file->offset = 0;

  return 0;

fail:
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_ssize_t
grub_afs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_afs_data *data = (struct grub_afs_data *) file->data;

  return grub_afs_read_file (&data->diropen, file->read_hook, file->closure,
                             file->flags, file->offset, len, buf);
}

static grub_err_t
grub_afs_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

struct grub_afs_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info, void *closure);
  void *closure;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node, void *closure)
{
  struct grub_afs_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  info.mtimeset = 1;
#ifdef MODE_BFS
  info.mtime = grub_afs_to_cpu64 (node->inode.modified_time) >> 16;
#else
  info.mtime = grub_divmod64 (grub_afs_to_cpu64 (node->inode.modified_time),
			      1000000, 0);
#endif
  grub_free (node);
  return c->hook (filename, &info, c->closure);
}

static grub_err_t
grub_afs_dir (grub_device_t device, const char *path,
              int (*hook) (const char *filename,
			   const struct grub_dirhook_info *info, void *closure),
	      void *closure)
{
  struct grub_afs_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;
  struct grub_afs_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_afs_mount (device->disk);
  if (! data)
    goto fail;

  grub_fshelp_find_file (path, &data->diropen, &fdiro, grub_afs_iterate_dir, 0,
			 grub_afs_read_symlink, GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;

  if (hook) {
    c.hook = hook;
    c.closure = closure;
    grub_afs_iterate_dir (fdiro, iterate, &c);
  }

  if (fdiro != &data->diropen)
    grub_free (fdiro);

 fail:
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_afs_label (grub_device_t device, char **label)
{
  struct grub_afs_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_afs_mount (disk);
  if (data)
    *label = grub_strndup (data->sblock.name, sizeof (data->sblock.name));
  else
    *label = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}


static struct grub_fs grub_afs_fs = {
  .name = GRUB_AFS_FSNAME,
  .dir = grub_afs_dir,
  .open = grub_afs_open,
  .read = grub_afs_read,
  .close = grub_afs_close,
  .label = grub_afs_label,
  .next = 0
};
