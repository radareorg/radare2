/* ext2.c - Second Extended filesystem */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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

/* Magic value used to identify an ext2 filesystem.  */
#define	EXT2_MAGIC		0xEF53
/* Amount of indirect blocks in an inode.  */
#define INDIRECT_BLOCKS		12
/* Maximum length of a pathname.  */
#define EXT2_PATH_MAX		4096
/* Maximum nesting of symlinks, used to prevent a loop.  */
#define	EXT2_MAX_SYMLINKCNT	8

/* The good old revision and the default inode size.  */
#define EXT2_GOOD_OLD_REVISION		0
#define EXT2_GOOD_OLD_INODE_SIZE	128

/* Filetype used in directory entry.  */
#define	FILETYPE_UNKNOWN	0
#define	FILETYPE_REG		1
#define	FILETYPE_DIRECTORY	2
#define	FILETYPE_SYMLINK	7

/* Filetype information as used in inodes.  */
#define FILETYPE_INO_MASK	0170000
#define FILETYPE_INO_REG	0100000
#define FILETYPE_INO_DIRECTORY	0040000
#define FILETYPE_INO_SYMLINK	0120000

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>

/* Log2 size of ext2 block in 512 blocks.  */
#define LOG2_EXT2_BLOCK_SIZE(data)			\
	(grub_le_to_cpu32 (data->sblock.log2_block_size) + 1)

/* Log2 size of ext2 block in bytes.  */
#define LOG2_BLOCK_SIZE(data)					\
	(grub_le_to_cpu32 (data->sblock.log2_block_size) + 10)

/* The size of an ext2 block in bytes.  */
#define EXT2_BLOCK_SIZE(data)		(1 << LOG2_BLOCK_SIZE (data))

/* The revision level.  */
#define EXT2_REVISION(data)	grub_le_to_cpu32 (data->sblock.revision_level)

/* The inode size.  */
#define EXT2_INODE_SIZE(data)	\
        (EXT2_REVISION (data) == EXT2_GOOD_OLD_REVISION \
         ? EXT2_GOOD_OLD_INODE_SIZE \
         : grub_le_to_cpu16 (data->sblock.inode_size))

/* Superblock filesystem feature flags (RW compatible)
 * A filesystem with any of these enabled can be read and written by a driver
 * that does not understand them without causing metadata/data corruption.  */
#define EXT2_FEATURE_COMPAT_DIR_PREALLOC	0x0001
#define EXT2_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x0004
#define EXT2_FEATURE_COMPAT_EXT_ATTR		0x0008
#define EXT2_FEATURE_COMPAT_RESIZE_INODE	0x0010
#define EXT2_FEATURE_COMPAT_DIR_INDEX		0x0020
/* Superblock filesystem feature flags (RO compatible)
 * A filesystem with any of these enabled can be safely read by a driver that
 * does not understand them, but should not be written to, usually because
 * additional metadata is required.  */
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE	0x0002
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR	0x0004
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM		0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK	0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE	0x0040
/* Superblock filesystem feature flags (back-incompatible)
 * A filesystem with any of these enabled should not be attempted to be read
 * by a driver that does not understand them, since they usually indicate
 * metadata format changes that might confuse the reader.  */
#define EXT2_FEATURE_INCOMPAT_COMPRESSION	0x0001
#define EXT2_FEATURE_INCOMPAT_FILETYPE		0x0002
#define EXT3_FEATURE_INCOMPAT_RECOVER		0x0004 /* Needs recovery */
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008 /* Volume is journal device */
#define EXT2_FEATURE_INCOMPAT_META_BG		0x0010
#define EXT4_FEATURE_INCOMPAT_EXTENTS		0x0040 /* Extents used */
#define EXT4_FEATURE_INCOMPAT_64BIT		0x0080
#define EXT4_FEATURE_INCOMPAT_FLEX_BG		0x0200

/* The set of back-incompatible features this driver DOES support. Add (OR)
 * flags here as the related features are implemented into the driver.  */
#define EXT2_DRIVER_SUPPORTED_INCOMPAT ( EXT2_FEATURE_INCOMPAT_FILETYPE \
                                       | EXT4_FEATURE_INCOMPAT_EXTENTS  \
                                       | EXT4_FEATURE_INCOMPAT_FLEX_BG )
/* List of rationales for the ignored "incompatible" features:
 * needs_recovery: Not really back-incompatible - was added as such to forbid
 *                 ext2 drivers from mounting an ext3 volume with a dirty
 *                 journal because they will ignore the journal, but the next
 *                 ext3 driver to mount the volume will find the journal and
 *                 replay it, potentially corrupting the metadata written by
 *                 the ext2 drivers. Safe to ignore for this RO driver.  */
#define EXT2_DRIVER_IGNORED_INCOMPAT ( EXT3_FEATURE_INCOMPAT_RECOVER )


#define EXT3_JOURNAL_MAGIC_NUMBER	0xc03b3998U

#define EXT3_JOURNAL_DESCRIPTOR_BLOCK	1
#define EXT3_JOURNAL_COMMIT_BLOCK	2
#define EXT3_JOURNAL_SUPERBLOCK_V1	3
#define EXT3_JOURNAL_SUPERBLOCK_V2	4
#define EXT3_JOURNAL_REVOKE_BLOCK	5

#define EXT3_JOURNAL_FLAG_ESCAPE	1
#define EXT3_JOURNAL_FLAG_SAME_UUID	2
#define EXT3_JOURNAL_FLAG_DELETED	4
#define EXT3_JOURNAL_FLAG_LAST_TAG	8

#define EXT4_EXTENTS_FLAG		0x80000

/* The ext2 superblock.  */
struct grub_ext2_sblock
{
  grub_uint32_t total_inodes;
  grub_uint32_t total_blocks;
  grub_uint32_t reserved_blocks;
  grub_uint32_t free_blocks;
  grub_uint32_t free_inodes;
  grub_uint32_t first_data_block;
  grub_uint32_t log2_block_size;
  grub_uint32_t log2_fragment_size;
  grub_uint32_t blocks_per_group;
  grub_uint32_t fragments_per_group;
  grub_uint32_t inodes_per_group;
  grub_uint32_t mtime;
  grub_uint32_t utime;
  grub_uint16_t mnt_count;
  grub_uint16_t max_mnt_count;
  grub_uint16_t magic;
  grub_uint16_t fs_state;
  grub_uint16_t error_handling;
  grub_uint16_t minor_revision_level;
  grub_uint32_t lastcheck;
  grub_uint32_t checkinterval;
  grub_uint32_t creator_os;
  grub_uint32_t revision_level;
  grub_uint16_t uid_reserved;
  grub_uint16_t gid_reserved;
  grub_uint32_t first_inode;
  grub_uint16_t inode_size;
  grub_uint16_t block_group_number;
  grub_uint32_t feature_compatibility;
  grub_uint32_t feature_incompat;
  grub_uint32_t feature_ro_compat;
  grub_uint16_t uuid[8];
  char volume_name[16];
  char last_mounted_on[64];
  grub_uint32_t compression_info;
  grub_uint8_t prealloc_blocks;
  grub_uint8_t prealloc_dir_blocks;
  grub_uint16_t reserved_gdt_blocks;
  grub_uint8_t journal_uuid[16];
  grub_uint32_t journal_inum;
  grub_uint32_t journal_dev;
  grub_uint32_t last_orphan;
  grub_uint32_t hash_seed[4];
  grub_uint8_t def_hash_version;
  grub_uint8_t jnl_backup_type;
  grub_uint16_t reserved_word_pad;
  grub_uint32_t default_mount_opts;
  grub_uint32_t first_meta_bg;
  grub_uint32_t mkfs_time;
  grub_uint32_t jnl_blocks[17];
};

/* The ext2 blockgroup.  */
struct grub_ext2_block_group
{
  grub_uint32_t block_id;
  grub_uint32_t inode_id;
  grub_uint32_t inode_table_id;
  grub_uint16_t free_blocks;
  grub_uint16_t free_inodes;
  grub_uint16_t used_dirs;
  grub_uint16_t pad;
  grub_uint32_t reserved[3];
};

/* The ext2 inode.  */
struct grub_ext2_inode
{
  grub_uint16_t mode;
  grub_uint16_t uid;
  grub_uint32_t size;
  grub_uint32_t atime;
  grub_uint32_t ctime;
  grub_uint32_t mtime;
  grub_uint32_t dtime;
  grub_uint16_t gid;
  grub_uint16_t nlinks;
  grub_uint32_t blockcnt;  /* Blocks of 512 bytes!! */
  grub_uint32_t flags;
  grub_uint32_t osd1;
  union
  {
    struct datablocks
    {
      grub_uint32_t dir_blocks[INDIRECT_BLOCKS];
      grub_uint32_t indir_block;
      grub_uint32_t double_indir_block;
      grub_uint32_t triple_indir_block;
    } blocks;
    char symlink[60];
  };
  grub_uint32_t version;
  grub_uint32_t acl;
  grub_uint32_t dir_acl;
  grub_uint32_t fragment_addr;
  grub_uint32_t osd2[3];
};

/* The header of an ext2 directory entry.  */
struct ext2_dirent
{
  grub_uint32_t inode;
  grub_uint16_t direntlen;
  grub_uint8_t namelen;
  grub_uint8_t filetype;
};

struct grub_ext3_journal_header
{
  grub_uint32_t magic;
  grub_uint32_t block_type;
  grub_uint32_t sequence;
};

struct grub_ext3_journal_revoke_header
{
  struct grub_ext3_journal_header header;
  grub_uint32_t count;
  grub_uint32_t data[0];
};

struct grub_ext3_journal_block_tag
{
  grub_uint32_t block;
  grub_uint32_t flags;
};

struct grub_ext3_journal_sblock
{
  struct grub_ext3_journal_header header;
  grub_uint32_t block_size;
  grub_uint32_t maxlen;
  grub_uint32_t first;
  grub_uint32_t sequence;
  grub_uint32_t start;
};

#define EXT4_EXT_MAGIC		0xf30a

struct grub_ext4_extent_header
{
  grub_uint16_t magic;
  grub_uint16_t entries;
  grub_uint16_t max;
  grub_uint16_t depth;
  grub_uint32_t generation;
};

struct grub_ext4_extent
{
  grub_uint32_t block;
  grub_uint16_t len;
  grub_uint16_t start_hi;
  grub_uint32_t start;
};

struct grub_ext4_extent_idx
{
  grub_uint32_t block;
  grub_uint32_t leaf;
  grub_uint16_t leaf_hi;
  grub_uint16_t unused;
};

struct grub_fshelp_node
{
  struct grub_ext2_data *data;
  struct grub_ext2_inode inode;
  int ino;
  int inode_read;
};

/* Information about a "mounted" ext2 filesystem.  */
struct grub_ext2_data
{
  struct grub_ext2_sblock sblock;
  grub_disk_t disk;
  struct grub_ext2_inode *inode;
  struct grub_fshelp_node diropen;
};

static grub_dl_t my_mod;



/* Read into BLKGRP the blockgroup descriptor of blockgroup GROUP of
   the mounted filesystem DATA.  */
inline static grub_err_t
grub_ext2_blockgroup (struct grub_ext2_data *data, int group,
		      struct grub_ext2_block_group *blkgrp)
{
  return grub_disk_read (data->disk,
                         ((grub_le_to_cpu32 (data->sblock.first_data_block) + 1)
                          << LOG2_EXT2_BLOCK_SIZE (data)),
			 group * sizeof (struct grub_ext2_block_group),
			 sizeof (struct grub_ext2_block_group), blkgrp);
}

static struct grub_ext4_extent_header *
grub_ext4_find_leaf (struct grub_ext2_data *data, char *buf,
                     struct grub_ext4_extent_header *ext_block,
                     grub_uint32_t fileblock)
{
  struct grub_ext4_extent_idx *index;

  while (1)
    {
      int i;
      grub_disk_addr_t block;

      index = (struct grub_ext4_extent_idx *) (ext_block + 1);

      if (grub_le_to_cpu16(ext_block->magic) != EXT4_EXT_MAGIC)
        return 0;

      if (ext_block->depth == 0)
        return ext_block;

      for (i = 0; i < grub_le_to_cpu16 (ext_block->entries); i++)
        {
          if (fileblock < grub_le_to_cpu32(index[i].block))
            break;
        }

      if (--i < 0)
        return 0;

      block = grub_le_to_cpu16 (index[i].leaf_hi);
      block = (block << 32) + grub_le_to_cpu32 (index[i].leaf);
      if (grub_disk_read (data->disk,
                          block << LOG2_EXT2_BLOCK_SIZE (data),
                          0, EXT2_BLOCK_SIZE(data), buf))
        return 0;

      ext_block = (struct grub_ext4_extent_header *) buf;
    }
}

static grub_disk_addr_t
grub_ext2_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  struct grub_ext2_data *data = node->data;
  struct grub_ext2_inode *inode = &node->inode;
  int blknr = -1;
  unsigned int blksz = EXT2_BLOCK_SIZE (data);
  int log2_blksz = LOG2_EXT2_BLOCK_SIZE (data);

  if (grub_le_to_cpu32(inode->flags) & EXT4_EXTENTS_FLAG)
    {
      char buf[EXT2_BLOCK_SIZE(data)];
      struct grub_ext4_extent_header *leaf;
      struct grub_ext4_extent *ext;
      int i;

      leaf = grub_ext4_find_leaf (data, buf,
		  (struct grub_ext4_extent_header *) inode->blocks.dir_blocks,
		  fileblock);
      if (! leaf)
        {
          grub_error (GRUB_ERR_BAD_FS, "invalid extent");
          return -1;
        }

      ext = (struct grub_ext4_extent *) (leaf + 1);
      for (i = 0; i < grub_le_to_cpu16 (leaf->entries); i++)
        {
          if (fileblock < grub_le_to_cpu32 (ext[i].block))
            break;
        }

      if (--i >= 0)
        {
          fileblock -= grub_le_to_cpu32 (ext[i].block);
          if (fileblock >= grub_le_to_cpu16 (ext[i].len))
            return 0;
          else
            {
              grub_disk_addr_t start;

              start = grub_le_to_cpu16 (ext[i].start_hi);
              start = (start << 32) + grub_le_to_cpu32 (ext[i].start);

              return fileblock + start;
            }
        }
      else
        {
          grub_error (GRUB_ERR_BAD_FS, "something wrong with extent");
          return -1;
        }
    }
  /* Direct blocks.  */
  if (fileblock < INDIRECT_BLOCKS)
    blknr = grub_le_to_cpu32 (inode->blocks.dir_blocks[fileblock]);
  /* Indirect.  */
  else if (fileblock < INDIRECT_BLOCKS + blksz / 4)
    {
      grub_uint32_t *indir;

      indir = grub_malloc (blksz);
      if (! indir)
	return grub_errno;

      if (grub_disk_read (data->disk,
			  ((grub_disk_addr_t)
			   grub_le_to_cpu32 (inode->blocks.indir_block))
			  << log2_blksz,
			  0, blksz, indir))
	return grub_errno;

      blknr = grub_le_to_cpu32 (indir[fileblock - INDIRECT_BLOCKS]);
      grub_free (indir);
    }
  /* Double indirect.  */
  else if (fileblock < (grub_disk_addr_t)(INDIRECT_BLOCKS + blksz / 4) \
		  * (grub_disk_addr_t)(blksz / 4 + 1))
    {
      unsigned int perblock = blksz / 4;
      unsigned int rblock = fileblock - (INDIRECT_BLOCKS
					 + blksz / 4);
      grub_uint32_t *indir;

      indir = grub_malloc (blksz);
      if (! indir)
	return grub_errno;

      if (grub_disk_read (data->disk,
			  ((grub_disk_addr_t)
			   grub_le_to_cpu32 (inode->blocks.double_indir_block))
			  << log2_blksz,
			  0, blksz, indir))
	return grub_errno;

      if (grub_disk_read (data->disk,
			  ((grub_disk_addr_t)
			   grub_le_to_cpu32 (indir[rblock / perblock]))
			  << log2_blksz,
			  0, blksz, indir))
	return grub_errno;

      blknr = grub_le_to_cpu32 (indir[rblock % perblock]);
            grub_free (indir);
    }
  /* triple indirect.  */
  else
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		  "ext2fs doesn't support triple indirect blocks");
    }

  return blknr;
}

/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_ext2_read_file (grub_fshelp_node_t node,
     void (*read_hook) (grub_disk_addr_t sector,
		unsigned offset, unsigned length, void *closure),
     void *closure, int flags, int pos, grub_size_t len, char *buf)
{
	return grub_fshelp_read_file (node->data->disk, node, read_hook, closure,
		flags, pos, len, buf, grub_ext2_read_block,
		node->inode.size, LOG2_EXT2_BLOCK_SIZE (node->data));
}


/* Read the inode INO for the file described by DATA into INODE.  */
static grub_err_t
grub_ext2_read_inode (struct grub_ext2_data *data,
		      int ino, struct grub_ext2_inode *inode)
{
  struct grub_ext2_block_group blkgrp;
  struct grub_ext2_sblock *sblock = &data->sblock;
  int inodes_per_block;
  unsigned int blkno;
  unsigned int blkoff;

  /* It is easier to calculate if the first inode is 0.  */
  ino--;

  grub_ext2_blockgroup (data,
                        ino / grub_le_to_cpu32 (sblock->inodes_per_group),
			&blkgrp);
  if (grub_errno)
    return grub_errno;

  inodes_per_block = EXT2_BLOCK_SIZE (data) / EXT2_INODE_SIZE (data);
  blkno = (ino % grub_le_to_cpu32 (sblock->inodes_per_group))
    / inodes_per_block;
  blkoff = (ino % grub_le_to_cpu32 (sblock->inodes_per_group))
    % inodes_per_block;

  /* Read the inode.  */
  if (grub_disk_read (data->disk,
		      ((grub_le_to_cpu32 (blkgrp.inode_table_id) + blkno)
		        << LOG2_EXT2_BLOCK_SIZE (data)),
		      EXT2_INODE_SIZE (data) * blkoff,
		      sizeof (struct grub_ext2_inode), inode))
    return grub_errno;

  return 0;
}

static struct grub_ext2_data *
grub_ext2_mount (grub_disk_t disk)
{
  struct grub_ext2_data *data;

  data = grub_malloc (sizeof (struct grub_ext2_data));
  if (!data)
    return 0;

  /* Read the superblock.  */
  grub_disk_read (disk, 1 * 2, 0, sizeof (struct grub_ext2_sblock),
                  &data->sblock);
  if (grub_errno)
    goto fail;

  /* Make sure this is an ext2 filesystem.  */
  if (grub_le_to_cpu16 (data->sblock.magic) != EXT2_MAGIC)
    {
      grub_error (GRUB_ERR_BAD_FS, "not an ext2 filesystem");
      goto fail;
    }

  /* Check the FS doesn't have feature bits enabled that we don't support. */
  if (grub_le_to_cpu32 (data->sblock.feature_incompat)
        & ~(EXT2_DRIVER_SUPPORTED_INCOMPAT | EXT2_DRIVER_IGNORED_INCOMPAT))
    {
      grub_error (GRUB_ERR_BAD_FS, "filesystem has unsupported incompatible features");
      goto fail;
    }


  data->disk = disk;

  data->diropen.data = data;
  data->diropen.ino = 2;
  data->diropen.inode_read = 1;

  data->inode = &data->diropen.inode;

  grub_ext2_read_inode (data, 2, data->inode);
  if (grub_errno)
    goto fail;

  return data;

 fail:
  if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
    grub_error (GRUB_ERR_BAD_FS, "not an ext2 filesystem");

  grub_free (data);
  return 0;
}

static char *
grub_ext2_read_symlink (grub_fshelp_node_t node)
{
  char *symlink;
  struct grub_fshelp_node *diro = node;

  if (! diro->inode_read)
    {
      grub_ext2_read_inode (diro->data, diro->ino, &diro->inode);
      if (grub_errno)
	return 0;
    }

  symlink = grub_malloc (grub_le_to_cpu32 (diro->inode.size) + 1);
  if (! symlink)
    return 0;

  /* If the filesize of the symlink is bigger than
     60 the symlink is stored in a separate block,
     otherwise it is stored in the inode.  */
  if (grub_le_to_cpu32 (diro->inode.size) <= 60)
    grub_strncpy (symlink,
		  diro->inode.symlink,
		  grub_le_to_cpu32 (diro->inode.size));
  else
    {
      grub_ext2_read_file (diro, 0, 0, 0, 0,
			   grub_le_to_cpu32 (diro->inode.size),
			   symlink);
      if (grub_errno)
	{
	  grub_free (symlink);
	  return 0;
	}
    }

  symlink[grub_le_to_cpu32 (diro->inode.size)] = '\0';
  return symlink;
}

static int
grub_ext2_iterate_dir (grub_fshelp_node_t dir,
		       int (*hook) (const char *filename,
				    enum grub_fshelp_filetype filetype,
				    grub_fshelp_node_t node,
				    void *closure),
		       void *closure)
{
  unsigned int fpos = 0;
  struct grub_fshelp_node *diro = (struct grub_fshelp_node *) dir;

  if (! diro->inode_read)
    {
      grub_ext2_read_inode (diro->data, diro->ino, &diro->inode);
      if (grub_errno)
	return 0;
    }

  /* Search the file.  */
  if (hook)
  while (fpos < grub_le_to_cpu32 (diro->inode.size))
    {
      struct ext2_dirent dirent;

      grub_ext2_read_file (diro, NULL, NULL, 0, fpos, sizeof (dirent),
			   (char *) &dirent);
      if (grub_errno)
	return 0;

      if (dirent.direntlen == 0)
        return 0;

      if (dirent.namelen != 0)
	{
	  char filename[dirent.namelen + 1];
	  struct grub_fshelp_node *fdiro;
	  enum grub_fshelp_filetype type = GRUB_FSHELP_UNKNOWN;

	  grub_ext2_read_file (diro, 0, 0, 0,
			       fpos + sizeof (struct ext2_dirent),
			       dirent.namelen, filename);
	  if (grub_errno)
	    return 0;

	  fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
	  if (! fdiro)
	    return 0;

	  fdiro->data = diro->data;
	  fdiro->ino = grub_le_to_cpu32 (dirent.inode);

	  filename[dirent.namelen] = '\0';

	  if (dirent.filetype != FILETYPE_UNKNOWN)
	    {
	      fdiro->inode_read = 0;

	      if (dirent.filetype == FILETYPE_DIRECTORY)
		type = GRUB_FSHELP_DIR;
	      else if (dirent.filetype == FILETYPE_SYMLINK)
		type = GRUB_FSHELP_SYMLINK;
	      else if (dirent.filetype == FILETYPE_REG)
		type = GRUB_FSHELP_REG;
	    }
	  else
	    {
	      /* The filetype can not be read from the dirent, read
		 the inode to get more information.  */
	      grub_ext2_read_inode (diro->data,
                                    grub_le_to_cpu32 (dirent.inode),
				    &fdiro->inode);
	      if (grub_errno)
		{
		  grub_free (fdiro);
		  return 0;
		}

	      fdiro->inode_read = 1;

	      if ((grub_le_to_cpu16 (fdiro->inode.mode)
		   & FILETYPE_INO_MASK) == FILETYPE_INO_DIRECTORY)
		type = GRUB_FSHELP_DIR;
	      else if ((grub_le_to_cpu16 (fdiro->inode.mode)
			& FILETYPE_INO_MASK) == FILETYPE_INO_SYMLINK)
		type = GRUB_FSHELP_SYMLINK;
	      else if ((grub_le_to_cpu16 (fdiro->inode.mode)
			& FILETYPE_INO_MASK) == FILETYPE_INO_REG)
		type = GRUB_FSHELP_REG;
	    }

	  if (hook (filename, type, fdiro, closure))
	    return 1;
	}

      fpos += grub_le_to_cpu16 (dirent.direntlen);
    }

  return 0;
}

/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_ext2_open (struct grub_file *file, const char *name)
{
  struct grub_ext2_data *data;
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  data = grub_ext2_mount (file->device->disk);
  if (! data)
    goto fail;

  grub_fshelp_find_file (name, &data->diropen, &fdiro, grub_ext2_iterate_dir, 0,
			 grub_ext2_read_symlink, GRUB_FSHELP_REG);
  if (grub_errno)
    goto fail;

  if (! fdiro->inode_read)
    {
      grub_ext2_read_inode (data, fdiro->ino, &fdiro->inode);
      if (grub_errno)
	goto fail;
    }

  grub_memcpy (data->inode, &fdiro->inode, sizeof (struct grub_ext2_inode));
  grub_free (fdiro);

  file->size = grub_le_to_cpu32 (data->inode->size);
  file->data = data;
  file->offset = 0;

  return 0;

 fail:
  if (fdiro != &data->diropen)
    grub_free (fdiro);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ext2_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

/* Read LEN bytes data from FILE into BUF.  */
static grub_ssize_t
grub_ext2_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_ext2_data *data = (struct grub_ext2_data *) file->data;
  return grub_ext2_read_file (&data->diropen, file->read_hook, file->closure,
			      file->flags, file->offset, len, buf);
}

struct grub_ext2_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info,
	       void *closure);
  void *closure;
  struct grub_ext2_data *data;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node,
	 void *closure)
{
  struct grub_ext2_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  if (! node->inode_read)
    {
      grub_ext2_read_inode (c->data, node->ino, &node->inode);
      if (!grub_errno)
	node->inode_read = 1;
      grub_errno = GRUB_ERR_NONE;
    }
  if (node->inode_read)
    {
      info.mtimeset = 1;
      info.mtime = grub_le_to_cpu32 (node->inode.mtime);
    }

  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return (c->hook != NULL)? c->hook (filename, &info, c->closure): 0;
}

static grub_err_t
grub_ext2_dir (grub_device_t device, const char *path,
	       int (*hook) (const char *filename,
			    const struct grub_dirhook_info *info,
			    void *closure),
	       void *closure)
{
  struct grub_ext2_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;
  struct grub_ext2_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_ext2_mount (device->disk);
  if (! data)
    goto fail;

  grub_fshelp_find_file (path, &data->diropen, &fdiro, grub_ext2_iterate_dir,
			 0, grub_ext2_read_symlink, GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;

  c.hook = hook;
  c.closure = closure;
  c.data = data;
  grub_ext2_iterate_dir (fdiro, iterate, &c);

 fail:
  if (fdiro != &data->diropen)
    grub_free (fdiro);
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ext2_label (grub_device_t device, char **label)
{
  struct grub_ext2_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ext2_mount (disk);
  if (data)
    *label = grub_strndup (data->sblock.volume_name, 14);
  else
    *label = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

static grub_err_t
grub_ext2_uuid (grub_device_t device, char **uuid)
{
  struct grub_ext2_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ext2_mount (disk);
  if (data)
    {
      *uuid = grub_xasprintf ("%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			     grub_be_to_cpu16 (data->sblock.uuid[0]),
			     grub_be_to_cpu16 (data->sblock.uuid[1]),
			     grub_be_to_cpu16 (data->sblock.uuid[2]),
			     grub_be_to_cpu16 (data->sblock.uuid[3]),
			     grub_be_to_cpu16 (data->sblock.uuid[4]),
			     grub_be_to_cpu16 (data->sblock.uuid[5]),
			     grub_be_to_cpu16 (data->sblock.uuid[6]),
			     grub_be_to_cpu16 (data->sblock.uuid[7]));
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

/* Get mtime.  */
static grub_err_t
grub_ext2_mtime (grub_device_t device, grub_int32_t *tm)
{
  struct grub_ext2_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ext2_mount (disk);
  if (!data)
    *tm = 0;
  else
    *tm = grub_le_to_cpu32 (data->sblock.utime);

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;

}



struct grub_fs grub_ext2_fs =
  {
    .name = "ext2",
    .dir = grub_ext2_dir,
    .open = grub_ext2_open,
    .read = grub_ext2_read,
    .close = grub_ext2_close,
    .label = grub_ext2_label,
    .uuid = grub_ext2_uuid,
    .mtime = grub_ext2_mtime,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
#endif
    .next = 0
  };
