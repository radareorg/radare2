/* hfs.c - HFS.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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

/* HFS is documented at
   http://developer.apple.com/documentation/mac/Files/Files-2.html */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/hfs.h>
#include <stdlib.h>

#define	GRUB_HFS_SBLOCK		2
#define GRUB_HFS_EMBED_HFSPLUS_SIG 0x482B

#define GRUB_HFS_BLKS		(data->blksz >> 9)

#define GRUB_HFS_NODE_LEAF	0xFF

/* The two supported filesystems a record can have.  */
enum
  {
    GRUB_HFS_FILETYPE_DIR = 1,
    GRUB_HFS_FILETYPE_FILE = 2
  };

/* Catalog node ID (CNID).  */
enum grub_hfs_cnid_type
  {
    GRUB_HFS_CNID_ROOT_PARENT = 1,
    GRUB_HFS_CNID_ROOT = 2,
    GRUB_HFS_CNID_EXT = 3,
    GRUB_HFS_CNID_CAT = 4,
    GRUB_HFS_CNID_BAD = 5
  };

/* A node descriptor.  This is the header of every node.  */
struct grub_hfs_node
{
  grub_uint32_t next;
  grub_uint32_t prev;
  grub_uint8_t type;
  grub_uint8_t level;
  grub_uint16_t reccnt;
  grub_uint16_t unused;
} __attribute__ ((packed));

/* The head of the B*-Tree.  */
struct grub_hfs_treeheader
{
  grub_uint16_t tree_depth;
  /* The number of the first node.  */
  grub_uint32_t root_node;
  grub_uint32_t leaves;
  grub_uint32_t first_leaf;
  grub_uint32_t last_leaf;
  grub_uint16_t node_size;
  grub_uint16_t key_size;
  grub_uint32_t nodes;
  grub_uint32_t free_nodes;
  grub_uint8_t unused[76];
} __attribute__ ((packed));

/* The state of a mounted HFS filesystem.  */
struct grub_hfs_data
{
  struct grub_hfs_sblock sblock;
  grub_disk_t disk;
  grub_hfs_datarecord_t extents;
  int fileid;
  int size;
  int ext_root;
  int ext_size;
  int cat_root;
  int cat_size;
  int blksz;
  int log2_blksz;
  int rootdir;
};

/* The key as used on disk in a catalog tree.  This is used to lookup
   file/directory nodes by parent directory ID and filename.  */
struct grub_hfs_catalog_key
{
  grub_uint8_t unused;
  grub_uint32_t parent_dir;

  /* Filename length.  */
  grub_uint8_t strlen;

  /* Filename.  */
  grub_uint8_t str[31];
} __attribute__ ((packed));

/* The key as used on disk in a extent overflow tree.  Using this key
   the extents can be looked up using a fileid and logical start block
   as index.  */
struct grub_hfs_extent_key
{
  /* The kind of fork.  This is used to store meta information like
     icons, attributes, etc.  We will only use the datafork, which is
     0.  */
  grub_uint8_t forktype;
  grub_uint32_t fileid;
  grub_uint16_t first_block;
} __attribute__ ((packed));

/* A directory record.  This is used to find out the directory ID.  */
struct grub_hfs_dirrec
{
  /* For a directory, type == 1.  */
  grub_uint8_t type;
  grub_uint8_t unused[5];
  grub_uint32_t dirid;
} __attribute__ ((packed));

/* Information about a file.  */
struct grub_hfs_filerec
{
  /* For a file, type == 2.  */
  grub_uint8_t type;
  grub_uint8_t unused[19];
  grub_uint32_t fileid;
  grub_uint8_t unused2[2];
  grub_uint32_t size;
  grub_uint8_t unused3[44];

  /* The first 3 extents of the file.  The other extents can be found
     in the extent overflow file.  */
  grub_hfs_datarecord_t extents;
} __attribute__ ((packed));

/* A record descriptor, both key and data, used to pass to call back
   functions.  */
struct grub_hfs_record
{
  void *key;
  int keylen;
  void *data;
  int datalen;
};

static grub_dl_t my_mod;

static int grub_hfs_find_node (struct grub_hfs_data *, char *,
			       grub_uint32_t, int, char *, int);

/* Find block BLOCK of the file FILE in the mounted UFS filesystem
   DATA.  The first 3 extents are described by DAT.  If cache is set,
   using caching to improve non-random reads.  */
static unsigned int
grub_hfs_block (struct grub_hfs_data *data, grub_hfs_datarecord_t dat,
		int file, int block, int cache)
{
  grub_hfs_datarecord_t dr;
  int pos = 0;
  struct grub_hfs_extent_key key;

  int tree = 0;
  static int cache_file = 0;
  static int cache_pos = 0;
  static grub_hfs_datarecord_t cache_dr;

  grub_memcpy (dr, dat, sizeof (dr));

  key.forktype = 0;
  key.fileid = grub_cpu_to_be32 (file);

  if (cache && cache_file == file  && block > cache_pos)
    {
      pos = cache_pos;
      key.first_block = grub_cpu_to_be16 (pos);
      grub_memcpy (dr, cache_dr, sizeof (cache_dr));
    }

  for (;;)
    {
      int i;

      /* Try all 3 extents.  */
      for (i = 0; i < 3; i++)
	{
	  /* Check if the block is stored in this extent.  */
	  if (grub_be_to_cpu16 (dr[i].count) + pos > block)
	    {
	      int first = grub_be_to_cpu16 (dr[i].first_block);

	      /* If the cache is enabled, store the current position
		 in the tree.  */
	      if (tree && cache)
		{
		  cache_file = file;
		  cache_pos = pos;
		  grub_memcpy (cache_dr, dr, sizeof (cache_dr));
		}

	      return (grub_be_to_cpu16 (data->sblock.first_block)
		      + (first + block - pos) * GRUB_HFS_BLKS);
	    }

	  /* Try the next extent.  */
	  pos += grub_be_to_cpu16 (dr[i].count);
	}

      /* Lookup the block in the extent overflow file.  */
      key.first_block = grub_cpu_to_be16 (pos);
      tree = 1;
      grub_hfs_find_node (data, (char *) &key, data->ext_root,
			  1, (char *) &dr, sizeof (dr));
      if (grub_errno)
	return 0;
    }
}


/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_hfs_read_file (struct grub_hfs_data *data,
		    void (*read_hook) (grub_disk_addr_t sector,
				       unsigned offset, unsigned length,
				       void *closure),
		    void *closure,
		    int pos, grub_size_t len, char *buf)
{
  int i;
  int blockcnt;

  blockcnt = ((len + pos)
	      + data->blksz - 1) / data->blksz;

  for (i = pos / data->blksz; i < blockcnt; i++)
    {
      int blknr;
      int blockoff = pos % data->blksz;
      int blockend = data->blksz;

      int skipfirst = 0;

      blknr = grub_hfs_block (data, data->extents, data->fileid, i, 1);
      if (grub_errno)
	return -1;

      /* Last block.  */
      if (i == blockcnt - 1)
	{
	  blockend = (len + pos) % data->blksz;

	  /* The last portion is exactly EXT2_BLOCK_SIZE (data).  */
	  if (! blockend)
	    blockend = data->blksz;
	}

      /* First block.  */
      if (i == pos / data->blksz)
	{
	  skipfirst = blockoff;
	  blockend -= skipfirst;
	}

      /* If the block number is 0 this block is not stored on disk but
	 is zero filled instead.  */
      if (blknr)
	{
	  data->disk->read_hook = read_hook;
	  data->disk->closure = closure;
	  grub_disk_read (data->disk, blknr, skipfirst,
			  blockend, buf);
	  data->disk->read_hook = 0;
	  if (grub_errno)
	    return -1;
	}

      buf += data->blksz - skipfirst;
    }

  return len;
}


/* Mount the filesystem on the disk DISK.  */
static struct grub_hfs_data *
grub_hfs_mount (grub_disk_t disk)
{
  struct grub_hfs_data *data;
  struct grub_hfs_catalog_key key;
  struct grub_hfs_dirrec dir;
  int first_block;

  struct
  {
    struct grub_hfs_node node;
    struct grub_hfs_treeheader head;
  } treehead;

  data = grub_malloc (sizeof (struct grub_hfs_data));
  if (!data)
    return 0;

  /* Read the superblock.  */
  if (grub_disk_read (disk, GRUB_HFS_SBLOCK, 0,
		      sizeof (struct grub_hfs_sblock), &data->sblock))
    goto fail;

  /* Check if this is a HFS filesystem.  */
  if (grub_be_to_cpu16 (data->sblock.magic) != GRUB_HFS_MAGIC)
    {
      grub_error (GRUB_ERR_BAD_FS, "not an HFS filesystem");
      goto fail;
    }

  /* Check if this is an embedded HFS+ filesystem.  */
  if (grub_be_to_cpu16 (data->sblock.embed_sig) == GRUB_HFS_EMBED_HFSPLUS_SIG)
    {
      grub_error (GRUB_ERR_BAD_FS, "embedded HFS+ filesystem");
      goto fail;
    }

  data->blksz = grub_be_to_cpu32 (data->sblock.blksz);
  data->disk = disk;

  /* Lookup the root node of the extent overflow tree.  */
  first_block = ((grub_be_to_cpu16 (data->sblock.extent_recs[0].first_block)
		  * GRUB_HFS_BLKS)
		 + grub_be_to_cpu16 (data->sblock.first_block));

  if (grub_disk_read (data->disk, first_block, 0,
		      sizeof (treehead), &treehead))
    goto fail;
  data->ext_root = grub_be_to_cpu32 (treehead.head.root_node);
  data->ext_size = grub_be_to_cpu16 (treehead.head.node_size);

  /* Lookup the root node of the catalog tree.  */
  first_block = ((grub_be_to_cpu16 (data->sblock.catalog_recs[0].first_block)
		  * GRUB_HFS_BLKS)
		 + grub_be_to_cpu16 (data->sblock.first_block));
  if (grub_disk_read (data->disk, first_block, 0,
		      sizeof (treehead), &treehead))
    goto fail;
  data->cat_root = grub_be_to_cpu32 (treehead.head.root_node);
  data->cat_size = grub_be_to_cpu16 (treehead.head.node_size);

  /* Lookup the root directory node in the catalog tree using the
     volume name.  */
  key.parent_dir = grub_cpu_to_be32 (1);
  key.strlen = data->sblock.volname[0];
  grub_strcpy ((char *) key.str, (char *) (data->sblock.volname + 1));

  if (grub_hfs_find_node (data, (char *) &key, data->cat_root,
			  0, (char *) &dir, sizeof (dir)) == 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "cannot find the HFS root directory");
      goto fail;
    }

  if (grub_errno)
    goto fail;

  data->rootdir = grub_be_to_cpu32 (dir.dirid);

  return data;
 fail:
  grub_free (data);

  if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
    grub_error (GRUB_ERR_BAD_FS, "not a HFS filesystem");

  return 0;
}

/* Compare the K1 and K2 catalog file keys using HFS character ordering.  */
static int
grub_hfs_cmp_catkeys (struct grub_hfs_catalog_key *k1,
		      struct grub_hfs_catalog_key *k2)
{
  /* Taken from hfsutils 3.2.6 and converted to a readable form */
  static const unsigned char hfs_charorder[256] = {
    [0x00] = 0,
    [0x01] = 1,
    [0x02] = 2,
    [0x03] = 3,
    [0x04] = 4,
    [0x05] = 5,
    [0x06] = 6,
    [0x07] = 7,
    [0x08] = 8,
    [0x09] = 9,
    [0x0A] = 10,
    [0x0B] = 11,
    [0x0C] = 12,
    [0x0D] = 13,
    [0x0E] = 14,
    [0x0F] = 15,
    [0x10] = 16,
    [0x11] = 17,
    [0x12] = 18,
    [0x13] = 19,
    [0x14] = 20,
    [0x15] = 21,
    [0x16] = 22,
    [0x17] = 23,
    [0x18] = 24,
    [0x19] = 25,
    [0x1A] = 26,
    [0x1B] = 27,
    [0x1C] = 28,
    [0x1D] = 29,
    [0x1E] = 30,
    [0x1F] = 31,
    [' '] = 32,		[0xCA] = 32,
    ['!'] = 33,
    ['"'] = 34,
    [0xD2] = 35,
    [0xD3] = 36,
    [0xC7] = 37,
    [0xC8] = 38,
    ['#'] = 39,
    ['$'] = 40,
    ['%'] = 41,
    ['&'] = 42,
    ['\''] = 43,
    [0xD4] = 44,
    [0xD5] = 45,
    ['('] = 46,
    [')'] = 47,
    ['*'] = 48,
    ['+'] = 49,
    [','] = 50,
    ['-'] = 51,
    ['.'] = 52,
    ['/'] = 53,
    ['0'] = 54,
    ['1'] = 55,
    ['2'] = 56,
    ['3'] = 57,
    ['4'] = 58,
    ['5'] = 59,
    ['6'] = 60,
    ['7'] = 61,
    ['8'] = 62,
    ['9'] = 63,
    [':'] = 64,
    [';'] = 65,
    ['<'] = 66,
    ['='] = 67,
    ['>'] = 68,
    ['?'] = 69,
    ['@'] = 70,
    ['A'] = 71,		['a'] = 71,
    [0x88] = 72,	[0xCB] = 72,
    [0x80] = 73,	[0x8A] = 73,
    [0x8B] = 74,	[0xCC] = 74,
    [0x81] = 75,	[0x8C] = 75,
    [0xAE] = 76,	[0xBE] = 76,
    ['`'] = 77,
    [0x87] = 78,
    [0x89] = 79,
    [0xBB] = 80,
    ['B'] = 81,		['b'] = 81,
    ['C'] = 82,		['c'] = 82,
    [0x82] = 83,	[0x8D] = 83,
    ['D'] = 84,		['d'] = 84,
    ['E'] = 85,		['e'] = 85,
    [0x83] = 86,	[0x8E] = 86,
    [0x8F] = 87,
    [0x90] = 88,
    [0x91] = 89,
    ['F'] = 90,		['f'] = 90,
    ['G'] = 91,		['g'] = 91,
    ['H'] = 92,		['h'] = 92,
    ['I'] = 93,		['i'] = 93,
    [0x92] = 94,
    [0x93] = 95,
    [0x94] = 96,
    [0x95] = 97,
    ['J'] = 98,		['j'] = 98,
    ['K'] = 99,		['k'] = 99,
    ['L'] = 100,	['l'] = 100,
    ['M'] = 101,	['m'] = 101,
    ['N'] = 102,	['n'] = 102,
    [0x84] = 103,	[0x96] = 103,
    ['O'] = 104,	['o'] = 104,
    [0x85] = 105,	[0x9A] = 105,
    [0x9B] = 106,	[0xCD] = 106,
    [0xAF] = 107,	[0xBF] = 107,
    [0xCE] = 108,	[0xCF] = 108,
    [0x97] = 109,
    [0x98] = 110,
    [0x99] = 111,
    [0xBC] = 112,
    ['P'] = 113,	['p'] = 113,
    ['Q'] = 114,	['q'] = 114,
    ['R'] = 115,	['r'] = 115,
    ['S'] = 116,	['s'] = 116,
    [0xA7] = 117,
    ['T'] = 118,	['t'] = 118,
    ['U'] = 119,	['u'] = 119,
    [0x86] = 120,	[0x9F] = 120,
    [0x9C] = 121,
    [0x9D] = 122,
    [0x9E] = 123,
    ['V'] = 124,	['v'] = 124,
    ['W'] = 125,	['w'] = 125,
    ['X'] = 126,	['x'] = 126,
    ['Y'] = 127,	['y'] = 127,
    [0xD8] = 128,
    ['Z'] = 129,	['z'] = 129,
    ['['] = 130,
    ['\\'] = 131,
    [']'] = 132,
    ['^'] = 133,
    ['_'] = 134,
    ['{'] = 135,
    ['|'] = 136,
    ['}'] = 137,
    ['~'] = 138,
    [0x7F] = 139,
    [0xA0] = 140,
    [0xA1] = 141,
    [0xA2] = 142,
    [0xA3] = 143,
    [0xA4] = 144,
    [0xA5] = 145,
    [0xA6] = 146,
    [0xA8] = 147,
    [0xA9] = 148,
    [0xAA] = 149,
    [0xAB] = 150,
    [0xAC] = 151,
    [0xAD] = 152,
    [0xB0] = 153,
    [0xB1] = 154,
    [0xB2] = 155,
    [0xB3] = 156,
    [0xB4] = 157,
    [0xB5] = 158,
    [0xB6] = 159,
    [0xB7] = 160,
    [0xB8] = 161,
    [0xB9] = 162,
    [0xBA] = 163,
    [0xBD] = 164,
    [0xC0] = 165,
    [0xC1] = 166,
    [0xC2] = 167,
    [0xC3] = 168,
    [0xC4] = 169,
    [0xC5] = 170,
    [0xC6] = 171,
    [0xC9] = 172,
    [0xD0] = 173,
    [0xD1] = 174,
    [0xD6] = 175,
    [0xD7] = 176,
    [0xD9] = 177,
    [0xDA] = 178,
    [0xDB] = 179,
    [0xDC] = 180,
    [0xDD] = 181,
    [0xDE] = 182,
    [0xDF] = 183,
    [0xE0] = 184,
    [0xE1] = 185,
    [0xE2] = 186,
    [0xE3] = 187,
    [0xE4] = 188,
    [0xE5] = 189,
    [0xE6] = 190,
    [0xE7] = 191,
    [0xE8] = 192,
    [0xE9] = 193,
    [0xEA] = 194,
    [0xEB] = 195,
    [0xEC] = 196,
    [0xED] = 197,
    [0xEE] = 198,
    [0xEF] = 199,
    [0xF0] = 200,
    [0xF1] = 201,
    [0xF2] = 202,
    [0xF3] = 203,
    [0xF4] = 204,
    [0xF5] = 205,
    [0xF6] = 206,
    [0xF7] = 207,
    [0xF8] = 208,
    [0xF9] = 209,
    [0xFA] = 210,
    [0xFB] = 211,
    [0xFC] = 212,
    [0xFD] = 213,
    [0xFE] = 214,
    [0xFF] = 215,
  };
  int i;
  int cmp;
  int minlen = (k1->strlen < k2->strlen) ? k1->strlen : k2->strlen;

  cmp = (grub_be_to_cpu32 (k1->parent_dir) - grub_be_to_cpu32 (k2->parent_dir));
  if (cmp != 0)
    return cmp;

  for (i = 0; i < minlen; i++)
    {
      cmp = (hfs_charorder[k1->str[i]] - hfs_charorder[k2->str[i]]);
      if (cmp != 0)
	return cmp;
    }

  /* Shorter strings precede long ones.  */
  return (k1->strlen - k2->strlen);
}


/* Compare the K1 and K2 extent overflow file keys.  */
static int
grub_hfs_cmp_extkeys (struct grub_hfs_extent_key *k1,
		      struct grub_hfs_extent_key *k2)
{
  int cmp = k1->forktype - k2->forktype;
  if (cmp == 0)
    cmp = grub_be_to_cpu32 (k1->fileid) - grub_be_to_cpu32 (k2->fileid);
  if (cmp == 0)
    cmp = (grub_be_to_cpu16 (k1->first_block)
	   - grub_be_to_cpu16 (k2->first_block));
  return cmp;
}


/* Iterate the records in the node with index IDX in the mounted HFS
   filesystem DATA.  This node holds data of the type TYPE (0 =
   catalog node, 1 = extent overflow node).  If this is set, continue
   iterating to the next node.  For every records, call NODE_HOOK.  */
static grub_err_t
grub_hfs_iterate_records (struct grub_hfs_data *data, int type, int idx, int this,
			  int (*node_hook) (struct grub_hfs_node *hnd,
					    struct grub_hfs_record *,
					    void *closure),
			  void *closure)
{
  int nodesize = type == 0 ? data->cat_size : data->ext_size;
#if GCC
  union
  {
    struct grub_hfs_node node;
    char rawnode[nodesize];
    grub_uint16_t offsets[nodesize / 2];
  } node;
#else
  union
  {
    struct grub_hfs_node node;
    char *rawnode;
    grub_uint16_t *offsets; //[nodesize / 2];
  } node;
#endif

node.rawnode = malloc (nodesize);
node.offsets = malloc ((nodesize*sizeof(grub_uint16_t))/2);

  do
    {
      int i;
      struct grub_hfs_extent *dat;
      int blk;

      dat = (struct grub_hfs_extent *) (type == 0
					? (&data->sblock.catalog_recs)
					: (&data->sblock.extent_recs));

      /* Read the node into memory.  */
      blk = grub_hfs_block (data, dat,
                            (type == 0) ? GRUB_HFS_CNID_CAT : GRUB_HFS_CNID_EXT,
			    idx / (data->blksz / nodesize), 0);
      blk += (idx % (data->blksz / nodesize));
      if (grub_errno) {
        free (node.rawnode);
        free (node.offsets);
	return grub_errno;
      }

      if (grub_disk_read (data->disk, blk, 0,
			      sizeof (node), &node)) {
	      free (node.rawnode);
	      free (node.offsets);
	      return grub_errno;
      }

      /* Iterate over all records in this node.  */
      for (i = 0; i < grub_be_to_cpu16 (node.node.reccnt); i++)
	{
	  int pos = (nodesize >> 1) - 1 - i;
 	  struct pointer
	  {
	    grub_uint8_t keylen;
	    grub_uint8_t key;
	  } __attribute__ ((packed)) *pnt;
	  pnt = (struct pointer *) (grub_be_to_cpu16 (node.offsets[pos])
				    + node.rawnode);

	  struct grub_hfs_record rec =
	    {
	      &pnt->key,
	      pnt->keylen,
	      &pnt->key + pnt->keylen +(pnt->keylen + 1) % 2,
	      nodesize - grub_be_to_cpu16 (node.offsets[pos])
	      - pnt->keylen - 1
	    };

	  if (node_hook (&node.node, &rec, closure)) {
		  free (node.rawnode);
		  free (node.offsets);
	    return 0;
		}
	}

      idx = grub_be_to_cpu32 (node.node.next);
    } while (idx && this);

  free (node.rawnode);
  free (node.offsets);

  return 0;
}

struct grub_hfs_find_node_closure
{
  char *key;
  int type;
  char *datar;
  int datalen;
  int found;
  int isleaf;
  int done;
};

static int
grub_hfs_find_node_node_found (struct grub_hfs_node *hnd,
			       struct grub_hfs_record *rec,
			       void *closure)
{
  struct grub_hfs_find_node_closure *c = closure;
  int cmp = 1;

  if (c->type == 0)
    cmp = grub_hfs_cmp_catkeys (rec->key, (void *) c->key);
  else
    cmp = grub_hfs_cmp_extkeys (rec->key, (void *) c->key);

  /* If the key is smaller or equal to the current node, mark the
     entry.  In case of a non-leaf mode it will be used to lookup
     the rest of the tree.  */
  if (cmp <= 0)
    {
      grub_uint32_t *node = (grub_uint32_t *) rec->data;
      c->found = grub_be_to_cpu32 (*node);
    }
  else /* The key can not be found in the tree. */
    return 1;

  /* Check if this node is a leaf node.  */
  if (hnd->type == GRUB_HFS_NODE_LEAF)
    {
      c->isleaf = 1;

      /* Found it!!!!  */
      if (cmp == 0)
	{
	  c->done = 1;

	  grub_memcpy (c->datar, rec->data,
		       rec->datalen < c->datalen ? rec->datalen : c->datalen);
	  return 1;
	}
    }

  return 0;
}

/* Lookup a record in the mounted filesystem DATA using the key KEY.
   The index of the node on top of the tree is IDX.  The tree is of
   the type TYPE (0 = catalog node, 1 = extent overflow node).  Return
   the data in DATAR with a maximum length of DATALEN.  */
static int
grub_hfs_find_node (struct grub_hfs_data *data, char *key,
		    grub_uint32_t idx, int type, char *datar, int datalen)
{
  struct grub_hfs_find_node_closure c;

  c.key = key;
  c.type = type;
  c.datar = datar;
  c.datalen = datalen;
  c.isleaf = 0;
  c.done = 0;
  do
    {
      c.found = -1;

      if (grub_hfs_iterate_records (data, type, idx, 0,
				    grub_hfs_find_node_node_found, &c))
        return 0;

      if (c.found == -1)
        return 0;

      idx = c.found;
    } while (! c.isleaf);

  return c.done;
}

struct grub_hfs_iterate_dir_closure
{
  unsigned int dir;
  int (*hook) (struct grub_hfs_record *, void *closure);
  void *closure;
  struct grub_hfs_catalog_key *key;
  int found;
  int isleaf;
  int next;
};

static int
grub_hfs_iterate_dir_node_found (struct grub_hfs_node *hnd,
				 struct grub_hfs_record *rec,
				 void *closure)
{
  struct grub_hfs_iterate_dir_closure *c = closure;
  struct grub_hfs_catalog_key *ckey = rec->key;

  if (grub_hfs_cmp_catkeys (rec->key, (void *) c->key) <= 0)
    c->found = grub_be_to_cpu32 (*(grub_uint32_t *) rec->data);

  if (hnd->type == 0xFF && ckey->strlen > 0)
    {
      c->isleaf = 1;
      c->next = grub_be_to_cpu32 (hnd->next);

      /* An entry was found.  */
      if (grub_be_to_cpu32 (ckey->parent_dir) == c->dir)
	return c->hook?c->hook (rec, c->closure): 0;
    }

  return 0;
}

static int
grub_hfs_iterate_dir_it_dir (struct grub_hfs_node *hnd __attribute ((unused)),
			     struct grub_hfs_record *rec,
			     void *closure)
{
  struct grub_hfs_iterate_dir_closure *c = closure;
  struct grub_hfs_catalog_key *ckey = rec->key;
  struct grub_hfs_catalog_key *origkey = c->key;

  /* Stop when the entries do not match anymore.  */
  if (grub_be_to_cpu32 (ckey->parent_dir)
      != grub_be_to_cpu32 ((origkey)->parent_dir))
    return 1;

  return c->hook (rec, c->closure);
}

/* Iterate over the directory with the id DIR.  The tree is searched
   starting with the node ROOT_IDX.  For every entry in this directory
   call HOOK.  */
static grub_err_t
grub_hfs_iterate_dir (struct grub_hfs_data *data, grub_uint32_t root_idx,
		      unsigned int dir,
		      int (*hook) (struct grub_hfs_record *, void *closure),
		      void *closure)
{
  /* The lowest key possible with DIR as root directory.  */
  struct grub_hfs_catalog_key key = {0, grub_cpu_to_be32 (dir), 0, ""};
  struct grub_hfs_iterate_dir_closure c;

  c.key = &key;
  c.dir = dir;
  c.hook = hook;
  c.closure = closure;
  c.isleaf = 0;
  c.next = 0;
  do
    {
      c.found = -1;

      if (grub_hfs_iterate_records (data, 0, root_idx, 0,
				    grub_hfs_iterate_dir_node_found, &c))
        return grub_errno;

      if (c.found == -1)
        return 0;

      root_idx = c.found;
    } while (! c.isleaf);

  /* If there was a matching record in this leaf node, continue the
     iteration until the last record was found.  */
  grub_hfs_iterate_records (data, 0, c.next, 1, grub_hfs_iterate_dir_it_dir, &c);
  return grub_errno;
}


/* Find a file or directory with the pathname PATH in the filesystem
   DATA.  Return the file record in RETDATA when it is non-zero.
   Return the directory number in RETINODE when it is non-zero.  */
static grub_err_t
grub_hfs_find_dir (struct grub_hfs_data *data, const char *path,
		   struct grub_hfs_filerec *retdata, int *retinode)
{
  int inode = data->rootdir;
  char *next;
  char *origpath;
  union {
    struct grub_hfs_filerec frec;
    struct grub_hfs_dirrec dir;
  } fdrec;

  fdrec.frec.type = GRUB_HFS_FILETYPE_DIR;

  if (path[0] != '/')
    {
      grub_error (GRUB_ERR_BAD_FILENAME, "bad filename");
      return 0;
    }

  origpath = grub_strdup (path);
  if (!origpath)
    return grub_errno;

  path = origpath;
  while (*path == '/')
    path++;

  while (path && grub_strlen (path))
    {
      if (fdrec.frec.type != GRUB_HFS_FILETYPE_DIR)
	{
	  grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
	  goto fail;
	}

      /* Isolate a part of the path.  */
      next = grub_strchr (path, '/');
      if (next)
	{
	  while (*next == '/')
	    *(next++) = '\0';
	}

      struct grub_hfs_catalog_key key;

      key.parent_dir = grub_cpu_to_be32 (inode);
      key.strlen = grub_strlen (path);
      grub_strcpy ((char *) (key.str), path);

      /* Lookup this node.  */
      if (! grub_hfs_find_node (data, (char *) &key, data->cat_root,
				0, (char *) &fdrec.frec, sizeof (fdrec.frec)))
	{
	  grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
	  goto fail;
	}

      if (grub_errno)
	goto fail;

      inode = grub_be_to_cpu32 (fdrec.dir.dirid);
      path = next;
    }

  if (retdata)
    grub_memcpy (retdata, &fdrec.frec, sizeof (fdrec.frec));

  if (retinode)
    *retinode = inode;

 fail:
  grub_free (origpath);
  return grub_errno;
}

struct grub_hfs_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info, void *closure);
  void *closure;
};

static int
grub_hfs_dir_hook (struct grub_hfs_record *rec, void *closure)
{
  struct grub_hfs_dir_closure *c = closure;
  char fname[32] = { 0 };
  char *filetype = rec->data;
  struct grub_hfs_catalog_key *ckey = rec->key;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));

  grub_strncpy (fname, (char *) (ckey->str), ckey->strlen);

  if (*filetype == GRUB_HFS_FILETYPE_DIR
      || *filetype == GRUB_HFS_FILETYPE_FILE)
    {
      info.dir = (*filetype == GRUB_HFS_FILETYPE_DIR);
      return c->hook (fname, &info, c->closure);
    }
  return 0;
}


static grub_err_t
grub_hfs_dir (grub_device_t device, const char *path,
	      int (*hook) (const char *filename,
			   const struct grub_dirhook_info *info, void *closure),
	      void *closure)
{
  int inode;
  struct grub_hfs_data *data;
  struct grub_hfs_filerec frec = {0};
  struct grub_hfs_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_hfs_mount (device->disk);
  if (!data)
    goto fail;

  /* First the directory ID for the directory.  */
  if (grub_hfs_find_dir (data, path, &frec, &inode))
    goto fail;

  if (frec.type != GRUB_HFS_FILETYPE_DIR)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
      goto fail;
    }

  c.hook = hook;
  c.closure = closure;
  grub_hfs_iterate_dir (data, data->cat_root, inode, grub_hfs_dir_hook, &c);

 fail:
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_hfs_open (struct grub_file *file, const char *name)
{
  struct grub_hfs_data *data;
  struct grub_hfs_filerec frec;

  grub_dl_ref (my_mod);

  data = grub_hfs_mount (file->device->disk);

  if (grub_hfs_find_dir (data, name, &frec, 0))
    {
      grub_free (data);
      grub_dl_unref (my_mod);
      return grub_errno;
    }

  if (frec.type != GRUB_HFS_FILETYPE_FILE)
    {
      grub_free (data);
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a file");
      grub_dl_unref (my_mod);
      return grub_errno;
    }

  grub_memcpy (data->extents, frec.extents, sizeof (grub_hfs_datarecord_t));
  file->size = grub_be_to_cpu32 (frec.size);
  data->size = grub_be_to_cpu32 (frec.size);
  data->fileid = grub_be_to_cpu32 (frec.fileid);
  file->offset = 0;

  file->data = data;

  return 0;
}

static grub_ssize_t
grub_hfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_hfs_data *data =
    (struct grub_hfs_data *) file->data;

  return grub_hfs_read_file (data, file->read_hook, file->closure,
			     file->offset, len, buf);
}


static grub_err_t
grub_hfs_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return 0;
}


static grub_err_t
grub_hfs_label (grub_device_t device, char **label)
{
  struct grub_hfs_data *data;

  data = grub_hfs_mount (device->disk);

  if (data)
    *label = grub_strndup ((char *) (data->sblock.volname + 1),
			   *data->sblock.volname);
  else
    *label = 0;

  grub_free (data);
  return grub_errno;
}

static grub_err_t
grub_hfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_hfs_data *data;

  grub_dl_ref (my_mod);

  data = grub_hfs_mount (device->disk);
  if (data && data->sblock.num_serial != 0)
    {
      *uuid = grub_xasprintf ("%016llx",
			     (unsigned long long)
			     grub_be_to_cpu64 (data->sblock.num_serial));
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}



struct grub_fs grub_hfs_fs =
  {
    .name = "hfs",
    .dir = grub_hfs_dir,
    .open = grub_hfs_open,
    .read = grub_hfs_read,
    .close = grub_hfs_close,
    .label = grub_hfs_label,
    .uuid = grub_hfs_uuid,
    .next = 0
  };
