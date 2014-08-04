/* reiserfs.c - ReiserFS versions up to 3.6 */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2008  Free Software Foundation, Inc.
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

/*
  TODO:
  implement journal handling (ram replay)
  test tail packing & direct files
  validate partition label position
*/

#if 0
# define GRUB_REISERFS_DEBUG
# define GRUB_REISERFS_JOURNALING
# define GRUB_HEXDUMP
#endif

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>

#define MIN(a, b) \
  ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

#define MAX(a, b) \
  ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
     _a > _b ? _a : _b; })

#define REISERFS_SUPER_BLOCK_OFFSET 0x10000
#define REISERFS_MAGIC_LEN 12
#define REISERFS_MAGIC_STRING "ReIsEr"
#define REISERFS_MAGIC_DESC_BLOCK "ReIsErLB"
/* If the 3rd bit of an item state is set, then it's visible.  */
#define GRUB_REISERFS_VISIBLE_MASK ((grub_uint16_t) 0x04)
#define REISERFS_MAX_LABEL_LENGTH 16
#define REISERFS_LABEL_OFFSET 0x64

#define S_IFLNK 0xA000

static grub_dl_t my_mod;

#define assert(boolean) real_assert (boolean, GRUB_FILE, __LINE__)
static inline void
real_assert (int boolean, const char *file, const int line)
{
  if (! boolean)
    grub_printf ("Assertion failed at %s:%d\n", file, line);
}

enum grub_reiserfs_item_type
  {
    GRUB_REISERFS_STAT,
    GRUB_REISERFS_DIRECTORY,
    GRUB_REISERFS_DIRECT,
    GRUB_REISERFS_INDIRECT,
    /* Matches both _DIRECT and _INDIRECT when searching.  */
    GRUB_REISERFS_ANY,
    GRUB_REISERFS_UNKNOWN
  };

struct grub_reiserfs_superblock
{
  grub_uint32_t block_count;
  grub_uint32_t block_free_count;
  grub_uint32_t root_block;
  grub_uint32_t journal_block;
  grub_uint32_t journal_device;
  grub_uint32_t journal_original_size;
  grub_uint32_t journal_max_transaction_size;
  grub_uint32_t journal_block_count;
  grub_uint32_t journal_max_batch;
  grub_uint32_t journal_max_commit_age;
  grub_uint32_t journal_max_transaction_age;
  grub_uint16_t block_size;
  grub_uint16_t oid_max_size;
  grub_uint16_t oid_current_size;
  grub_uint16_t state;
  grub_uint8_t magic_string[REISERFS_MAGIC_LEN];
  grub_uint32_t function_hash_code;
  grub_uint16_t tree_height;
  grub_uint16_t bitmap_number;
  grub_uint16_t version;
  grub_uint16_t reserved;
  grub_uint32_t inode_generation;
  grub_uint8_t unused[4];
  grub_uint16_t uuid[8];
} __attribute__ ((packed));

struct grub_reiserfs_journal_header
{
  grub_uint32_t last_flush_uid;
  grub_uint32_t unflushed_offset;
  grub_uint32_t mount_id;
} __attribute__ ((packed));

struct grub_reiserfs_description_block
{
  grub_uint32_t id;
  grub_uint32_t len;
  grub_uint32_t mount_id;
  grub_uint32_t real_blocks[0];
} __attribute__ ((packed));

struct grub_reiserfs_commit_block
{
  grub_uint32_t id;
  grub_uint32_t len;
  grub_uint32_t real_blocks[0];
} __attribute__ ((packed));

struct grub_reiserfs_stat_item_v1
{
  grub_uint16_t mode;
  grub_uint16_t hardlink_count;
  grub_uint16_t uid;
  grub_uint16_t gid;
  grub_uint32_t size;
  grub_uint32_t atime;
  grub_uint32_t mtime;
  grub_uint32_t ctime;
  grub_uint32_t rdev;
  grub_uint32_t first_direct_byte;
} __attribute__ ((packed));

struct grub_reiserfs_stat_item_v2
{
  grub_uint16_t mode;
  grub_uint16_t reserved;
  grub_uint32_t hardlink_count;
  grub_uint64_t size;
  grub_uint32_t uid;
  grub_uint32_t gid;
  grub_uint32_t atime;
  grub_uint32_t mtime;
  grub_uint32_t ctime;
  grub_uint32_t blocks;
  grub_uint32_t first_direct_byte;
} __attribute__ ((packed));

struct grub_reiserfs_key
{
  grub_uint32_t directory_id;
  grub_uint32_t object_id;
  union
  {
    struct
    {
      grub_uint32_t offset;
      grub_uint32_t type;
    } v1 __attribute__ ((packed));
    struct
    {
      grub_uint64_t offset_type;
    } v2 __attribute__ ((packed));
  } u;
} __attribute__ ((packed));

struct grub_reiserfs_item_header
{
  struct grub_reiserfs_key key;
  union
  {
    grub_uint16_t free_space;
    grub_uint16_t entry_count;
  } u __attribute__ ((packed));
  grub_uint16_t item_size;
  grub_uint16_t item_location;
  grub_uint16_t version;
} __attribute__ ((packed));

struct grub_reiserfs_block_header
{
  grub_uint16_t level;
  grub_uint16_t item_count;
  grub_uint16_t free_space;
  grub_uint16_t reserved;
  struct grub_reiserfs_key block_right_delimiting_key;
} __attribute__ ((packed));

struct grub_reiserfs_disk_child
{
  grub_uint32_t block_number;
  grub_uint16_t size;
  grub_uint16_t reserved;
} __attribute__ ((packed));

struct grub_reiserfs_directory_header
{
  grub_uint32_t offset;
  grub_uint32_t directory_id;
  grub_uint32_t object_id;
  grub_uint16_t location;
  grub_uint16_t state;
} __attribute__ ((packed));

struct grub_fshelp_node
{
  struct grub_reiserfs_data *data;
  grub_uint32_t block_number; /* 0 if node is not found.  */
  grub_uint16_t block_position;
  grub_uint64_t next_offset;
  enum grub_reiserfs_item_type type; /* To know how to read the header.  */
  struct grub_reiserfs_item_header header;
};

/* Returned when opening a file.  */
struct grub_reiserfs_data
{
  struct grub_reiserfs_superblock superblock;
  grub_disk_t disk;
};

/* Internal-only functions. Not to be used outside of this file.  */

/* Return the type of given v2 key.  */
static enum grub_reiserfs_item_type
grub_reiserfs_get_key_v2_type (const struct grub_reiserfs_key *key)
{
  unsigned long long o = grub_le_to_cpu64 (key->u.v2.offset_type);
  switch ((int)(o>>60))
    {
    case 0:
      return GRUB_REISERFS_STAT;
    case 15:
      return GRUB_REISERFS_ANY;
    case 3:
      return GRUB_REISERFS_DIRECTORY;
    case 2:
      return GRUB_REISERFS_DIRECT;
    case 1:
      return GRUB_REISERFS_INDIRECT;
    }
  return GRUB_REISERFS_UNKNOWN;
}

/* Return the type of given v1 key.  */
static enum grub_reiserfs_item_type
grub_reiserfs_get_key_v1_type (const struct grub_reiserfs_key *key)
{
  switch (grub_le_to_cpu32 (key->u.v1.type))
    {
    case 0:
      return GRUB_REISERFS_STAT;
    case 555:
      return GRUB_REISERFS_ANY;
    case 500:
      return GRUB_REISERFS_DIRECTORY;
    case 0x20000000:
    case 0xFFFFFFFF:
      return GRUB_REISERFS_DIRECT;
    case 0x10000000:
    case 0xFFFFFFFE:
      return GRUB_REISERFS_INDIRECT;
    }
  return GRUB_REISERFS_UNKNOWN;
}

/* Return 1 if the given key is version 1 key, 2 otherwise.  */
static int
grub_reiserfs_get_key_version (const struct grub_reiserfs_key *key)
{
  return grub_reiserfs_get_key_v1_type (key) == GRUB_REISERFS_UNKNOWN ? 2 : 1;
}

#ifdef GRUB_HEXDUMP
static void
grub_hexdump (char *buffer, grub_size_t len)
{
  grub_size_t a;
  for (a = 0; a < len; a++)
    {
      if (! (a & 0x0F))
        grub_printf ("\n%08x  ", a);
      grub_printf ("%02x ",
                   ((unsigned int) ((unsigned char *) buffer)[a]) & 0xFF);
    }
  grub_printf ("\n");
}
#endif

#ifdef GRUB_REISERFS_DEBUG
static grub_uint64_t
grub_reiserfs_get_key_offset (const struct grub_reiserfs_key *key);

static enum grub_reiserfs_item_type
grub_reiserfs_get_key_type (const struct grub_reiserfs_key *key);

static void
grub_reiserfs_print_key (const struct grub_reiserfs_key *key)
{
  unsigned int a;
  char *reiserfs_type_strings[] = {
    "stat     ",
    "directory",
    "direct   ",
    "indirect ",
    "any      ",
    "unknown  "
  };

  for (a = 0; a < sizeof (struct grub_reiserfs_key); a++)
    grub_printf ("%02x ", ((unsigned int) ((unsigned char *) key)[a]) & 0xFF);
  grub_printf ("parent id = 0x%08x, self id = 0x%08x, type = %s, offset = ",
               grub_le_to_cpu32 (key->directory_id),
               grub_le_to_cpu32 (key->object_id),
               reiserfs_type_strings [grub_reiserfs_get_key_type (key)]);
  if (grub_reiserfs_get_key_version (key) == 1)
    grub_printf("%08x", (unsigned int) grub_reiserfs_get_key_offset (key));
  else
    grub_printf("0x%07x%08x",
                (unsigned) (grub_reiserfs_get_key_offset (key) >> 32),
                (unsigned) (grub_reiserfs_get_key_offset (key) & 0xFFFFFFFF));
  grub_printf ("\n");
}
#endif

/* Return the offset of given key.  */
static grub_uint64_t
grub_reiserfs_get_key_offset (const struct grub_reiserfs_key *key)
{
  if (grub_reiserfs_get_key_version (key) == 1)
    return grub_le_to_cpu32 (key->u.v1.offset);
  else
    return grub_le_to_cpu64 (key->u.v2.offset_type) & (~0ULL >> 4);
}

/* Set the offset of given key.  */
static void
grub_reiserfs_set_key_offset (struct grub_reiserfs_key *key,
                              grub_uint64_t value)
{
  if (grub_reiserfs_get_key_version (key) == 1)
    key->u.v1.offset = grub_cpu_to_le32 (value);
  else
    key->u.v2.offset_type \
      = ((key->u.v2.offset_type & grub_cpu_to_le64 (15ULL << 60))
         | grub_cpu_to_le64 (value & (~0ULL >> 4)));
}

/* Return the type of given key.  */
static enum grub_reiserfs_item_type
grub_reiserfs_get_key_type (const struct grub_reiserfs_key *key)
{
  if (grub_reiserfs_get_key_version (key) == 1)
    return grub_reiserfs_get_key_v1_type (key);
  else
    return grub_reiserfs_get_key_v2_type (key);
}

/* Set the type of given key, with given version number.  */
static void
grub_reiserfs_set_key_type (struct grub_reiserfs_key *key,
                            enum grub_reiserfs_item_type grub_type,
                            int version)
{
  grub_uint32_t type;

  switch (grub_type)
    {
    case GRUB_REISERFS_STAT:
      type = 0;
      break;
    case GRUB_REISERFS_ANY:
      type = (version == 1) ? 555 : 15;
      break;
    case GRUB_REISERFS_DIRECTORY:
      type = (version == 1) ? 500 : 3;
      break;
    case GRUB_REISERFS_DIRECT:
      type = (version == 1) ? 0xFFFFFFFF : 2;
      break;
    case GRUB_REISERFS_INDIRECT:
      type = (version == 1) ? 0xFFFFFFFE : 1;
      break;
    default:
      return;
    }

  if (version == 1)
    key->u.v1.type = grub_cpu_to_le32 (type);
  else
    key->u.v2.offset_type
      = ((key->u.v2.offset_type & grub_cpu_to_le64 (~0ULL >> 4))
         | grub_cpu_to_le64 ((grub_uint64_t) type << 60));

  assert (grub_reiserfs_get_key_type (key) == grub_type);
}

/* -1 if key 1 if lower than key 2.
   0 if key 1 is equal to key 2.
   1 if key 1 is higher than key 2.  */
static int
grub_reiserfs_compare_keys (const struct grub_reiserfs_key *key1,
                            const struct grub_reiserfs_key *key2)
{
  grub_uint64_t offset1, offset2;
  enum grub_reiserfs_item_type type1, type2;
  grub_uint32_t id1, id2;

  if (! key1 || ! key2)
    return -2;

  id1 = grub_le_to_cpu32 (key1->directory_id);
  id2 = grub_le_to_cpu32 (key2->directory_id);
  if (id1 < id2)
    return -1;
  if (id1 > id2)
    return 1;

  id1 = grub_le_to_cpu32 (key1->object_id);
  id2 = grub_le_to_cpu32 (key2->object_id);
  if (id1 < id2)
    return -1;
  if (id1 > id2)
    return 1;

  offset1 = grub_reiserfs_get_key_offset (key1);
  offset2 = grub_reiserfs_get_key_offset (key2);
  if (offset1 < offset2)
    return -1;
  if (offset1 > offset2)
    return 1;

  type1 = grub_reiserfs_get_key_type (key1);
  type2 = grub_reiserfs_get_key_type (key2);
  if ((type1 == GRUB_REISERFS_ANY
       && (type2 == GRUB_REISERFS_DIRECT
           || type2 == GRUB_REISERFS_INDIRECT))
      || (type2 == GRUB_REISERFS_ANY
          && (type1 == GRUB_REISERFS_DIRECT
              || type1 == GRUB_REISERFS_INDIRECT)))
    return 0;
  if (type1 < type2)
    return -1;
  if (type1 > type2)
    return 1;

  return 0;
}

/* Find the item identified by KEY in mounted filesystem DATA, and fill ITEM
   accordingly to what was found.  */
static grub_err_t
grub_reiserfs_get_item (struct grub_reiserfs_data *data,
                        const struct grub_reiserfs_key *key,
                        struct grub_fshelp_node *item)
{
  grub_uint32_t block_number;
  struct grub_reiserfs_block_header *block_header = 0;
  struct grub_reiserfs_key *block_key = 0;
  grub_uint16_t block_size, item_count, current_level;
  grub_uint16_t i;
  grub_uint16_t previous_level = ~0;
  struct grub_reiserfs_item_header *item_headers = 0;

  if (! data)
    {
      grub_error (GRUB_ERR_TEST_FAILURE, "data is NULL");
      goto fail;
    }

  if (! key)
    {
      grub_error (GRUB_ERR_TEST_FAILURE, "key is NULL");
      goto fail;
    }

  if (! item)
    {
      grub_error (GRUB_ERR_TEST_FAILURE, "item is NULL");
      goto fail;
    }

  block_size = grub_le_to_cpu16 (data->superblock.block_size);
  block_number = grub_le_to_cpu32 (data->superblock.root_block);
#ifdef GRUB_REISERFS_DEBUG
  grub_printf("Searching for ");
  grub_reiserfs_print_key (key);
#endif
  block_header = grub_malloc (block_size);
  if (! block_header)
    goto fail;

  item->next_offset = 0;
  do
    {
      grub_disk_read (data->disk,
                      block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                      (((grub_off_t) block_number * block_size)
                       & (GRUB_DISK_SECTOR_SIZE - 1)),
                      block_size, block_header);
      if (grub_errno)
        goto fail;
      current_level = grub_le_to_cpu16 (block_header->level);
      grub_dprintf ("reiserfs_tree", " at level %d\n", current_level);
      if (current_level >= previous_level)
        {
          grub_dprintf ("reiserfs_tree", "level loop detected, aborting\n");
          grub_error (GRUB_ERR_FILE_READ_ERROR, "level loop");
          goto fail;
        }
      previous_level = current_level;
      item_count = grub_le_to_cpu16 (block_header->item_count);
      grub_dprintf ("reiserfs_tree", " number of contained items : %d\n",
                    item_count);
      if (current_level > 1)
        {
          /* Internal node. Navigate to the child that should contain
             the searched key.  */
          struct grub_reiserfs_key *keys
            = (struct grub_reiserfs_key *) (block_header + 1);
          struct grub_reiserfs_disk_child *children
            = ((struct grub_reiserfs_disk_child *)
               (keys + item_count));

          for (i = 0;
               i < item_count
                 && grub_reiserfs_compare_keys (key, &(keys[i])) >= 0;
               i++)
            {
#ifdef GRUB_REISERFS_DEBUG
              grub_printf("i %03d/%03d ", i + 1, item_count + 1);
              grub_reiserfs_print_key (&(keys[i]));
#endif
            }
          block_number = grub_le_to_cpu32 (children[i].block_number);
	  if ((i < item_count) && (key->directory_id == keys[i].directory_id)
	       && (key->object_id == keys[i].object_id))
	    item->next_offset = grub_reiserfs_get_key_offset(&(keys[i]));
#ifdef GRUB_REISERFS_DEBUG
          if (i == item_count
              || grub_reiserfs_compare_keys (key, &(keys[i])) == 0)
            grub_printf(">");
          else
            grub_printf("<");
          if (i < item_count)
            {
              grub_printf (" %03d/%03d ", i + 1, item_count + 1);
              grub_reiserfs_print_key (&(keys[i]));
              if (i + 1 < item_count)
                {
                  grub_printf ("+ %03d/%03d ", i + 2, item_count);
                  grub_reiserfs_print_key (&(keys[i + 1]));
                }
            }
          else
            grub_printf ("Accessing rightmost child at block %d.\n",
                         block_number);
#endif
        }
      else
        {
          /* Leaf node.  Check that the key is actually present.  */
          item_headers
            = (struct grub_reiserfs_item_header *) (block_header + 1);
          for (i = 0;
               i < item_count
                 && (grub_reiserfs_compare_keys (key, &(item_headers[i].key))
                     != 0);
               i++)
            {
#ifdef GRUB_REISERFS_DEBUG
              if (key->directory_id == item_headers[i].key.directory_id && \
                  key->object_id == item_headers[i].key.object_id)
                grub_printf("C");
              else
                grub_printf(" ");
              grub_printf(" %03d/%03d ", i + 1, item_count);
              grub_reiserfs_print_key (&(item_headers[i].key));
#endif
            }
          if (i < item_count)
            block_key = &(item_headers[i].key);
        }
    }
  while (current_level > 1);

  item->data = data;

  if (i == item_count || grub_reiserfs_compare_keys (key, block_key))
    {
      item->block_number = 0;
      item->block_position = 0;
      item->type = GRUB_REISERFS_UNKNOWN;
#ifdef GRUB_REISERFS_DEBUG
      grub_printf("Not found.\n");
#endif
    }
  else
    {
      item->block_number = block_number;
      item->block_position = i;
      item->type = grub_reiserfs_get_key_type (block_key);
      grub_memcpy (&(item->header), &(item_headers[i]),
                   sizeof (struct grub_reiserfs_item_header));
#ifdef GRUB_REISERFS_DEBUG
      grub_printf ("F %03d/%03d ", i + 1, item_count);
      grub_reiserfs_print_key (block_key);
#endif
    }

  assert (grub_errno == GRUB_ERR_NONE);
  grub_free (block_header);
  return GRUB_ERR_NONE;

 fail:
  assert (grub_errno != GRUB_ERR_NONE);
  grub_free (block_header);
  assert (grub_errno != GRUB_ERR_NONE);
  return grub_errno;
}

/* Return the path of the file which is pointed at by symlink NODE.  */
static char *
grub_reiserfs_read_symlink (grub_fshelp_node_t node)
{
  char *symlink_buffer = 0;
  grub_uint16_t block_size;
  grub_disk_addr_t block;
  grub_off_t offset;
  grub_size_t len;
  struct grub_fshelp_node found;
  struct grub_reiserfs_key key;

  grub_memcpy (&key, &(node->header.key), sizeof (key));
  grub_reiserfs_set_key_offset (&key, 1);
  grub_reiserfs_set_key_type (&key, GRUB_REISERFS_DIRECT,
                              grub_reiserfs_get_key_version (&key));

  if (grub_reiserfs_get_item (node->data, &key, &found) != GRUB_ERR_NONE)
    goto fail;

  if (found.block_number == 0)
    goto fail;

  block_size = grub_le_to_cpu16 (node->data->superblock.block_size);
  len = grub_le_to_cpu16 (found.header.item_size);
  block = (grub_disk_addr_t)found.block_number \
		  * ((grub_disk_addr_t)block_size  >> GRUB_DISK_SECTOR_BITS);
  offset = grub_le_to_cpu16 (found.header.item_location);

  symlink_buffer = grub_malloc (len + 1);
  if (! symlink_buffer)
    goto fail;

  grub_disk_read (node->data->disk, block, offset, len, symlink_buffer);
  if (grub_errno)
    goto fail;

  symlink_buffer[len] = 0;
  return symlink_buffer;

 fail:
  grub_free (symlink_buffer);
  return 0;
}

/* Fill the mounted filesystem structure and return it.  */
static struct grub_reiserfs_data *
grub_reiserfs_mount (grub_disk_t disk)
{
  struct grub_reiserfs_data *data = 0;
  data = grub_malloc (sizeof (*data));
  if (! data)
    goto fail;
  grub_disk_read (disk, REISERFS_SUPER_BLOCK_OFFSET / GRUB_DISK_SECTOR_SIZE,
                  0, sizeof (data->superblock), &(data->superblock));
  if (grub_errno)
    goto fail;
  if (grub_memcmp (data->superblock.magic_string,
                   REISERFS_MAGIC_STRING, sizeof (REISERFS_MAGIC_STRING) - 1))
    {
      grub_error (GRUB_ERR_BAD_FS, "not a ReiserFS filesystem");
      goto fail;
    }
  data->disk = disk;
  return data;

 fail:
  /* Disk is too small to contain a ReiserFS.  */
  if (grub_errno == GRUB_ERR_OUT_OF_RANGE)
    grub_error (GRUB_ERR_BAD_FS, "not a ReiserFS filesystem");

  grub_free (data);
  return 0;
}

/* Call HOOK for each file in directory ITEM.  */
static int
grub_reiserfs_iterate_dir (grub_fshelp_node_t item,
                           int (*hook) (const char *filename,
					enum grub_fshelp_filetype filetype,
					grub_fshelp_node_t node,
					void *closure),
			   void *closure)
{
  struct grub_reiserfs_data *data = item->data;
  struct grub_reiserfs_block_header *block_header = 0;
  grub_uint16_t block_size, block_position;
  grub_uint32_t block_number;
  grub_uint64_t next_offset = item->next_offset;
  int ret = 0;

  if (item->type != GRUB_REISERFS_DIRECTORY)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE,
                  "grub_reiserfs_iterate_dir called on a non-directory item");
      goto fail;
    }
  block_size = grub_le_to_cpu16 (data->superblock.block_size);
  block_header = grub_malloc (block_size);
  if (! block_header)
    goto fail;
  block_number = item->block_number;
  block_position = item->block_position;
  grub_dprintf ("reiserfs", "Iterating directory...\n");
  if (!hook)
    return GRUB_ERR_NONE;
  do
    {
      struct grub_reiserfs_directory_header *directory_headers;
      struct grub_fshelp_node directory_item;
      grub_uint16_t entry_count, entry_number;
      struct grub_reiserfs_item_header *item_headers;

      grub_disk_read (data->disk,
                      block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                      (((grub_off_t) block_number * block_size)
                       & (GRUB_DISK_SECTOR_SIZE - 1)),
                      block_size, (char *) block_header);
      if (grub_errno)
        goto fail;

#if 0
      if (grub_le_to_cpu16 (block_header->level) != 1)
        {
          grub_error (GRUB_ERR_TEST_FAILURE,
                      "reiserfs: block %d is not a leaf block",
                      block_number);
          goto fail;
        }
#endif

      item_headers = (struct grub_reiserfs_item_header *) (block_header + 1);
      directory_headers
        = ((struct grub_reiserfs_directory_header *)
           ((char *) block_header
            + grub_le_to_cpu16 (item_headers[block_position].item_location)));
      entry_count
        = grub_le_to_cpu16 (item_headers[block_position].u.entry_count);
      for (entry_number = 0; entry_number < entry_count; entry_number++)
        {
          struct grub_reiserfs_directory_header *directory_header
            = &directory_headers[entry_number];
          grub_uint16_t entry_state
            = grub_le_to_cpu16 (directory_header->state);

          if (entry_state & GRUB_REISERFS_VISIBLE_MASK)
            {
              grub_fshelp_node_t entry_item;
              struct grub_reiserfs_key entry_key;
	      enum grub_fshelp_filetype entry_type;
              char *entry_name;

              entry_name = (((char *) directory_headers)
                            + grub_le_to_cpu16 (directory_header->location));
              entry_key.directory_id = directory_header->directory_id;
              entry_key.object_id = directory_header->object_id;
              entry_key.u.v2.offset_type = 0;
              grub_reiserfs_set_key_type (&entry_key, GRUB_REISERFS_DIRECTORY,
                                          2);
              grub_reiserfs_set_key_offset (&entry_key, 1);

              entry_item = grub_malloc (sizeof (*entry_item));
              if (! entry_item)
                goto fail;

              if (grub_reiserfs_get_item (data, &entry_key, entry_item)
                  != GRUB_ERR_NONE)
                {
                  grub_free (entry_item);
                  goto fail;
                }

              if (entry_item->type == GRUB_REISERFS_DIRECTORY)
                entry_type = GRUB_FSHELP_DIR;
              else
                {
                  grub_uint32_t entry_block_number;
                  /* Order is very important here.
                     First set the offset to 0 using current key version.
                     Then change the key type, which affects key version
                     detection.  */
                  grub_reiserfs_set_key_offset (&entry_key, 0);
                  grub_reiserfs_set_key_type (&entry_key, GRUB_REISERFS_STAT,
                                              2);
                  if (grub_reiserfs_get_item (data, &entry_key, entry_item)
                      != GRUB_ERR_NONE)
                    {
                      grub_free (entry_item);
                      goto fail;
                    }

                  if (entry_item->block_number != 0)
                    {
                      grub_uint16_t entry_version;
                      entry_version
                        = grub_le_to_cpu16 (entry_item->header.version);
                      entry_block_number = entry_item->block_number;
#if 0
		      grub_dprintf ("reiserfs",
                                    "version %04x block %08x (%08x) position %08x\n",
                                    entry_version, entry_block_number,
                                    ((grub_disk_addr_t) entry_block_number * block_size) / GRUB_DISK_SECTOR_SIZE,
                                    grub_le_to_cpu16 (entry_item->header.item_location));
#endif
                      if (entry_version == 0) /* Version 1 stat item. */
                        {
                          struct grub_reiserfs_stat_item_v1 entry_v1_stat;
                          grub_disk_read (data->disk,
                                          entry_block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                                          grub_le_to_cpu16 (entry_item->header.item_location),
                                          sizeof (entry_v1_stat),
                                          (char *) &entry_v1_stat);
                          if (grub_errno)
                            goto fail;
#if 0
			  grub_dprintf ("reiserfs",
                                        "%04x %04x %04x %04x %08x %08x | %08x %08x %08x %08x\n",
                                        grub_le_to_cpu16 (entry_v1_stat.mode),
                                        grub_le_to_cpu16 (entry_v1_stat.hardlink_count),
                                        grub_le_to_cpu16 (entry_v1_stat.uid),
                                        grub_le_to_cpu16 (entry_v1_stat.gid),
                                        grub_le_to_cpu32 (entry_v1_stat.size),
                                        grub_le_to_cpu32 (entry_v1_stat.atime),
                                        grub_le_to_cpu32 (entry_v1_stat.mtime),
                                        grub_le_to_cpu32 (entry_v1_stat.ctime),
                                        grub_le_to_cpu32 (entry_v1_stat.rdev),
                                        grub_le_to_cpu32 (entry_v1_stat.first_direct_byte));
			  grub_dprintf ("reiserfs",
                                        "%04x %04x %04x %04x %08x %08x | %08x %08x %08x %08x\n",
                                        entry_v1_stat.mode,
                                        entry_v1_stat.hardlink_count,
                                        entry_v1_stat.uid,
                                        entry_v1_stat.gid,
                                        entry_v1_stat.size,
                                        entry_v1_stat.atime,
                                        entry_v1_stat.mtime,
                                        entry_v1_stat.ctime,
                                        entry_v1_stat.rdev,
                                        entry_v1_stat.first_direct_byte);
#endif
                          if ((grub_le_to_cpu16 (entry_v1_stat.mode) & S_IFLNK)
                              == S_IFLNK)
                            entry_type = GRUB_FSHELP_SYMLINK;
                          else
                            entry_type = GRUB_FSHELP_REG;
                        }
                      else
                        {
                          struct grub_reiserfs_stat_item_v2 entry_v2_stat;
                          grub_disk_read (data->disk,
                                          entry_block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                                          grub_le_to_cpu16 (entry_item->header.item_location),
                                          sizeof (entry_v2_stat),
                                          (char *) &entry_v2_stat);
                          if (grub_errno)
                            goto fail;
#if 0
			  grub_dprintf ("reiserfs",
                                        "%04x %04x %08x %08x%08x | %08x %08x %08x %08x | %08x %08x %08x\n",
                                        grub_le_to_cpu16 (entry_v2_stat.mode),
                                        grub_le_to_cpu16 (entry_v2_stat.reserved),
                                        grub_le_to_cpu32 (entry_v2_stat.hardlink_count),
                                        (unsigned int) (grub_le_to_cpu64 (entry_v2_stat.size) >> 32),
                                        (unsigned int) (grub_le_to_cpu64 (entry_v2_stat.size) && 0xFFFFFFFF),
                                        grub_le_to_cpu32 (entry_v2_stat.uid),
                                        grub_le_to_cpu32 (entry_v2_stat.gid),
                                        grub_le_to_cpu32 (entry_v2_stat.atime),
                                        grub_le_to_cpu32 (entry_v2_stat.mtime),
                                        grub_le_to_cpu32 (entry_v2_stat.ctime),
                                        grub_le_to_cpu32 (entry_v2_stat.blocks),
                                        grub_le_to_cpu32 (entry_v2_stat.first_direct_byte));
			  grub_dprintf ("reiserfs",
                                        "%04x %04x %08x %08x%08x | %08x %08x %08x %08x | %08x %08x %08x\n",
                                        entry_v2_stat.mode,
                                        entry_v2_stat.reserved,
                                        entry_v2_stat.hardlink_count,
                                        (unsigned int) (entry_v2_stat.size >> 32),
                                        (unsigned int) (entry_v2_stat.size && 0xFFFFFFFF),
                                        entry_v2_stat.uid,
                                        entry_v2_stat.gid,
                                        entry_v2_stat.atime,
                                        entry_v2_stat.mtime,
                                        entry_v2_stat.ctime,
                                        entry_v2_stat.blocks,
                                        entry_v2_stat.first_direct_byte);
#endif
                          if ((grub_le_to_cpu16 (entry_v2_stat.mode) & S_IFLNK)
                              == S_IFLNK)
                            entry_type = GRUB_FSHELP_SYMLINK;
                          else
                            entry_type = GRUB_FSHELP_REG;
                        }
                    }
                  else
                    {
                      /* Pseudo file ".." never has stat block.  */
                      if (grub_strcmp (entry_name, ".."))
                        grub_dprintf ("reiserfs",
                                      "Warning : %s has no stat block !\n",
                                      entry_name);
                      grub_free (entry_item);
                      continue;
                    }
                }
              if (hook (entry_name, entry_type, entry_item, closure))
                {
                  grub_dprintf ("reiserfs", "Found : %s, type=%d\n",
                                entry_name, entry_type);
                  ret = 1;
                  goto found;
                }

              *entry_name = 0; /* Make sure next entry name (which is just
                                  before this one in disk order) stops before
                                  the current one.  */
            }
        }

      if (next_offset == 0)
        break;

      grub_reiserfs_set_key_offset (&(item_headers[block_position].key),
                                    next_offset);
      if (grub_reiserfs_get_item (data, &(item_headers[block_position].key),
                                  &directory_item) != GRUB_ERR_NONE)
        goto fail;
      block_number = directory_item.block_number;
      block_position = directory_item.block_position;
      next_offset = directory_item.next_offset;
    }
  while (block_number);

 found:
  assert (grub_errno == GRUB_ERR_NONE);
  grub_free (block_header);
  return ret;
 fail:
  assert (grub_errno != GRUB_ERR_NONE);
  grub_free (block_header);
  return 0;
}

/****************************************************************************/
/* grub api functions */
/****************************************************************************/

/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_reiserfs_open (struct grub_file *file, const char *name)
{
  struct grub_reiserfs_data *data = 0;
  struct grub_fshelp_node root, *found = 0, info;
  struct grub_reiserfs_key key;
  grub_uint32_t block_number;
  grub_uint16_t entry_version, block_size, entry_location;

  grub_dl_ref (my_mod);
  data = grub_reiserfs_mount (file->device->disk);
  if (! data)
    goto fail;
  block_size = grub_le_to_cpu16 (data->superblock.block_size);
  key.directory_id = grub_cpu_to_le32 (1);
  key.object_id = grub_cpu_to_le32 (2);
  key.u.v2.offset_type = 0;
  grub_reiserfs_set_key_type (&key, GRUB_REISERFS_DIRECTORY, 2);
  grub_reiserfs_set_key_offset (&key, 1);
  if (grub_reiserfs_get_item (data, &key, &root) != GRUB_ERR_NONE)
    goto fail;
  if (root.block_number == 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "unable to find root item");
      goto fail; /* Should never happen since checked at mount.  */
    }
  grub_fshelp_find_file (name, &root, &found,
                         grub_reiserfs_iterate_dir, 0,
                         grub_reiserfs_read_symlink, GRUB_FSHELP_REG);
  if (grub_errno)
    goto fail;
  key.directory_id = found->header.key.directory_id;
  key.object_id = found->header.key.object_id;
  grub_reiserfs_set_key_type (&key, GRUB_REISERFS_STAT, 2);
  grub_reiserfs_set_key_offset (&key, 0);
  if (grub_reiserfs_get_item (data, &key, &info) != GRUB_ERR_NONE)
    goto fail;
  if (info.block_number == 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "unable to find searched item");
      goto fail;
    }
  entry_version = grub_le_to_cpu16 (info.header.version);
  entry_location = grub_le_to_cpu16 (info.header.item_location);
  block_number = info.block_number;
  if (entry_version == 0) /* Version 1 stat item. */
    {
      struct grub_reiserfs_stat_item_v1 entry_v1_stat;
      grub_disk_read (data->disk,
                      block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                      entry_location
                      + (((grub_off_t) block_number * block_size)
                         & (GRUB_DISK_SECTOR_SIZE - 1)),
                      sizeof (entry_v1_stat), &entry_v1_stat);
      if (grub_errno)
        goto fail;
      file->size = (grub_off_t) grub_le_to_cpu64 (entry_v1_stat.size);
    }
  else
    {
      struct grub_reiserfs_stat_item_v2 entry_v2_stat;
      grub_disk_read (data->disk,
                      block_number * (block_size  >> GRUB_DISK_SECTOR_BITS),
                      entry_location
                      + (((grub_off_t) block_number * block_size)
                         & (GRUB_DISK_SECTOR_SIZE - 1)),
                      sizeof (entry_v2_stat), &entry_v2_stat);
      if (grub_errno)
        goto fail;
      file->size = (grub_off_t) grub_le_to_cpu64 (entry_v2_stat.size);
    }
  grub_dprintf ("reiserfs", "file size : %d (%08x%08x)\n",
                (unsigned int) file->size,
                (unsigned int) (file->size >> 32), (unsigned int) file->size);
  file->offset = 0;
  file->data = found;
  return GRUB_ERR_NONE;

 fail:
  assert (grub_errno != GRUB_ERR_NONE);
  grub_free (found);
  grub_free (data);
  grub_dl_unref (my_mod);
  return grub_errno;
}

static grub_ssize_t
grub_reiserfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  unsigned int indirect_block, indirect_block_count;
  struct grub_reiserfs_key key;
  struct grub_fshelp_node *node = file->data;
  struct grub_reiserfs_data *data = node->data;
  struct grub_fshelp_node found;
  grub_uint16_t block_size = grub_le_to_cpu16 (data->superblock.block_size);
  grub_uint16_t item_size;
  grub_uint32_t *indirect_block_ptr = 0;
  grub_uint64_t current_key_offset = 1;
  grub_off_t initial_position, current_position, final_position, length;
  grub_disk_addr_t block;
  grub_off_t offset;

  key.directory_id = node->header.key.directory_id;
  key.object_id = node->header.key.object_id;
  key.u.v2.offset_type = 0;
  grub_reiserfs_set_key_type (&key, GRUB_REISERFS_ANY, 2);
  initial_position = file->offset;
  current_position = 0;
  final_position = MIN (len + initial_position, file->size);
  grub_dprintf ("reiserfs",
		"Reading from %lld to %lld (%lld instead of requested %ld)\n",
		(unsigned long long) initial_position,
		(unsigned long long) final_position,
		(unsigned long long) (final_position - initial_position),
		(unsigned long) len);
  while (current_position < final_position)
    {
      grub_reiserfs_set_key_offset (&key, current_key_offset);

      if (grub_reiserfs_get_item (data, &key, &found) != GRUB_ERR_NONE)
        goto fail;
      if (found.block_number == 0)
        goto fail;
      item_size = grub_le_to_cpu16 (found.header.item_size);
      switch (found.type)
        {
        case GRUB_REISERFS_DIRECT:
          block = (grub_disk_addr_t)found.block_number \
				  * ((grub_disk_addr_t)block_size  >> GRUB_DISK_SECTOR_BITS);
          grub_dprintf ("reiserfs_blocktype", "D: %u\n", (unsigned) block);
          if (initial_position < current_position + item_size)
            {
              offset = MAX ((signed) (initial_position - current_position), 0);
              length = (MIN (item_size, final_position - current_position)
                        - offset);
              grub_dprintf ("reiserfs",
                            "Reading direct block %u from %u to %u...\n",
                            (unsigned) block, (unsigned) offset,
                            (unsigned) (offset + length));
              found.data->disk->read_hook = file->read_hook;
	      found.data->disk->closure = file->closure;
              grub_disk_read (found.data->disk,
                              block,
                              offset
                              + grub_le_to_cpu16 (found.header.item_location),
                              length, buf);
              found.data->disk->read_hook = 0;
              if (grub_errno)
                goto fail;
              buf += length;
              current_position += offset + length;
            }
          else
            current_position += item_size;
          break;
        case GRUB_REISERFS_INDIRECT:
          indirect_block_count = item_size / sizeof (*indirect_block_ptr);
          indirect_block_ptr = grub_malloc (item_size);
          if (! indirect_block_ptr)
            goto fail;
          grub_disk_read (found.data->disk,
                          found.block_number * (block_size >> GRUB_DISK_SECTOR_BITS),
                          grub_le_to_cpu16 (found.header.item_location),
                          item_size, indirect_block_ptr);
          if (grub_errno)
            goto fail;
          found.data->disk->read_hook = file->read_hook;
          for (indirect_block = 0;
               indirect_block < indirect_block_count
                 && current_position < final_position;
               indirect_block++)
            {
              block = grub_le_to_cpu32 (indirect_block_ptr[indirect_block]) *
                      (block_size >> GRUB_DISK_SECTOR_BITS);
              grub_dprintf ("reiserfs_blocktype", "I: %u\n", (unsigned) block);
              if (current_position + block_size >= initial_position)
                {
                  offset = MAX ((signed) (initial_position - current_position),
                                0);
                  length = (MIN (block_size, final_position - current_position)
                            - offset);
                  grub_dprintf ("reiserfs",
                                "Reading indirect block %u from %u to %u...\n",
                                (unsigned) block, (unsigned) offset,
                                (unsigned) (offset + length));
#if 0
                  grub_dprintf ("reiserfs",
                                "\nib=%04d/%04d, ip=%d, cp=%d, fp=%d, off=%d, l=%d, tl=%d\n",
                                indirect_block + 1, indirect_block_count,
                                initial_position, current_position,
                                final_position, offset, length, len);
#endif
                  grub_disk_read (found.data->disk, block, offset, length, buf);
                  if (grub_errno)
                    goto fail;
                  buf += length;
                  current_position += offset + length;
                }
              else
                current_position += block_size;
            }
          found.data->disk->read_hook = 0;
          grub_free (indirect_block_ptr);
          indirect_block_ptr = 0;
          break;
        default:
          goto fail;
        }
      current_key_offset = current_position + 1;
    }

  grub_dprintf ("reiserfs",
		"Have successfully read %lld bytes (%ld requested)\n",
		(unsigned long long) (current_position - initial_position),
		(unsigned long) len);
  return current_position - initial_position;

#if 0
  switch (found.type)
    {
      case GRUB_REISERFS_DIRECT:
        read_length = MIN (len, item_size - file->offset);
        grub_disk_read (found.data->disk,
                        (found.block_number * block_size) / GRUB_DISK_SECTOR_SIZE,
                        grub_le_to_cpu16 (found.header.item_location) + file->offset,
                        read_length, buf);
        if (grub_errno)
          goto fail;
        break;
      case GRUB_REISERFS_INDIRECT:
        indirect_block_count = item_size / sizeof (*indirect_block_ptr);
        indirect_block_ptr = grub_malloc (item_size);
        if (!indirect_block_ptr)
          goto fail;
        grub_disk_read (found.data->disk,
                        (found.block_number * block_size) / GRUB_DISK_SECTOR_SIZE,
                        grub_le_to_cpu16 (found.header.item_location),
                        item_size, (char *) indirect_block_ptr);
        if (grub_errno)
          goto fail;
        len = MIN (len, file->size - file->offset);
        for (indirect_block = file->offset / block_size;
             indirect_block < indirect_block_count && read_length < len;
             indirect_block++)
          {
            read = MIN (block_size, len - read_length);
            grub_disk_read (found.data->disk,
                            (grub_le_to_cpu32 (indirect_block_ptr[indirect_block]) * block_size) / GRUB_DISK_SECTOR_SIZE,
                            file->offset % block_size, read,
                            ((void *) buf) + read_length);
            if (grub_errno)
              goto fail;
            read_length += read;
          }
        grub_free (indirect_block_ptr);
        break;
      default:
        goto fail;
    }

  return read_length;
#endif

 fail:
  grub_free (indirect_block_ptr);
  return 0;
}

/* Close the file FILE.  */
static grub_err_t
grub_reiserfs_close (grub_file_t file)
{
  struct grub_fshelp_node *node = file->data;
  struct grub_reiserfs_data *data = node->data;

  grub_free (data);
  grub_free (node);
  grub_dl_unref (my_mod);
  return GRUB_ERR_NONE;
}

struct grub_reiserfs_dir_closure
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
  struct grub_reiserfs_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook (filename, &info, c->closure);
}

/* Call HOOK with each file under DIR.  */
static grub_err_t
grub_reiserfs_dir (grub_device_t device, const char *path,
                   int (*hook) (const char *filename,
				const struct grub_dirhook_info *info,
				void *closure),
		   void *closure)
{
  struct grub_reiserfs_data *data = 0;
  struct grub_fshelp_node root, *found;
  struct grub_reiserfs_key root_key;
  struct grub_reiserfs_dir_closure c;

  grub_dl_ref (my_mod);
  data = grub_reiserfs_mount (device->disk);
  if (! data)
    goto fail;
  root_key.directory_id = grub_cpu_to_le32 (1);
  root_key.object_id = grub_cpu_to_le32 (2);
  root_key.u.v2.offset_type = 0;
  grub_reiserfs_set_key_type (&root_key, GRUB_REISERFS_DIRECTORY, 2);
  grub_reiserfs_set_key_offset (&root_key, 1);
  if (grub_reiserfs_get_item (data, &root_key, &root) != GRUB_ERR_NONE)
    goto fail;
  if (root.block_number == 0)
    {
      grub_error(GRUB_ERR_BAD_FS, "root not found");
      goto fail;
    }
  grub_fshelp_find_file (path, &root, &found, grub_reiserfs_iterate_dir, 0,
                         grub_reiserfs_read_symlink, GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;
  c.hook = hook;
  c.closure = closure;
  grub_reiserfs_iterate_dir (found, iterate, &c);
  grub_free (data);
  grub_dl_unref (my_mod);
  return GRUB_ERR_NONE;

 fail:
  grub_free (data);
  grub_dl_unref (my_mod);
  return grub_errno;
}

/* Return the label of the device DEVICE in LABEL.  The label is
   returned in a grub_malloc'ed buffer and should be freed by the
   caller.  */
static grub_err_t
grub_reiserfs_label (grub_device_t device, char **label)
{
  *label = grub_malloc (REISERFS_MAX_LABEL_LENGTH);
  if (*label)
    {
      grub_disk_read (device->disk,
                      REISERFS_SUPER_BLOCK_OFFSET / GRUB_DISK_SECTOR_SIZE,
                      REISERFS_LABEL_OFFSET, REISERFS_MAX_LABEL_LENGTH,
                      *label);
    }
  return grub_errno;
}

static grub_err_t
grub_reiserfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_reiserfs_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_reiserfs_mount (disk);
  if (data)
    {
      *uuid = grub_xasprintf ("%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			     grub_be_to_cpu16 (data->superblock.uuid[0]),
			     grub_be_to_cpu16 (data->superblock.uuid[1]),
			     grub_be_to_cpu16 (data->superblock.uuid[2]),
			     grub_be_to_cpu16 (data->superblock.uuid[3]),
			     grub_be_to_cpu16 (data->superblock.uuid[4]),
			     grub_be_to_cpu16 (data->superblock.uuid[5]),
			     grub_be_to_cpu16 (data->superblock.uuid[6]),
			     grub_be_to_cpu16 (data->superblock.uuid[7]));
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

struct grub_fs grub_reiserfs_fs =
  {
    .name = "reiserfs",
    .dir = grub_reiserfs_dir,
    .open = grub_reiserfs_open,
    .read = grub_reiserfs_read,
    .close = grub_reiserfs_close,
    .label = grub_reiserfs_label,
    .uuid = grub_reiserfs_uuid,
    .next = 0
  };
