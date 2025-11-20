/* radare2: Be File System - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <r_util.h>

// BFS Magic numbers
#define BFS_SUPER_MAGIC1 0x42465331 // "BFS1"
#define OBS_SUPER_MAGIC1 0x4f425331 // "OBS1" for OpenBFS
#define BFS_SUPER_MAGIC2 0xdd121031
#define BFS_SUPER_MAGIC3 0x00000000
#define BFS_INODE_MAGIC1 0x3bbe0ad9
#define BFS_BTREE_MAGIC 0x69f6c2e8

#define BFS_BYTEORDER_NATIVE 0x42494745
#define BFS_CLEAN 0x434C454E

#define B_OS_NAME_LENGTH 32
#define BFS_SYMLINK_LEN 144
#define BFS_NUM_DIRECT_BLOCKS 12
#define BTREE_ALIGN 8
#define BTREE_ALIGN 8

// Inode flags
#define BEFS_INODE_IN_USE 0x00000001
#define BEFS_ATTR_INODE 0x00000004
#define BEFS_INODE_LOGGED 0x00000008
#define BEFS_INODE_DELETED 0x00000010
#define BEFS_LONG_SYMLINK 0x00000040
#define BEFS_PERMANENT_FLAG 0x0000ffff
#define BEFS_INODE_NO_CREATE 0x00010000
#define BEFS_INODE_WAS_WRITTEN 0x00020000
#define BEFS_NO_TRANSACTION 0x00040000

// File types
#define BEFS_FT_UNKNOWN 0
#define BEFS_FT_FILE 1
#define BEFS_FT_DIRECTORY 2
#define BEFS_FT_SYMLINK 3

// Block run (extent)
R_PACKED(
	typedef struct {
		ut32 allocation_group;
		ut16 start;
		ut16 len;
	})
bfs_block_run_t;

// Data stream
R_PACKED(
	typedef struct {
		bfs_block_run_t direct[BFS_NUM_DIRECT_BLOCKS];
		ut64 max_direct_range;
		bfs_block_run_t indirect;
		ut64 max_indirect_range;
		bfs_block_run_t double_indirect;
		ut64 max_double_indirect_range;
		ut64 size;
	})
bfs_data_stream_t;

// Small data entry
R_PACKED(
	typedef struct {
		ut32 type;
		ut16 name_size;
		ut16 data_size;
		char name[1];
	})
bfs_small_data_t;

// BFS Inode
R_PACKED(
	typedef struct {
		ut32 magic1;
		bfs_block_run_t inode_num;
		ut32 uid;
		ut32 gid;
		ut32 mode;
		ut32 flags;
		ut64 create_time;
		ut64 last_modified_time;
		bfs_block_run_t parent;
		bfs_block_run_t attributes;
		ut32 type;
		ut32 inode_size;
		ut32 etc;
		union {
			bfs_data_stream_t datastream;
			char symlink[BFS_SYMLINK_LEN];
		} data;
		ut32 pad[4];
		bfs_small_data_t small_data[1];
	})
bfs_inode_t;

// BFS Superblock
R_PACKED(
	typedef struct {
		char name[B_OS_NAME_LENGTH];
		ut32 magic1;
		ut32 fs_byte_order;
		ut32 block_size;
		ut32 block_shift;
		ut64 num_blocks;
		ut64 used_blocks;
		ut32 inode_size;
		ut32 magic2;
		ut32 blocks_per_ag;
		ut32 ag_shift;
		ut32 num_ags;
		ut32 flags;
		bfs_block_run_t log_blocks;
		ut64 log_start;
		ut64 log_end;
		ut32 magic3;
		bfs_block_run_t root_dir;
		bfs_block_run_t indices;
	})
bfs_super_block_t;

// B+tree superblock
R_PACKED(
	typedef struct {
		ut32 magic;
		ut32 node_size;
		ut32 max_depth;
		ut32 data_type;
		ut64 root_node_ptr;
		ut64 free_node_ptr;
		ut64 max_size;
	})
bfs_btree_super_t;

// B+tree node header
R_PACKED(
	typedef struct {
		ut64 left;
		ut64 right;
		ut64 overflow;
		ut16 all_key_count;
		ut16 all_key_length;
	})
bfs_btree_nodehead_t;

// Parsed inode cache entry
typedef struct {
	ut64 inode_num;
	ut64 parent_inode_num;
	char *name;
	bfs_inode_t *inode;
	RList *dent_nodes; // Directory entries
	bool is_directory;
	bool parsed;
} bfs_inode_t_cache;

// Filesystem context
typedef struct {
	RIOBind *iob;
	ut64 delta;
	ut32 block_size;
	ut32 block_shift;
	ut32 inode_size;
	ut64 blocks_per_ag;
	ut32 ag_shift;
	ut32 num_ags;
	bfs_block_run_t root_dir;
	HtUP *inodes; // Hash table: inode_num -> bfs_inode_t_cache
	bool mounted;
	bool is_openbfs;
	bool is_le;
} bfs_ctx_t;

static bool bfs_read_at(bfs_ctx_t *ctx, ut64 offset, ut8 *buf, int len) {
	if (!ctx || !ctx->iob || !ctx->iob->read_at) {
		return false;
	}
	return ctx->iob->read_at (ctx->iob->io, ctx->delta + offset, buf, len);
}

static ut32 bfs_read32(bfs_ctx_t *ctx, ut8 *buf);
static ut16 bfs_read16(bfs_ctx_t *ctx, ut8 *buf);
static ut64 bfs_read64(bfs_ctx_t *ctx, ut8 *buf);

static ut64 bfs_block_to_offset(bfs_ctx_t *ctx, bfs_block_run_t *run) {
	ut64 ag_offset = (ut64)bfs_read32 (ctx, (ut8 *)&run->allocation_group) << ctx->ag_shift;
	ut64 block_offset = (ut64)bfs_read16 (ctx, (ut8 *)&run->start) << ctx->block_shift;
	return ag_offset + block_offset;
}

static ut64 bfs_block_run_to_block_index(bfs_ctx_t *ctx, const bfs_block_run_t *run) {
	ut64 ag = bfs_read32 (ctx, (ut8 *)&run->allocation_group);
	ut64 start = bfs_read16 (ctx, (ut8 *)&run->start);
	if (!ctx->blocks_per_ag) {
		if (ctx->ag_shift > ctx->block_shift) {
			ut32 diff = ctx->ag_shift - ctx->block_shift;
			ctx->blocks_per_ag = diff >= 63? (1ULL << 63): (1ULL << diff);
		} else {
			ctx->blocks_per_ag = 1;
		}
	}
	return ag * ctx->blocks_per_ag + start;
}

static bfs_inode_t *bfs_read_inode_block(bfs_ctx_t *ctx, ut64 block_index) {
	ut64 offset = block_index << ctx->block_shift;
	bfs_inode_t *inode = malloc (ctx->inode_size);
	if (!inode) {
		return NULL;
	}
	if (!bfs_read_at (ctx, offset, (ut8 *)inode, ctx->inode_size)) {
		free (inode);
		return NULL;
	}
	return inode;
}

static bool bfs_read_stream(bfs_ctx_t *ctx, bfs_inode_t *inode, ut64 offset, ut8 *buf, ut32 len) {
	bfs_data_stream_t *ds;
	ut64 total = 0;
	ut64 pos;
	ut32 remaining;
	int i;

	if (!ctx || !inode || (!buf && len)) {
		return false;
	}
	if (!len) {
		return true;
	}

	ds = &inode->data.datastream;
	for (i = 0; i < BFS_NUM_DIRECT_BLOCKS; i++) {
		ut16 run_len = bfs_read16 (ctx, (ut8 *)&ds->direct[i].len);
		if (!run_len) {
			continue;
		}
		total += ((ut64)run_len) << ctx->block_shift;
	}
	if (offset + len > total) {
		return false;
	}

	pos = offset;
	remaining = len;
	while (remaining > 0) {
		ut64 consumed = 0;
		bool found = false;
		for (i = 0; i < BFS_NUM_DIRECT_BLOCKS; i++) {
			bfs_block_run_t *run = &ds->direct[i];
			ut16 run_len = bfs_read16 (ctx, (ut8 *)&run->len);
			ut64 run_size;
			if (!run_len) {
				continue;
			}
			run_size = ((ut64)run_len) << ctx->block_shift;
			if (pos < consumed + run_size) {
				ut64 offset_in_run = pos - consumed;
				ut64 disk_offset = bfs_block_to_offset (ctx, run) + offset_in_run;
				ut32 chunk = R_MIN ((ut32) (run_size - offset_in_run), remaining);
				if (!bfs_read_at (ctx, disk_offset, buf, chunk)) {
					return false;
				}
				buf += chunk;
				pos += chunk;
				remaining -= chunk;
				found = true;
				break;
			}
			consumed += run_size;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

static bfs_inode_t_cache *bfs_get_inode(bfs_ctx_t *ctx, ut64 inode_num) {
	return ht_up_find (ctx->inodes, inode_num, NULL);
}

static void bfs_free_inode(bfs_inode_t_cache *inode) {
	if (!inode) {
		return;
	}
	r_list_free (inode->dent_nodes);
	free (inode->name);
	free (inode->inode);
	free (inode);
}

static bool bfs_free_inode_cb(void *user, const ut64 key, const void *value) {
	bfs_free_inode ((bfs_inode_t_cache *)value);
	return true;
}

static ut64 bfs_block_run_to_block_index(bfs_ctx_t *ctx, const bfs_block_run_t *run);
static bfs_inode_t *bfs_read_inode_block(bfs_ctx_t *ctx, ut64 block_index);
static bool bfs_read_stream(bfs_ctx_t *ctx, bfs_inode_t *inode, ut64 offset, ut8 *buf, ut32 len);
static bool bfs_walk_directory(bfs_ctx_t *ctx, bfs_inode_t *dir_inode, ut64 parent_inode_num);

typedef struct {
	RList *list;
	ut64 parent_inode_num;
	bfs_ctx_t *bfs_ctx;
} bfs_dir_iter_ctx_t;

typedef struct {
	const char *name;
	ut64 parent_inode_num;
	ut64 *result;
} bfs_find_ctx_t;

static ut32 bfs_read32(bfs_ctx_t *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le32 (buf): r_read_be32 (buf);
}

static ut16 bfs_read16(bfs_ctx_t *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le16 (buf): r_read_be16 (buf);
}

static ut64 bfs_read64(bfs_ctx_t *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le64 (buf): r_read_be64 (buf);
}

static bool bfs_find_inode_by_name_cb(void *user, const ut64 key, const void *value) {
	bfs_find_ctx_t *ctx = (bfs_find_ctx_t *)user;
	bfs_inode_t_cache *cache = (bfs_inode_t_cache *)value;
	if (!cache || !cache->name || cache->parent_inode_num != ctx->parent_inode_num) {
		return true;
	}
	if (strcmp (cache->name, ctx->name) == 0) {
		*ctx->result = cache->inode_num;
		return false; // Stop iteration
	}
	return true;
}

static ut64 bfs_resolve_path(bfs_ctx_t *ctx, const char *path) {
	if (!path || !*path || strcmp (path, "/") == 0) {
		return 0;
	}
	RList *components = r_str_split_list ((char *)path, "/", 0);
	if (!components) {
		return 0;
	}
	ut64 current_inode = 0;
	RListIter *iter;
	const char *comp;
	r_list_foreach (components, iter, comp) {
		if (!comp || !*comp) {
			continue;
		}
		ut64 found = 0;
		bfs_find_ctx_t find_ctx = { comp, current_inode, &found };
		ht_up_foreach (ctx->inodes, bfs_find_inode_by_name_cb, &find_ctx);
		if (found == 0) {
			r_list_free (components);
			return 0;
		}
		current_inode = found;
	}
	r_list_free (components);
	return current_inode;
}

static bool bfs_dir_iter_cb(void *user, const ut64 key, const void *value) {
	bfs_dir_iter_ctx_t *ctx = (bfs_dir_iter_ctx_t *)user;
	RList *list = ctx->list;
	ut64 parent_inode_num = ctx->parent_inode_num;
	bfs_ctx_t *bfs_ctx = ctx->bfs_ctx;
	bfs_inode_t_cache *cache = (bfs_inode_t_cache *)value;
	if (!cache || !cache->inode || !cache->name || cache->parent_inode_num != parent_inode_num) {
		return true;
	}

	RFSFile *fsf = r_fs_file_new (NULL, cache->name);
	if (!fsf) {
		return true;
	}

	ut32 mode = bfs_read32 (bfs_ctx, (ut8 *)&cache->inode->mode);
	if ((mode & 0xF000) == 0x4000) { // Directory
		fsf->type = R_FS_FILE_TYPE_DIRECTORY;
	} else if ((mode & 0xF000) == 0x8000) { // Regular file
		fsf->type = R_FS_FILE_TYPE_REGULAR;
		fsf->size = bfs_read64 (bfs_ctx, (ut8 *)&cache->inode->data.datastream.size);
	} else {
		fsf->type = R_FS_FILE_TYPE_SPECIAL;
	}

	fsf->time = bfs_read64 (bfs_ctx, (ut8 *)&cache->inode->last_modified_time) / 1000000; // Convert to seconds

	r_list_append (list, fsf);
	return true;
}

static bool fs_bfs_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);

	bfs_ctx_t *ctx = R_NEW0 (bfs_ctx_t);
	ctx->iob = &root->iob;
	ctx->delta = root->delta;
	ctx->block_size = 1024; // Default block size for BFS
	ctx->inodes = ht_up_new0 ();

	// Read superblock from offset 512 (block 1 start)
	bfs_super_block_t sb;
	ut64 sb_offset = 512;
	if (!bfs_read_at (ctx, sb_offset, (ut8 *)&sb, sizeof (sb))) {
		R_LOG_ERROR ("Failed to read BFS superblock");
		goto fail;
	}

	ut32 magic_le = r_read_le32 ((ut8 *)&sb.magic1);
	ut32 magic_be = r_read_be32 ((ut8 *)&sb.magic1);
	ut32 magic1 = 0;
	if (magic_le == BFS_SUPER_MAGIC1 || magic_le == OBS_SUPER_MAGIC1) {
		ctx->is_le = true;
		magic1 = magic_le;
	} else if (magic_be == BFS_SUPER_MAGIC1 || magic_be == OBS_SUPER_MAGIC1) {
		ctx->is_le = false;
		magic1 = magic_be;
	} else {
		R_LOG_ERROR ("Invalid BFS superblock magic");
		goto fail;
	}
	ctx->is_openbfs = (magic1 == OBS_SUPER_MAGIC1);

	ctx->block_size = bfs_read32 (ctx, (ut8 *)&sb.block_size);
	if (!ctx->block_size || (ctx->block_size &(ctx->block_size - 1))) {
		R_LOG_WARN ("Unexpected BFS block size");
	}
	ctx->block_shift = bfs_read32 (ctx, (ut8 *)&sb.block_shift);
	ctx->inode_size = bfs_read32 (ctx, (ut8 *)&sb.inode_size);
	if (!ctx->inode_size) {
		ctx->inode_size = ctx->block_size;
	}
	ctx->ag_shift = bfs_read32 (ctx, (ut8 *)&sb.ag_shift);
	if (ctx->ag_shift < ctx->block_shift) {
		ctx->ag_shift = ctx->block_shift;
	}
	ctx->num_ags = bfs_read32 (ctx, (ut8 *)&sb.num_ags);
	{
		ut32 diff = ctx->ag_shift - ctx->block_shift;
		ctx->blocks_per_ag = diff >= 63? (1ULL << 63): (1ULL << diff);
	}
	ctx->root_dir = sb.root_dir;

	// Walk the root directory tree
	{
		ut64 root_block = bfs_block_run_to_block_index (ctx, &ctx->root_dir);
		bfs_inode_t *root_inode = bfs_read_inode_block (ctx, root_block);
		if (!root_inode) {
			R_LOG_ERROR ("Failed to read root directory inode");
			goto fail;
		}
		if (!bfs_walk_directory (ctx, root_inode, 0)) {
			free (root_inode);
			R_LOG_ERROR ("Failed to walk root directory B+tree");
			goto fail;
		}
		free (root_inode);
	}

	ctx->mounted = true;
	root->ptr = ctx;
	return true;

fail:
	ht_up_free (ctx->inodes);
	free (ctx);
	return false;
}

static void fs_bfs_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);

	bfs_ctx_t *ctx = root->ptr;
	if (!ctx) {
		return;
	}

	if (ctx->inodes) {
		ht_up_foreach (ctx->inodes, bfs_free_inode_cb, NULL);
		ht_up_free (ctx->inodes);
	}

	free (ctx);
	root->ptr = NULL;
}

static bool bfs_walk_directory(bfs_ctx_t *ctx, bfs_inode_t *dir_inode, ut64 parent_inode_num) {
	bfs_btree_super_t super;
	ut32 node_size;
	ut32 level;
	ut64 node_off;
	ut8 *node_buf = NULL;

	R_RETURN_VAL_IF_FAIL (ctx && dir_inode, false);

	if (!bfs_read_stream (ctx, dir_inode, 0, (ut8 *)&super, sizeof (super))) {
		return false;
	}
	if (bfs_read32 (ctx, (ut8 *)&super.magic) != BFS_BTREE_MAGIC) {
		return false;
	}

	node_size = bfs_read32 (ctx, (ut8 *)&super.node_size);
	if (!node_size) {
		node_size = ctx->block_size;
	}
	level = bfs_read32 (ctx, (ut8 *)&super.max_depth);
	if (!level) {
		level = 1;
	}
	node_off = bfs_read64 (ctx, (ut8 *)&super.root_node_ptr);
	if (node_off == UT64_MAX) {
		return true;
	}

	node_buf = calloc (1, node_size);
	if (!node_buf) {
		return false;
	}

	if (level > 0) {
		ut32 depth = level - 1;
		while (depth--) {
			bfs_btree_nodehead_t *node_head;
			ut16 key_count;
			ut16 key_length;
			ut16 *key_offsets;
			ut64 *values;
			size_t key_section;
			size_t align_pad;

			if (!bfs_read_stream (ctx, dir_inode, node_off, node_buf, node_size)) {
				free (node_buf);
				return false;
			}
			node_head = (bfs_btree_nodehead_t *)node_buf;
			key_count = bfs_read16 (ctx, (ut8 *)&node_head->all_key_count);
			key_length = bfs_read16 (ctx, (ut8 *)&node_head->all_key_length);
			if (!key_count) {
				free (node_buf);
				return false;
			}
			key_section = sizeof (bfs_btree_nodehead_t) + key_length;
			if (key_section > node_size) {
				free (node_buf);
				return false;
			}
			align_pad = (BTREE_ALIGN - (key_section % BTREE_ALIGN)) % BTREE_ALIGN;
			key_offsets = (ut16 *) (node_buf + sizeof (bfs_btree_nodehead_t) + key_length + align_pad);
			values = (ut64 *) ((ut8 *)key_offsets + key_count * sizeof (ut16));
			node_off = bfs_read64 (ctx, (ut8 *)&values[0]);
		}
	}

	while (1) {
		bfs_btree_nodehead_t *node_head;
		ut16 key_count;
		ut16 key_length;
		ut8 *key_data;
		ut16 *key_offsets;
		ut64 *values;
		size_t key_section;
		size_t align_pad;
		ut16 prev_end = 0;
		ut16 i;

		if (!bfs_read_stream (ctx, dir_inode, node_off, node_buf, node_size)) {
			free (node_buf);
			return false;
		}
		node_head = (bfs_btree_nodehead_t *)node_buf;
		key_count = bfs_read16 (ctx, (ut8 *)&node_head->all_key_count);
		key_length = bfs_read16 (ctx, (ut8 *)&node_head->all_key_length);
		key_section = sizeof (bfs_btree_nodehead_t) + key_length;
		if (key_section > node_size) {
			free (node_buf);
			return false;
		}
		align_pad = (BTREE_ALIGN - (key_section % BTREE_ALIGN)) % BTREE_ALIGN;
		key_data = node_buf + sizeof (bfs_btree_nodehead_t);
		key_offsets = (ut16 *) (key_data + key_length + align_pad);
		values = (ut64 *) ((ut8 *)key_offsets + key_count * sizeof (ut16));

		for (i = 0; i < key_count; i++) {
			ut16 end = bfs_read16 (ctx, (ut8 *)&key_offsets[i]);
			ut16 name_len;
			const char *name_ptr;
			ut64 inode_block;
			bfs_inode_t *child_inode;
			bfs_inode_t_cache *cache;
			ut32 mode;

			if (end > key_length) {
				end = key_length;
			}
			if (end < prev_end) {
				continue;
			}
			name_len = end - prev_end;
			if (!name_len) {
				prev_end = end;
				continue;
			}
			name_ptr = (const char *) (key_data + prev_end);
			prev_end = end;
			if ((name_len == 1 && name_ptr[0] == '.') ||
				(name_len == 2 && name_ptr[0] == '.' && name_ptr[1] == '.')) {
				continue;
			}

			inode_block = bfs_read64 (ctx, (ut8 *)&values[i]);
			child_inode = bfs_read_inode_block (ctx, inode_block);
			if (!child_inode) {
				continue;
			}
			cache = bfs_get_inode (ctx, inode_block);
			if (!cache) {
				cache = R_NEW0 (bfs_inode_t_cache);
				if (!cache) {
					free (child_inode);
					free (node_buf);
					return false;
				}
				cache->inode_num = inode_block;
				cache->parent_inode_num = parent_inode_num;
				cache->name = r_str_ndup (name_ptr, name_len);
				cache->inode = child_inode;
				cache->dent_nodes = NULL;
				ht_up_insert (ctx->inodes, inode_block, cache);
			} else {
				if (!cache->name) {
					cache->name = r_str_ndup (name_ptr, name_len);
				}
				cache->parent_inode_num = parent_inode_num;
				if (!cache->inode) {
					cache->inode = child_inode;
				} else {
					free (child_inode);
				}
			}

			mode = bfs_read32 (ctx, (ut8 *)&cache->inode->mode);
			cache->is_directory = (mode & 0xF000) == 0x4000;
			if (cache->is_directory && !cache->parsed) {
				cache->parsed = true;
				bfs_walk_directory (ctx, cache->inode, cache->inode_num);
			}
		}

		node_off = bfs_read64 (ctx, (ut8 *)&node_head->right);
		if (node_off == UT64_MAX) {
			break;
		}
	}

	free (node_buf);
	return true;
}

static RList *fs_bfs_dir(RFSRoot *root, const char *path, int view) {
	R_RETURN_VAL_IF_FAIL (root, NULL);

	bfs_ctx_t *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		return NULL;
	}

	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}

	ut64 parent_inode_num = bfs_resolve_path (ctx, path);
	if (parent_inode_num == 0 && strcmp (path, "/") != 0) {
		r_list_free (list);
		return NULL;
	}

	// Iterate over cached inodes and filter by parent
	bfs_dir_iter_ctx_t iter_ctx = { list, parent_inode_num, ctx };
	ht_up_foreach (ctx->inodes, bfs_dir_iter_cb, &iter_ctx);

	return list;
}

static RFSFile *fs_bfs_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);

	bfs_ctx_t *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		R_LOG_ERROR ("Open: filesystem not mounted");
		return NULL;
	}

	if (create) {
		return NULL;
	}

	ut64 inode_num = bfs_resolve_path (ctx, path);
	if (inode_num == 0 && strcmp (path, "/") != 0) {
		return NULL;
	}

	bfs_inode_t_cache *cache = NULL;
	if (inode_num != 0) {
		cache = bfs_get_inode (ctx, inode_num);
		if (!cache || !cache->inode) {
			return NULL;
		}
	}

	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}

	file->ptr = (void *) (size_t)inode_num;

	if (inode_num == 0) {
		file->type = R_FS_FILE_TYPE_DIRECTORY;
		file->size = 0;
	} else {
		ut32 mode = bfs_read32 (ctx, (ut8 *)&cache->inode->mode);
		if ((mode & 0xF000) == 0x4000) { // Directory
			file->type = R_FS_FILE_TYPE_DIRECTORY;
		} else if ((mode & 0xF000) == 0x8000) { // Regular file
			file->type = R_FS_FILE_TYPE_REGULAR;
			file->size = bfs_read64 (ctx, (ut8 *)&cache->inode->data.datastream.size);
		} else {
			file->type = R_FS_FILE_TYPE_SPECIAL;
		}
	}

	return file;
}

static bool bfs_get_block_run(bfs_ctx_t *ctx, bfs_data_stream_t *ds, ut64 block_index, bfs_block_run_t *run) {
	if (block_index < BFS_NUM_DIRECT_BLOCKS) {
		*run = ds->direct[block_index];
		return true;
	}
	ut64 indirect_index = block_index - BFS_NUM_DIRECT_BLOCKS;
	ut64 num_per_block = ctx->block_size / sizeof (bfs_block_run_t);
	if (indirect_index < num_per_block) {
		ut64 indirect_offset = bfs_block_to_offset (ctx, &ds->indirect);
		ut64 entry_offset = indirect_offset + indirect_index * sizeof (bfs_block_run_t);
		return bfs_read_at (ctx, entry_offset, (ut8 *)run, sizeof (*run));
	} else {
		indirect_index -= num_per_block;
		ut64 double_indirect_index = indirect_index / num_per_block;
		ut64 sub_index = indirect_index % num_per_block;
		ut64 double_offset = bfs_block_to_offset (ctx, &ds->double_indirect);
		ut64 double_entry_offset = double_offset + double_indirect_index * sizeof (bfs_block_run_t);
		bfs_block_run_t indirect_run;
		if (!bfs_read_at (ctx, double_entry_offset, (ut8 *)&indirect_run, sizeof (indirect_run))) {
			return false;
		}
		ut64 indirect_offset = bfs_block_to_offset (ctx, &indirect_run);
		ut64 entry_offset = indirect_offset + sub_index * sizeof (bfs_block_run_t);
		return bfs_read_at (ctx, entry_offset, (ut8 *)run, sizeof (*run));
	}
}

static int fs_bfs_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);

	bfs_ctx_t *ctx = file->root->ptr;
	if (!ctx || !ctx->mounted) {
		return -1;
	}

	ut64 inode_num = (ut64) (size_t)file->ptr;
	bfs_inode_t_cache *cache = bfs_get_inode (ctx, inode_num);
	if (!cache || !cache->inode) {
		return -1;
	}

	// For simplicity, read from direct blocks only
	bfs_data_stream_t *ds = &cache->inode->data.datastream;
	ut64 file_size = bfs_read64 (ctx, (ut8 *)&ds->size);
	if (addr >= file_size) {
		return 0;
	}
	if (addr + len > file_size) {
		len = file_size - addr;
	}

	// Find which block contains addr
	ut64 block_size = ctx->block_size;
	if (!block_size) {
		return -1;
	}
	ut64 block_index = addr / block_size;
	ut64 offset_in_block = addr % block_size;

	bfs_block_run_t run;
	if (!bfs_get_block_run (ctx, ds, block_index, &run)) {
		return 0;
	}
	if (run.len == 0) {
		return 0;
	}

	ut64 block_offset = bfs_block_to_offset (ctx, &run);
	ut64 read_offset = block_offset + offset_in_block;
	int to_read = R_MIN (len, block_size - offset_in_block);

	// Allocate buffer
	if (!file->data) {
		file->data = malloc (to_read);
	} else {
		file->data = realloc (file->data, to_read);
	}
	if (!file->data) {
		return -1;
	}

	if (bfs_read_at (ctx, read_offset, file->data, to_read)) {
		return to_read;
	}
	return -1;
}

static void fs_bfs_close(RFSFile *file) {
	R_RETURN_IF_FAIL (file);

	R_FREE (file->data);
}

static void fs_bfs_details(RFSRoot *root, RStrBuf *sb) {
	R_RETURN_IF_FAIL (root && sb);

	bfs_ctx_t *ctx = (bfs_ctx_t *)root->ptr;
	if (!ctx) {
		return;
	}

	r_strbuf_appendf (sb, "Type: %s\n", ctx->is_openbfs? "OpenBFS": "BFS (Be File System)");
	r_strbuf_appendf (sb, "Block Size: %u bytes\n", ctx->block_size);
	r_strbuf_appendf (sb, "Inode Size: %u bytes\n", ctx->inode_size);
	r_strbuf_appendf (sb, "Blocks per AG: %" PFMT64u "\n", (ut64)ctx->blocks_per_ag);
	r_strbuf_appendf (sb, "AG Shift: %u\n", ctx->ag_shift);
	r_strbuf_appendf (sb, "Number of AGs: %u\n", ctx->num_ags);
	r_strbuf_append (sb, "Purpose: BeOS/Haiku filesystem\n");
}

RFSPlugin r_fs_plugin_bfs = {
	.meta = {
		.name = "bfs",
		.desc = "BFS (Be File System)",
		.author = "pancake",
		.license = "MIT",
	},
	.open = fs_bfs_open,
	.read = fs_bfs_read,
	.close = fs_bfs_close,
	.dir = fs_bfs_dir,
	.mount = fs_bfs_mount,
	.umount = fs_bfs_umount,
	.details = fs_bfs_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_bfs,
	.version = R2_VERSION
};
#endif
