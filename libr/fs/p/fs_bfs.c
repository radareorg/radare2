/* radare2: Be File System - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <r_util.h>

// BFS Magic numbers
#define BFS_SUPER_MAGIC1 0x42465331 // "BFS1"
#define OBS_SUPER_MAGIC1 0x4f425331 // "OBS1" for OpenBFS
#define BFS_SUPER_MAGIC2 0xdd121031
#define BFS_SUPER_MAGIC3 0x15b6830e
#define BFS_INODE_MAGIC1 0x3bbe0ad9
#define BFS_BTREE_MAGIC 0x69f6c2e8

#define BFS_BYTEORDER_NATIVE 0x42494745
#define BFS_CLEAN 0x434C454E

#define B_OS_NAME_LENGTH 32
#define BFS_SYMLINK_LEN 144
#define BFS_NUM_DIRECT_BLOCKS 12

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
} bfs_inode_t_cache;

// Filesystem context
typedef struct {
	RIOBind *iob;
	ut64 delta;
	ut32 block_size;
	ut32 block_shift;
	ut32 inode_size;
	ut32 blocks_per_ag;
	ut32 ag_shift;
	ut32 num_ags;
	bfs_block_run_t root_dir;
	HtUP *inodes; // Hash table: inode_num -> bfs_inode_t_cache
	bool mounted;
	bool is_openbfs;
} bfs_ctx_t;

static bool bfs_read_at(bfs_ctx_t *ctx, ut64 offset, ut8 *buf, int len) {
	if (!ctx || !ctx->iob || !ctx->iob->read_at) {
		return false;
	}
	return ctx->iob->read_at (ctx->iob->io, ctx->delta + offset, buf, len);
}

static ut64 bfs_block_to_offset(bfs_ctx_t *ctx, bfs_block_run_t *run) {
	ut64 ag_offset = (ut64)run->allocation_group << ctx->ag_shift;
	ut64 block_offset = (ut64)run->start << ctx->block_shift;
	return ag_offset + block_offset;
}

static bfs_inode_t *bfs_read_inode(bfs_ctx_t *ctx, bfs_block_run_t *inode_addr) {
	ut64 offset = bfs_block_to_offset (ctx, inode_addr);
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

static bool bfs_walk_btree(bfs_ctx_t *ctx, ut64 node_ptr, ut64 parent_inode_num);

static bool fs_bfs_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);

	bfs_ctx_t *ctx = R_NEW0 (bfs_ctx_t);
	ctx->iob = &root->iob;
	ctx->delta = root->delta;
	ctx->block_size = 1024; // Default block size for BFS
	ctx->inodes = ht_up_new0 ();

	// Read superblock from offset 512 (block 1 start)
	bfs_super_block_t sb;
	if (!bfs_read_at (ctx, 512, (ut8 *)&sb, sizeof (sb))) {
		R_LOG_ERROR ("Failed to read BFS superblock");
		goto fail;
	}

	ut32 magic1 = r_read_le32 ((ut8 *)&sb.magic1);
	if ((magic1 != BFS_SUPER_MAGIC1 && magic1 != OBS_SUPER_MAGIC1) ||
		r_read_le32 ((ut8 *)&sb.magic2) != BFS_SUPER_MAGIC2 ||
		r_read_le32 ((ut8 *)&sb.magic3) != BFS_SUPER_MAGIC3) {
		R_LOG_ERROR ("Invalid BFS/OpenBFS superblock magic");
		goto fail;
	}
	ctx->is_openbfs = (magic1 == OBS_SUPER_MAGIC1);

	ctx->block_size = r_read_le32 ((ut8 *)&sb.block_size);
	if (ctx->block_size < 512 || ctx->block_size > 4096 || (ctx->block_size &(ctx->block_size - 1)) != 0) {
		R_LOG_ERROR ("Invalid block size");
		goto fail;
	}
	ctx->block_shift = r_read_le32 ((ut8 *)&sb.block_shift);
	if (ctx->block_shift != 31 - __builtin_clz (ctx->block_size)) {
		R_LOG_ERROR ("Invalid block shift");
		goto fail;
	}
	ctx->inode_size = r_read_le32 ((ut8 *)&sb.inode_size);
	if (ctx->inode_size < sizeof (bfs_inode_t) || ctx->inode_size > 4096) {
		R_LOG_ERROR ("Invalid inode size");
		goto fail;
	}
	ctx->blocks_per_ag = r_read_le32 ((ut8 *)&sb.blocks_per_ag);
	ctx->ag_shift = r_read_le32 ((ut8 *)&sb.ag_shift);
	ctx->num_ags = r_read_le32 ((ut8 *)&sb.num_ags);
	ctx->root_dir = sb.root_dir;

	// Walk the root directory B+tree
	if (!bfs_walk_btree (ctx, bfs_block_to_offset (ctx, &ctx->root_dir), 0)) {
		R_LOG_ERROR ("Failed to walk root directory B+tree");
		goto fail;
	}

	ctx->mounted = true;
	root->ptr = ctx;
	return true;

fail:
	if (ctx->inodes) {
		ht_up_free (ctx->inodes);
	}
	free (ctx);
	return false;
}

static bool bfs_walk_btree(bfs_ctx_t *ctx, ut64 node_ptr, ut64 parent_inode_num) {
	// Read B+tree node
	ut8 *node_buf = calloc (1, ctx->block_size);
	if (!node_buf) {
		return false;
	}

	if (!bfs_read_at (ctx, node_ptr, node_buf, ctx->block_size)) {
		free (node_buf);
		return false;
	}

	bfs_btree_nodehead_t *node = (bfs_btree_nodehead_t *)node_buf;
	ut16 key_count = r_read_le16 ((ut8 *)&node->all_key_count);
	ut16 key_length = r_read_le16 ((ut8 *)&node->all_key_length);

	if (key_count == 0) {
		free (node_buf);
		return true;
	}

	// Parse keys and values
	ut8 *key_data = node_buf + sizeof (bfs_btree_nodehead_t);
	ut16 *key_offsets = (ut16 *) (key_data + key_length);
	ut64 *values = (ut64 *) ((ut8 *)key_offsets + key_count * sizeof (ut16));

	for (int i = 0; i < key_count; i++) {
		ut64 inode_num = r_read_le64 ((ut8 *)&values[i]);

		// Get file name from key
		ut16 key_offset = r_read_le16 ((ut8 *)&key_offsets[i]);
		char *name_start = (char *)key_data + key_offset;
		size_t name_len;
		if (i + 1 < key_count) {
			ut16 next_offset = r_read_le16 ((ut8 *)&key_offsets[i + 1]);
			name_len = next_offset - key_offset;
		} else {
			name_len = key_length - key_offset;
		}
		// Trim trailing nulls or spaces
		while (name_len > 0 && (name_start[name_len - 1] == '\0' || name_start[name_len - 1] == ' ')) {
			name_len--;
		}
		if (name_len == 0) {
			continue; // Skip empty names
		}

		// Read inode
		bfs_block_run_t inode_addr = { .allocation_group = inode_num >> 16, .start = inode_num & 0xFFFF, .len = 1 };
		bfs_inode_t *inode = bfs_read_inode (ctx, &inode_addr);
		if (!inode) {
			continue;
		}

		// Cache inode
		bfs_inode_t_cache *cache = R_NEW0 (bfs_inode_t_cache);
		cache->inode_num = inode_num;
		cache->parent_inode_num = parent_inode_num;
		cache->name = r_str_ndup (name_start, name_len);
		cache->inode = inode;
		cache->dent_nodes = r_list_new ();
		ht_up_insert (ctx->inodes, inode_num, cache);

		// If this is a directory, walk its B+tree
		ut32 mode = r_read_le32 ((ut8 *)&inode->mode);
		if ((mode & 0xF000) == 0x4000) { // Directory
			ut64 btree_root = bfs_block_to_offset (ctx, &inode->data.datastream.direct[0]);
			bfs_walk_btree (ctx, btree_root, inode_num);
		}
	}

	free (node_buf);
	return true;
}

static void fs_bfs_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);

	bfs_ctx_t *ctx = root->ptr;
	if (!ctx) {
		return;
	}

	if (ctx->inodes) {
		ht_up_foreach (ctx->inodes, (HtUPForeachCallback)bfs_free_inode, NULL);
		ht_up_free (ctx->inodes);
	}

	free (ctx);
	root->ptr = NULL;
}

typedef struct {
	RList *list;
	ut64 parent_inode_num;
} bfs_dir_iter_ctx_t;

typedef struct {
	const char *name;
	ut64 parent_inode_num;
	ut64 *result;
} bfs_find_ctx_t;

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

static bool bfs_dir_iter_cb(void *user, const ut64 key, const void *value) {
	bfs_dir_iter_ctx_t *ctx = (bfs_dir_iter_ctx_t *)user;
	RList *list = ctx->list;
	ut64 parent_inode_num = ctx->parent_inode_num;
	bfs_inode_t_cache *cache = (bfs_inode_t_cache *)value;
	if (!cache || !cache->inode || !cache->name || cache->parent_inode_num != parent_inode_num) {
		return true;
	}

	RFSFile *fsf = r_fs_file_new (NULL, cache->name);
	if (!fsf) {
		return true;
	}

	ut32 mode = r_read_le32 ((ut8 *)&cache->inode->mode);
	if ((mode & 0xF000) == 0x4000) { // Directory
		fsf->type = R_FS_FILE_TYPE_DIRECTORY;
	} else if ((mode & 0xF000) == 0x8000) { // Regular file
		fsf->type = R_FS_FILE_TYPE_REGULAR;
		fsf->size = r_read_le64 ((ut8 *)&cache->inode->data.datastream.size);
	} else {
		fsf->type = R_FS_FILE_TYPE_SPECIAL;
	}

	fsf->time = r_read_le64 ((ut8 *)&cache->inode->last_modified_time) / 1000000; // Convert to seconds

	r_list_append (list, fsf);
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

	// For now, assume root directory (path == "/" or empty)
	// TODO: Implement proper path resolution
	ut64 parent_inode_num = 0; // Root parent

	// Iterate over cached inodes and filter by parent
	bfs_dir_iter_ctx_t iter_ctx = { list, parent_inode_num };
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

	// TODO: Implement proper path resolution
	// For now, only handle root directory
	if (strcmp (path, "/") == 0) {
		RFSFile *file = r_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->type = R_FS_FILE_TYPE_DIRECTORY;
		file->size = 0;
		// Root inode num is 0 or from superblock
		file->ptr = (void *)0;
		return file;
	}

	// For other paths, try to find by name (simple case: direct children of root)
	ut64 inode_num = 0;
	bfs_find_ctx_t find_ctx = { path + 1, 0, &inode_num };
	ht_up_foreach (ctx->inodes, bfs_find_inode_by_name_cb, &find_ctx);
	if (inode_num == 0) {
		return NULL; // Not found
	}

	bfs_inode_t_cache *cache = bfs_get_inode (ctx, inode_num);
	if (!cache || !cache->inode) {
		return NULL;
	}

	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}

	file->ptr = (void *) (size_t)inode_num;

	ut32 mode = r_read_le32 ((ut8 *)&cache->inode->mode);
	if ((mode & 0xF000) == 0x4000) { // Directory
		file->type = R_FS_FILE_TYPE_DIRECTORY;
	} else if ((mode & 0xF000) == 0x8000) { // Regular file
		file->type = R_FS_FILE_TYPE_REGULAR;
		file->size = r_read_le64 ((ut8 *)&cache->inode->data.datastream.size);
	} else {
		file->type = R_FS_FILE_TYPE_SPECIAL;
	}

	return file;
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
	ut64 file_size = r_read_le64 ((ut8 *)&ds->size);
	if (addr >= file_size) {
		return 0;
	}
	if (addr + len > file_size) {
		len = file_size - addr;
	}

	// Find which block contains addr
	ut64 block_size = ctx->block_size;
	ut64 block_index = addr / block_size;
	ut64 offset_in_block = addr % block_size;

	if (block_index >= BFS_NUM_DIRECT_BLOCKS) {
		// TODO: Handle indirect blocks
		return 0;
	}

	bfs_block_run_t *run = &ds->direct[block_index];
	if (run->len == 0) {
		return 0;
	}

	ut64 block_offset = bfs_block_to_offset (ctx, run);
	ut64 read_offset = block_offset + offset_in_block;
	int to_read = R_MIN (len, block_size - offset_in_block);

	// Allocate buffer if needed
	if (!file->data) {
		file->data = malloc (len);
		if (!file->data) {
			return -1;
		}
	}

	if (bfs_read_at (ctx, read_offset, file->data, to_read)) {
		return to_read;
	}
	return -1;
}

static void fs_bfs_close(RFSFile *file) {
	R_RETURN_IF_FAIL (file);

	if (file->data) {
		free (file->data);
		file->data = NULL;
	}
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
	r_strbuf_appendf (sb, "Blocks per AG: %u\n", ctx->blocks_per_ag);
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
