/* radare2: Be File System - MIT - Copyright 2025 - pancake */

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

#define BFS_BLOCK_SIZE 1024
#define BFS_BYTEORDER_NATIVE 0x42494745
#define BFS_CLEAN 0x434C454E

#define B_OS_NAME_LENGTH 32
#define BFS_SYMLINK_LEN 144
#define BFS_NUM_DIRECT_BLOCKS 12
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
BeosBlockRun;

// Data stream
R_PACKED(
	typedef struct {
		BeosBlockRun direct[BFS_NUM_DIRECT_BLOCKS];
		ut64 max_direct_range;
		BeosBlockRun indirect;
		ut64 max_indirect_range;
		BeosBlockRun double_indirect;
		ut64 max_double_indirect_range;
		ut64 size;
	})
BeosDataStream;

// Small data entry
R_PACKED(
	typedef struct {
		ut32 type;
		ut16 name_size;
		ut16 data_size;
		char name[1];
	})
BeosSmallData;

// BFS Inode
R_PACKED(
	typedef struct {
		ut32 magic1;
		BeosBlockRun inode_num;
		ut32 uid;
		ut32 gid;
		ut32 mode;
		ut32 flags;
		ut64 create_time;
		ut64 last_modified_time;
		BeosBlockRun parent;
		BeosBlockRun attributes;
		ut32 type;
		ut32 inode_size;
		ut32 etc;
		union {
			BeosDataStream datastream;
			char symlink[BFS_SYMLINK_LEN];
		} data;
		ut32 pad[4];
		BeosSmallData small_data[1];
	})
BeosInode;

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
		BeosBlockRun log_blocks;
		ut64 log_start;
		ut64 log_end;
		ut32 magic3;
		BeosBlockRun root_dir;
		BeosBlockRun indices;
	})
BeosSuperBlock;

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
BeosTreeSuper;

// B+tree node header
R_PACKED(
	typedef struct {
		ut64 left;
		ut64 right;
		ut64 overflow;
		ut16 all_key_count;
		ut16 all_key_length;
	})
BeosTreeNodeHead;

// Parsed inode cache entry
typedef struct {
	ut64 inode_num;
	ut64 parent_inode_num;
	char *name;
	BeosInode *inode;
	bool parsed;
} BeosInodeCache;

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
	BeosBlockRun root_dir;
	HtUP *inodes; // Hash table: inode_num -> BeosInodeCache
	bool mounted;
	bool is_openbfs;
	bool is_le;
} BeosFS;

static bool bfs_read_at(BeosFS *ctx, ut64 offset, ut8 *buf, int len) {
	if (!ctx || !ctx->iob || !ctx->iob->read_at) {
		return false;
	}
	return ctx->iob->read_at (ctx->iob->io, ctx->delta + offset, buf, len);
}

static ut32 bfs_read32(BeosFS *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le32 (buf): r_read_be32 (buf);
}

static ut16 bfs_read16(BeosFS *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le16 (buf): r_read_be16 (buf);
}

static ut64 bfs_read64(BeosFS *ctx, ut8 *buf) {
	return ctx->is_le? r_read_le64 (buf): r_read_be64 (buf);
}

static inline bool bfs_is_directory(ut32 mode) {
	return (mode & 0xF000) == 0x4000;
}

static ut64 bfs_block_to_offset(BeosFS *ctx, BeosBlockRun *run) {
	ut64 ag_offset = (ut64)bfs_read32 (ctx, (ut8 *)&run->allocation_group) << ctx->ag_shift;
	ut64 block_offset = (ut64)bfs_read16 (ctx, (ut8 *)&run->start) << ctx->block_shift;
	return ag_offset + block_offset;
}

static ut64 bfs_block_index(BeosFS *ctx, const BeosBlockRun *run) {
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

static BeosInode *bfs_read_inode_block(BeosFS *ctx, ut64 block_index) {
	ut64 offset = block_index << ctx->block_shift;
	BeosInode *inode = malloc (ctx->inode_size);
	if (!inode) {
		return NULL;
	}
	if (!bfs_read_at (ctx, offset, (ut8 *)inode, ctx->inode_size)) {
		free (inode);
		return NULL;
	}
	return inode;
}

static bool bfs_read_stream(BeosFS *ctx, BeosInode *inode, ut64 offset, ut8 *buf, ut32 len) {
	BeosDataStream *ds;
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
			BeosBlockRun *run = &ds->direct[i];
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

static BeosInodeCache *bfs_get_inode(BeosFS *ctx, ut64 inode_num) {
	return ht_up_find (ctx->inodes, inode_num, NULL);
}

static void bfs_free_inode(BeosInodeCache *inode) {
	if (!inode) {
		return;
	}
	free (inode->name);
	free (inode->inode);
	free (inode);
}

static bool bfs_free_inode_cb(void *user, const ut64 key, const void *value) {
	bfs_free_inode ((BeosInodeCache *)value);
	return true;
}

static bool bfs_walk_directory(BeosFS *ctx, BeosInode *dir_inode, ut64 parent_inode_num);

typedef struct {
	RList *list;
	ut64 parent_inode_num;
	BeosFS *bfs_ctx;
} BeosDirIterContext;

typedef struct {
	const char *name;
	ut64 parent_inode_num;
	ut64 *result;
} BeosFindContext;

static bool bfs_find_inode_by_name_cb(void *user, const ut64 key, const void *value) {
	BeosFindContext *ctx = (BeosFindContext *)user;
	BeosInodeCache *cache = (BeosInodeCache *)value;
	if (!cache || !cache->name || cache->parent_inode_num != ctx->parent_inode_num) {
		return true;
	}
	if (strcmp (cache->name, ctx->name) == 0) {
		*ctx->result = cache->inode_num;
		return false; // Stop iteration
	}
	return true;
}

static ut64 bfs_resolve_path(BeosFS *ctx, const char *path) {
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
		BeosFindContext find_ctx = { comp, current_inode, &found };
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
	BeosDirIterContext *ctx = (BeosDirIterContext *)user;
	RList *list = ctx->list;
	ut64 parent_inode_num = ctx->parent_inode_num;
	BeosFS *bfs_ctx = ctx->bfs_ctx;
	BeosInodeCache *cache = (BeosInodeCache *)value;
	if (!cache || !cache->inode || !cache->name || cache->parent_inode_num != parent_inode_num) {
		return true;
	}

	RFSFile *fsf = r_fs_file_new (NULL, cache->name);
	if (!fsf) {
		return true;
	}

	ut32 mode = bfs_read32 (bfs_ctx, (ut8 *)&cache->inode->mode);
	if (bfs_is_directory (mode)) {
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

	BeosFS *ctx = R_NEW0 (BeosFS);
	ctx->iob = &root->iob;
	ctx->delta = root->delta;
	ctx->block_size = BFS_BLOCK_SIZE;
	ctx->inodes = ht_up_new0 ();

	// Read superblock from offset 512 (block 1 start)
	BeosSuperBlock sb;
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
	if (!ctx->block_size || (ctx->block_size & (ctx->block_size - 1))) {
		R_LOG_ERROR ("Invalid BFS block size: must be power of 2");
		goto fail;
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
		ut64 root_block = bfs_block_index (ctx, &ctx->root_dir);
		BeosInode *root_inode = bfs_read_inode_block (ctx, root_block);
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

	BeosFS *ctx = root->ptr;
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

static bool bfs_walk_directory(BeosFS *ctx, BeosInode *dir_inode, ut64 parent_inode_num) {
	R_RETURN_VAL_IF_FAIL (ctx && dir_inode, false);

	BeosTreeSuper super;
	if (!bfs_read_stream (ctx, dir_inode, 0, (ut8 *)&super, sizeof (super))) {
		return false;
	}
	if (bfs_read32 (ctx, (ut8 *)&super.magic) != BFS_BTREE_MAGIC) {
		return false;
	}

	ut32 node_size = bfs_read32 (ctx, (ut8 *)&super.node_size);
	if (!node_size) {
		node_size = ctx->block_size;
	}
	ut32 level = bfs_read32 (ctx, (ut8 *)&super.max_depth);
	if (!level) {
		level = 1;
	}
	ut64 node_off = bfs_read64 (ctx, (ut8 *)&super.root_node_ptr);
	if (node_off == UT64_MAX) {
		return true;
	}

	ut8 *node_buf = calloc (1, node_size);
	if (!node_buf) {
		return false;
	}

	if (level > 0) {
		ut32 depth = level - 1;
		while (depth--) {
			BeosTreeNodeHead *node_head;
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
			node_head = (BeosTreeNodeHead *)node_buf;
			key_count = bfs_read16 (ctx, (ut8 *)&node_head->all_key_count);
			key_length = bfs_read16 (ctx, (ut8 *)&node_head->all_key_length);
			if (!key_count) {
				free (node_buf);
				return false;
			}
			key_section = sizeof (BeosTreeNodeHead) + key_length;
			if (key_section > node_size) {
				free (node_buf);
				return false;
			}
			align_pad = (BTREE_ALIGN - (key_section % BTREE_ALIGN)) % BTREE_ALIGN;
			key_offsets = (ut16 *) (node_buf + sizeof (BeosTreeNodeHead) + key_length + align_pad);
			values = (ut64 *) ((ut8 *)key_offsets + key_count * sizeof (ut16));
			node_off = bfs_read64 (ctx, (ut8 *)&values[0]);
		}
	}

	while (1) {
		ut16 prev_end = 0;
		ut16 i;

		if (!bfs_read_stream (ctx, dir_inode, node_off, node_buf, node_size)) {
			free (node_buf);
			return false;
		}
		BeosTreeNodeHead *node_head = (BeosTreeNodeHead *)node_buf;
		ut16 key_count = bfs_read16 (ctx, (ut8 *)&node_head->all_key_count);
		ut16 key_length = bfs_read16 (ctx, (ut8 *)&node_head->all_key_length);
		size_t key_section = sizeof (BeosTreeNodeHead) + key_length;
		if (key_section > node_size) {
			free (node_buf);
			return false;
		}
		size_t align_pad = (BTREE_ALIGN - (key_section % BTREE_ALIGN)) % BTREE_ALIGN;
		ut8 *key_data = node_buf + sizeof (BeosTreeNodeHead);
		ut16 *key_offsets = (ut16 *) (key_data + key_length + align_pad);
		ut64 *values = (ut64 *) ((ut8 *)key_offsets + key_count * sizeof (ut16));

		for (i = 0; i < key_count; i++) {
			ut16 end = bfs_read16 (ctx, (ut8 *)&key_offsets[i]);
			ut32 mode;

			if (end > key_length) {
				end = key_length;
			}
			if (end < prev_end) {
				continue;
			}
			ut16 name_len = end - prev_end;
			if (!name_len) {
				prev_end = end;
				continue;
			}
			const char *name_ptr = (const char *) (key_data + prev_end);
			prev_end = end;
			if ((name_len == 1 && name_ptr[0] == '.') ||
				(name_len == 2 && name_ptr[0] == '.' && name_ptr[1] == '.')) {
				continue;
			}

			ut64 inode_block = bfs_read64 (ctx, (ut8 *)&values[i]);
			BeosInode *child_inode = bfs_read_inode_block (ctx, inode_block);
			if (!child_inode) {
				continue;
			}
			BeosInodeCache *cache = bfs_get_inode (ctx, inode_block);
			if (!cache) {
				cache = R_NEW0 (BeosInodeCache);
				cache->inode_num = inode_block;
				cache->parent_inode_num = parent_inode_num;
				cache->name = r_str_ndup (name_ptr, name_len);
				cache->inode = child_inode;
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
			if (bfs_is_directory (mode) && !cache->parsed) {
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

	BeosFS *ctx = root->ptr;
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
	BeosDirIterContext iter_ctx = { list, parent_inode_num, ctx };
	ht_up_foreach (ctx->inodes, bfs_dir_iter_cb, &iter_ctx);
	return list;
}

static RFSFile *fs_bfs_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);

	BeosFS *ctx = root->ptr;
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

	BeosInodeCache *cache = NULL;
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
		if (bfs_is_directory (mode)) {
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

static bool bfs_get_block_run(BeosFS *ctx, BeosDataStream *ds, ut64 block_index, BeosBlockRun *run) {
	if (block_index < BFS_NUM_DIRECT_BLOCKS) {
		*run = ds->direct[block_index];
		return true;
	}
	ut64 indirect_index = block_index - BFS_NUM_DIRECT_BLOCKS;
	ut64 num_per_block = ctx->block_size / sizeof (BeosBlockRun);
	if (indirect_index < num_per_block) {
		ut64 indirect_offset = bfs_block_to_offset (ctx, &ds->indirect);
		ut64 entry_offset = indirect_offset + indirect_index * sizeof (BeosBlockRun);
		return bfs_read_at (ctx, entry_offset, (ut8 *)run, sizeof (*run));
	}
	if (num_per_block == 0) {
		return false;
	}
	indirect_index -= num_per_block;
	ut64 double_indirect_index = indirect_index / num_per_block;
	ut64 sub_index = indirect_index % num_per_block;
	ut64 double_offset = bfs_block_to_offset (ctx, &ds->double_indirect);
	ut64 double_entry_offset = double_offset + double_indirect_index * sizeof (BeosBlockRun);
	BeosBlockRun indirect_run;
	if (!bfs_read_at (ctx, double_entry_offset, (ut8 *)&indirect_run, sizeof (indirect_run))) {
		return false;
	}
	ut64 indirect_offset = bfs_block_to_offset (ctx, &indirect_run);
	ut64 entry_offset = indirect_offset + sub_index * sizeof (BeosBlockRun);
	return bfs_read_at (ctx, entry_offset, (ut8 *)run, sizeof (*run));
}

static int fs_bfs_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);

	BeosFS *ctx = file->root->ptr;
	if (!ctx || !ctx->mounted) {
		return -1;
	}

	ut64 inode_num = (ut64) (size_t)file->ptr;
	BeosInodeCache *cache = bfs_get_inode (ctx, inode_num);
	if (!cache || !cache->inode) {
		return -1;
	}

	// For simplicity, read from direct blocks only
	BeosDataStream *ds = &cache->inode->data.datastream;
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

	BeosBlockRun run;
	if (!bfs_get_block_run (ctx, ds, block_index, &run)) {
		return 0;
	}
	if (run.len == 0) {
		return 0;
	}

	ut64 block_offset = bfs_block_to_offset (ctx, &run);
	ut64 read_offset = block_offset + offset_in_block;
	int to_read = R_MIN (len, block_size - offset_in_block);
	if (to_read < 1) {
		return -1;
	}
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

	BeosFS *ctx = (BeosFS *)root->ptr;
	if (!ctx) {
		return;
	}

	r_strbuf_appendf (sb, "Type: %s\n", ctx->is_openbfs? "OpenBFS": "BFS (Be File System)");
	r_strbuf_appendf (sb, "Block Size: %u bytes\n", ctx->block_size);
	r_strbuf_appendf (sb, "Inode Size: %u bytes\n", ctx->inode_size);
	r_strbuf_appendf (sb, "Blocks per AG: %" PFMT64u "\n", ctx->blocks_per_ag);
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
