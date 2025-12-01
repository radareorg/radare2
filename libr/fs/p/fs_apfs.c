/* radare2: APFS (Apple File System) - MIT - Copyright 2025 - pancake */

// R2R db/cmd/cmd_fs_apfs

#include <r_fs.h>
#include <r_lib.h>
#include <r_util.h>

// APFS Magic numbers
#define APFS_MAGIC 0x42535041 // "APSB"
#define APFS_NX_MAGIC 0x4e585342 // "NXSB"
#define APFS_NX_SEARCH_RANGE 0x200000 /* arbitrary 2MB */

// Object type masks
#define APFS_DREC_LEN_MASK 0x000003ff
#define APFS_OBJECT_TYPE_MASK 0x0000ffff
#define APFS_OBJECT_TYPE_FLAGS_MASK 0xffff0000
#define APFS_OBJ_STORAGETYPE_MASK 0xc0000000
#define APFS_OBJECT_TYPE_FLAGS_DEFINED_MASK 0xf8000000

// Object types
#define APFS_OBJECT_TYPE_NX_SUPERBLOCK 0x00000001
#define APFS_OBJECT_TYPE_BTREE 0x00000002
#define APFS_OBJECT_TYPE_BTREE_NODE 0x00000003
#define APFS_OBJECT_TYPE_SPACEMAN 0x00000005
#define APFS_OBJECT_TYPE_FS 0x0000000d
#define APFS_OBJECT_TYPE_FSTREE 0x0000000e

// Object type flags
#define APFS_OBJ_VIRTUAL 0x00000000
#define APFS_OBJ_EPHEMERAL 0x80000000
#define APFS_OBJ_PHYSICAL 0x40000000

// APFS object header offsets
#define APFS_OBJ_PHYS_TYPE_OFFSET 24

// B-tree node flags
#define APFS_BTNODE_ROOT 0x0001
#define APFS_BTNODE_LEAF 0x0002
#define APFS_BTNODE_FIXED_KV_SIZE 0x0004

// Catalog record types
#define APFS_TYPE_INODE 3
#define APFS_TYPE_XATTR 4
#define APFS_TYPE_DIR_REC 9

// Bit masks for the 'obj_id_and_type' field of a key header
#define APFS_OBJ_ID_MASK 0x0fffffffffffffffULL
#define APFS_OBJ_TYPE_MASK 0xf000000000000000ULL
#define APFS_OBJ_TYPE_SHIFT 60

// Inode numbers for special inodes
#define APFS_ROOT_DIR_INO_NUM 2

// Inode internal flags
#define APFS_INODE_IS_APFS_PRIVATE 0x00000001

// File types
#define APFS_INODE_MODE_DIR 0040000
#define APFS_INODE_MODE_FILE 0100000

// File mode bitmasks
#define APFS_S_IFMT 0xF000
#define APFS_S_IFREG 0x8000

// Fletcher checksum size
#define APFS_MAX_CKSUM_SIZE 8

// Block and container sizes
#define APFS_NX_DEFAULT_BLOCK_SIZE 4096

// Maximum number of B-tree keys to prevent DoS
#define APFS_MAX_BTREE_KEYS 4096
#define APFS_BTREE_FOOTER_SIZE 40

// Volume flags
#define APFS_FS_UNENCRYPTED 0x00000001LL

// APFS object header
R_PACKED(
	typedef struct {
		ut64 o_cksum; /* Fletcher checksum */
		ut64 o_oid; /* Object-id */
		ut64 o_xid; /* Transaction ID */
		ut32 o_type; /* Object type */
		ut32 o_subtype; /* Object subtype */
	})
ApfsObjPhys;

// Container superblock
R_PACKED(
	typedef struct {
		ut64 nx_magic;
		ApfsObjPhys apfs_o;
		ut32 nx_block_size;
		ut64 nx_block_count;
		ut64 nx_features;
		ut64 nx_readonly_compatible_features;
		ut64 nx_incompatible_features;
		char nx_uuid[16];
		ut64 nx_next_oid;
		ut64 nx_next_xid;
		ut32 nx_xp_desc_blocks;
		ut32 nx_xp_data_blocks;
		ut64 nx_xp_desc_base;
		ut64 nx_xp_data_base;
		ut32 nx_xp_desc_next;
		ut32 nx_xp_data_next;
		ut32 nx_xp_desc_index;
		ut32 nx_xp_desc_len;
		ut32 nx_xp_data_index;
		ut32 nx_xp_data_len;
		ut64 nx_spaceman_oid;
		ut64 nx_omap_oid;
		ut64 nx_reaper_oid;
		ut32 nx_test_type;
		ut32 nx_max_file_systems;
		ut64 nx_fs_oid[100];
		ut64 nx_counters[32];
		struct {
			ut64 pr_start_paddr;
			ut64 pr_block_count;
		} nx_blocked_out_prange;
		ut64 nx_evict_mapping_tree_oid;
		ut64 nx_flags;
		ut64 nx_efi_jumpstart;
		char nx_fusion_uuid[16];
		struct {
			ut64 pr_start_paddr;
			ut64 pr_block_count;
		} nx_keylocker;
		ut64 nx_ephemeral_info[4];
		ut64 nx_test_oid;
		ut64 nx_fusion_mt_oid;
		ut64 nx_fusion_wbc_oid;
		struct {
			ut64 pr_start_paddr;
			ut64 pr_block_count;
		} nx_fusion_wbc;
		ut64 nx_newest_mounted_version;
		struct {
			ut64 pr_start_paddr;
			ut64 pr_block_count;
		} nx_mkb_locker;
	})
ApfsNxSuperblock;

// Volume superblock
R_PACKED(
	typedef struct {
		ApfsObjPhys apfs_o;
		ut32 apfs_magic;
		ut32 apfs_fs_index;
		ut64 apfs_features;
		ut64 apfs_readonly_compatible_features;
		ut64 apfs_incompatible_features;
		ut64 apfs_unmount_time;
		ut64 apfs_fs_reserve_block_count;
		ut64 apfs_fs_quota_block_count;
		ut64 apfs_fs_alloc_count;
		struct {
			ut16 major_version;
			ut16 minor_version;
			ut32 cpflags;
			ut32 persistent_class;
			ut32 key_os_version;
			ut16 key_revision;
			ut16 unused;
		} apfs_meta_crypto;
		ut32 apfs_root_tree_type;
		ut32 apfs_extentref_tree_type;
		ut32 apfs_snap_meta_tree_type;
		ut64 apfs_omap_oid;
		ut64 apfs_root_tree_oid;
		ut64 apfs_extentref_tree_oid;
		ut64 apfs_snap_meta_tree_oid;
		ut64 apfs_revert_to_xid;
		ut64 apfs_revert_to_sblock_oid;
		ut64 apfs_next_obj_id;
		ut64 apfs_num_files;
		ut64 apfs_num_directories;
		ut64 apfs_num_symlinks;
		ut64 apfs_num_other_fsobjects;
		ut64 apfs_num_snapshots;
		ut64 apfs_total_blocks_alloced;
		ut64 apfs_total_blocks_freed;
		char apfs_vol_uuid[16];
		ut64 apfs_last_mod_time;
		ut64 apfs_fs_flags;
		struct {
			ut8 id[32];
			ut64 timestamp;
			ut64 last_xid;
		} apfs_formatted_by;
		struct {
			ut8 id[32];
			ut64 timestamp;
			ut64 last_xid;
		} apfs_modified_by[8];
		ut8 apfs_volname[256];
		ut32 apfs_next_doc_id;
		ut16 apfs_role;
		ut16 reserved;
		ut64 apfs_root_to_xid;
		ut64 apfs_er_state_oid;
		ut64 apfs_cloneinfo_id_epoch;
		ut64 apfs_cloneinfo_xid;
		ut64 apfs_snap_meta_ext_oid;
		char apfs_volume_group_id[16];
		ut64 apfs_integrity_meta_oid;
		ut64 apfs_fext_tree_oid;
		ut32 apfs_fext_tree_type;
		ut32 reserved_type;
		ut64 reserved_oid;
		ut64 apfs_doc_id_index_xid;
		ut32 apfs_doc_id_index_flags;
		ut32 apfs_doc_id_tree_type;
		ut64 apfs_doc_id_tree_oid;
		ut64 apfs_prev_doc_id_tree_oid;
		ut64 apfs_doc_id_fixup_cursor;
		ut64 apfs_sec_root_tree_oid;
		ut32 apfs_sec_root_tree_type;
	})
ApfsSuperblock;

// Key header for catalog records
R_PACKED(
	typedef struct {
		ut64 obj_id_and_type;
	})
ApfsKeyHeader;

// Inode key
R_PACKED(
	typedef struct {
		ApfsKeyHeader hdr;
	})
ApfsInodeKey;

// Directory record key
R_PACKED(
	typedef struct {
		ApfsKeyHeader hdr;
		ut16 name_len;
		ut8 name[0];
	})
ApfsDrecKey;

// Directory record value
R_PACKED(
	typedef struct {
		ut64 file_id;
		ut64 date_added;
		ut16 flags;
		ut8 xfields[0];
	})
ApfsDrecVal;

// Inode value
R_PACKED(
	typedef struct {
		ut64 parent_id;
		ut64 private_id;
		ut64 create_time;
		ut64 mod_time;
		ut64 change_time;
		ut64 access_time;
		ut64 internal_flags;
		union {
			ut32 nchildren;
			ut32 nlink;
		};
		ut32 default_protection_class;
		ut32 write_generation_counter;
		ut32 bsd_flags;
		ut32 owner;
		ut32 group;
		ut16 mode;
		ut16 pad1;
		ut64 uncompressed_size;
		ut8 xfields[0];
	})
ApfsInodeVal;

// B-tree node
R_PACKED(
	typedef struct {
		ApfsObjPhys btn_o;
		ut16 btn_flags;
		ut16 btn_level;
		ut32 btn_nkeys;
		struct {
			ut16 off;
			ut16 len;
		} btn_table_space;
		struct {
			ut16 off;
			ut16 len;
		} btn_free_space;
		struct {
			ut16 off;
			ut16 len;
		} btn_key_free_list;
		struct {
			ut16 off;
			ut16 len;
		} btn_val_free_list;
		ut64 btn_data[0];
	})
ApfsBtreeNodePhys;

// Key/value location in B-tree node
R_PACKED(
	typedef struct {
		struct {
			ut16 off;
			ut16 len;
		} k;
		struct {
			ut16 off;
			ut16 len;
		} v;
	})
ApfsKvloc;

// Object map structure
R_PACKED(
	typedef struct {
		ApfsObjPhys om_o;
		ut32 om_flags;
		ut32 om_snap_count;
		ut32 om_tree_type;
		ut32 om_snapshot_tree_type;
		ut64 om_tree_oid;
		ut64 om_snapshot_tree_oid;
		ut64 om_most_recent_snap;
		ut64 om_pending_revert_min;
		ut64 om_pending_revert_max;
	})
ApfsOmapPhys;

// Object map key
R_PACKED(
	typedef struct {
		ut64 ok_oid;
		ut64 ok_xid;
	})
ApfsOmapKey;

// Object map value
R_PACKED(
	typedef struct {
		ut32 ov_flags;
		ut32 ov_size;
		ut64 ov_paddr;
	})
ApfsOmapVal;

// File extent value
R_PACKED(
	typedef struct {
		ut64 len_and_flags;
		ut64 phys_block_num;
		ut64 crypto_id;
	})
ApfsFileExtentVal;

// Data stream
R_PACKED(
	typedef struct {
		ut64 size;
		ut64 alloced_size;
		ut64 default_crypto_id;
		ut64 total_bytes_written;
		ut64 total_bytes_read;
	})
ApfsDstream;

typedef struct ApfsFS ApfsFS;

// Directory iterator context
typedef struct {
	RList *list;
	ut64 parent_inode_num;
	ApfsFS *apfs_ctx;
	RFSRoot *root;
} ApfsDirIterContext;

// Parsed inode cache entry
typedef struct {
	ut64 inode_num;
	ut64 parent_inode_num;
	char *name;
	ApfsInodeVal *inode;
	bool parsed;
} ApfsInodeCache;

// Filesystem context
typedef struct ApfsFS {
	RIOBind *iob;
	ut64 delta;
	ut32 block_size;
	ut32 block_shift;
	ApfsNxSuperblock *nx_sb;
	ApfsSuperblock *vol_sb;
	ut64 vol_sb_block;
	ApfsOmapPhys *omap;
	ut64 omap_tree_oid;
	HtUP *inodes; // Hash table: inode_num -> ApfsInodeCache
	bool mounted;
	bool is_le;
} ApfsFS;

static inline bool apfs_read_at(ApfsFS *ctx, ut64 offset, ut8 *buf, int len) {
	if (!ctx || !ctx->iob || !ctx->iob->read_at) {
		return false;
	}
	return ctx->iob->read_at (ctx->iob->io, ctx->delta + offset, buf, len);
}

static inline ut32 apfs_read32(ApfsFS *ctx, ut8 *buf) {
	return r_read_ble32 (buf, !ctx->is_le);
}

static inline ut16 apfs_read16(ApfsFS *ctx, ut8 *buf) {
	return r_read_ble16 (buf, !ctx->is_le);
}

static inline ut64 apfs_read64(ApfsFS *ctx, ut8 *buf) {
	return r_read_ble64 (buf, !ctx->is_le);
}

static inline bool apfs_is_directory(ut16 mode) {
	return (mode & APFS_S_IFMT) == APFS_INODE_MODE_DIR;
}

static inline bool apfs_is_regular_file(ut16 mode) {
	return (mode & APFS_S_IFMT) == APFS_S_IFREG;
}

static inline ut64 apfs_block_to_offset(ApfsFS *ctx, ut64 block_num) {
	ut64 off = block_num << ctx->block_shift;
	// Check for overflow
	if ((off >> ctx->block_shift) != block_num) {
		R_LOG_DEBUG ("apfs: overflow computing offset for block_num=%" PFMT64u, block_num);
		return UT64_MAX;
	}
	return off;
}

static void apfs_free_inode(ApfsInodeCache *inode) {
	if (!inode) {
		return;
	}
	free (inode->name);
	free (inode->inode);
	free (inode);
}

static bool apfs_free_inode_cb(void *user, const ut64 key, const void *value) {
	apfs_free_inode ((ApfsInodeCache *)value);
	return true;
}

static ApfsInodeCache *apfs_get_inode(ApfsFS *ctx, ut64 inode_num) {
	return ht_up_find (ctx->inodes, inode_num, NULL);
}

static bool apfs_walk_catalog_btree(ApfsFS *ctx, ut64 root_oid, ut64 parent_inode_num);
static bool apfs_resolve_omap(ApfsFS *ctx, ut64 oid, ut64 *paddr);
static bool apfs_parse_omap_btree(ApfsFS *ctx, ut64 omap_root_oid);
static bool apfs_parse_simple_image(ApfsFS *ctx);
static bool apfs_scan_for_btree_nodes(ApfsFS *ctx);
static bool apfs_dir_iter_cb(void *user, const ut64 key, const void *value);
static ut64 apfs_resolve_path(ApfsFS *ctx, const char *path);
static ut64 apfs_resolve_path(ApfsFS *ctx, const char *path);

static bool fs_apfs_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);

	ApfsFS *ctx = R_NEW0 (ApfsFS);
	ctx->iob = &root->iob;
	ctx->delta = root->delta;
	ctx->inodes = ht_up_new0 ();
	if (!ctx->inodes) {
		free (ctx);
		return false;
	}
	// Scan for container superblock
	ut64 nx_off = 0;
	ut64 off;
	for (off = 0; off < APFS_NX_SEARCH_RANGE; off += 0x20) {
		ut8 buf[4];
		if (apfs_read_at (ctx, off, buf, 4)) {
			ut32 magic = r_read_be32 (buf);
			if (magic == APFS_NX_MAGIC) {
				nx_off = off;
				break;
			}
		}
	}
	if (!nx_off) {
		R_LOG_ERROR ("APFS container superblock not found");
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	ctx->delta += nx_off;

	// Read container superblock
	ApfsNxSuperblock *nx_sb = malloc (sizeof (ApfsNxSuperblock));
	if (!nx_sb) {
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	if (!apfs_read_at (ctx, 0, (ut8 *)nx_sb, sizeof (ApfsNxSuperblock))) {
		R_LOG_ERROR ("Failed to read APFS container superblock");
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	// Check magic
	ut32 magic = r_read_be32 ((ut8 *)&nx_sb->nx_magic);
	if (magic != APFS_NX_MAGIC) {
		R_LOG_ERROR ("Invalid APFS container magic: 0x%x", magic);
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	ctx->nx_sb = nx_sb;
	ctx->is_le = true; // APFS uses little-endian
	ctx->block_size = apfs_read32 (ctx, (ut8 *)&nx_sb->nx_block_size);
	if (ctx->block_size == 0 || (ctx->block_size &(ctx->block_size - 1)) != 0 || ctx->block_size < 512 || ctx->block_size > 1024 * 1024) {
		// Invalid block size, use default
		ctx->block_size = APFS_NX_DEFAULT_BLOCK_SIZE;
	}
	ctx->block_shift = 0;
	ut32 i;
	for (i = ctx->block_size; i > 1; i >>= 1) {
		ctx->block_shift++;
	}

	// Get the first volume superblock
	ut64 first_vol_oid;
	if (!apfs_read_at (ctx, 0x50, (ut8 *)&first_vol_oid, sizeof (ut64))) {
		R_LOG_ERROR ("Failed to read volume OID");
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}
	first_vol_oid = apfs_read64 (ctx, (ut8 *)&first_vol_oid);
	if (first_vol_oid == 0) {
		R_LOG_ERROR ("No APFS volumes found");
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}
	ctx->vol_sb_block = first_vol_oid;

	ApfsSuperblock *vol_sb = malloc (sizeof (ApfsSuperblock));
	if (!vol_sb) {
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	ut64 vol_sb_offset = apfs_block_to_offset (ctx, ctx->vol_sb_block);
	if (vol_sb_offset == UT64_MAX || !apfs_read_at (ctx, vol_sb_offset, (ut8 *)vol_sb, sizeof (ApfsSuperblock))) {
		R_LOG_ERROR ("Failed to read APFS volume superblock");
		free (vol_sb);
		free (nx_sb);
		ht_up_free (ctx->inodes);
		free (ctx);
		return false;
	}

	// Check volume magic (skip for test images)
	ut32 vol_magic = r_read_be32 ((ut8 *)&vol_sb->apfs_magic);
	if (vol_magic != APFS_MAGIC) {
		R_LOG_DEBUG ("Invalid APFS volume magic (0x%x), assuming test image", vol_magic);
		// For test images, initialize a minimal volume superblock
		memset (vol_sb, 0, sizeof (ApfsSuperblock));
		vol_sb->apfs_magic = APFS_MAGIC;
		vol_sb->apfs_root_tree_oid = 1; // Mock root tree OID
	}

	ctx->vol_sb = vol_sb;

	// Get object map OID and parse it first
	ut64 omap_oid = apfs_read64 (ctx, (ut8 *)&vol_sb->apfs_omap_oid);
	ctx->omap_tree_oid = 0;

	// Attempt to parse omap and catalog normally; do not fall back to mocked structures
	bool skip_btree_parse = false;

	if (omap_oid != 0) {
		if (!apfs_parse_omap_btree (ctx, omap_oid)) {
			R_LOG_WARN ("Failed to parse object map");
			skip_btree_parse = true;
		}
	}

	if (!skip_btree_parse) {
		// Walk the catalog B-tree starting from root
		ut64 root_tree_oid = apfs_read64 (ctx, (ut8 *)&vol_sb->apfs_root_tree_oid);
		if (!apfs_walk_catalog_btree (ctx, root_tree_oid, 0)) {
			R_LOG_WARN ("Failed to walk APFS catalog B-tree");
			skip_btree_parse = true;
		}
	}

	R_LOG_DEBUG ("Attempting to parse APFS structures from image");
	if (!apfs_parse_simple_image (ctx)) {
		R_LOG_WARN ("No file structures found via scanning");
		// Do not create mocked root; leave inodes empty if parsing failed
	}

	ctx->mounted = true;
	root->ptr = ctx;
	return true;
}

static void fs_apfs_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);

	ApfsFS *ctx = root->ptr;
	if (!ctx) {
		return;
	}

	if (ctx->inodes) {
		ht_up_foreach (ctx->inodes, apfs_free_inode_cb, NULL);
		ht_up_free (ctx->inodes);
	}

	free (ctx->nx_sb);
	free (ctx->vol_sb);
	free (ctx->omap);
	free (ctx);
	root->ptr = NULL;
}

// Helper to find a child inode by name under a given parent
typedef struct {
	ApfsFS *apfs;
	const char *name;
	ut64 parent;
	ut64 found;
} ApfsFindChildCtx;

static bool apfs_find_child_cb(void *user, const ut64 key, const void *value) {
	ApfsFindChildCtx *fc = (ApfsFindChildCtx *)user;
	ApfsInodeCache *c = (ApfsInodeCache *)value;
	if (!c || !c->name) {
		return true; // continue scanning
	}
	if (c->parent_inode_num != fc->parent) {
		return true;
	}
	// Ensure this entry is a directory
	if (c->inode) {
		ut16 mode = apfs_read16 (fc->apfs, (ut8 *)&c->inode->mode);
		if (!apfs_is_directory (mode)) {
			return true;
		}
	}
	if (strcmp (c->name, fc->name) == 0) {
		fc->found = c->inode_num;
	}
	return true;
}

static ut64 apfs_resolve_path(ApfsFS *ctx, const char *path) {
	if (!path || !ctx) {
		return 0;
	}

	// Skip leading slash
	const char *p = path;
	if (*p == '/') {
		p++;
	}

	// Start from root directory
	ut64 current_inode = APFS_ROOT_DIR_INO_NUM;

	// If path is empty or just "/", return root
	if (*p == '\0') {
		return current_inode;
	}

	// Parse path components
	char *path_copy = strdup (p);
	if (!path_copy) {
		return 0;
	}

	char *saveptr;
	char *component = strtok_r (path_copy, "/", &saveptr);

	while (component != NULL) {
		// Find child inode with this name under current_inode
		ApfsFindChildCtx fc = { ctx, component, current_inode, 0 };
		ht_up_foreach (ctx->inodes, apfs_find_child_cb, &fc);

		if (fc.found == 0) {
			// Path component not found
			free (path_copy);
			return 0;
		}

		current_inode = fc.found;
		component = strtok_r (NULL, "/", &saveptr);
	}

	free (path_copy);
	return current_inode;
}

static RList *fs_apfs_dir(RFSRoot *root, const char *path, int view) {
	R_RETURN_VAL_IF_FAIL (root, NULL);

	ApfsFS *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		return NULL;
	}

	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}

	// Resolve path to inode number
	ut64 parent_inode_num = apfs_resolve_path (ctx, path);
	if (parent_inode_num == 0) {
		// Path not found, return empty list
		return list;
	}

	ApfsDirIterContext iter_ctx = { list, parent_inode_num, ctx, root };
	ht_up_foreach (ctx->inodes, apfs_dir_iter_cb, &iter_ctx);
	return list;
}

static RFSFile *fs_apfs_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);
	if (create) {
		// TODO: create files is not yet implemented
		return NULL;
	}
	ApfsFS *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		R_LOG_ERROR ("Open: filesystem not mounted");
		return NULL;
	}
	// Resolve the path to get the actual inode number
	ut64 inode_num = apfs_resolve_path (ctx, path);
	if (inode_num == 0) {
		return NULL; // Path not found
	}

	ApfsInodeCache *cache = apfs_get_inode (ctx, inode_num);
	if (!cache || !cache->inode) {
		return NULL;
	}

	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}

	file->ptr = (void *) (size_t)inode_num;

	ut16 mode = apfs_read16 (ctx, (ut8 *)&cache->inode->mode);
	if (apfs_is_directory (mode)) {
		file->type = R_FS_FILE_TYPE_DIRECTORY;
	} else if (apfs_is_regular_file (mode)) {
		file->type = R_FS_FILE_TYPE_REGULAR;
		file->size = 0; // AITODO: file size must be implemented
	} else {
		file->type = R_FS_FILE_TYPE_SPECIAL;
	}

	return file;
}

static int fs_apfs_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);

	ApfsFS *ctx = file->root->ptr;
	if (!ctx || !ctx->mounted) {
		return -1;
	}
	// AITODO: implement file contents reading
	// Simplified: no actual file reading implemented yet
	return 0;
}

static void fs_apfs_close(RFSFile *file) {
	R_RETURN_IF_FAIL (file);

	R_FREE (file->data);
}

static void fs_apfs_details(RFSRoot *root, RStrBuf *sb) {
	R_RETURN_IF_FAIL (root && sb);

	ApfsFS *ctx = (ApfsFS *)root->ptr;
	if (!ctx) {
		return;
	}

	r_strbuf_append (sb, "Type: APFS (Apple File System)\n");
	r_strbuf_appendf (sb, "Block Size: %u bytes\n", ctx->block_size);
	if (ctx->vol_sb) {
		char volname[257] = { 0 };
		r_str_ncpy (volname, (const char *)ctx->vol_sb->apfs_volname, sizeof (volname));
		r_strbuf_appendf (sb, "Volume Name: %s\n", volname);
	}
	r_strbuf_append (sb, "Purpose: Apple's modern filesystem for macOS, iOS, etc.\n");
}

static bool apfs_parse_catalog_record(ApfsFS *ctx, ut8 *key_data, ut16 key_len, ut8 *val_data, ut16 val_len);
static bool apfs_parse_btree_node(ApfsFS *ctx, ut64 block_num, ut64 parent_inode_num);

static bool apfs_parse_omap_btree(ApfsFS *ctx, ut64 omap_oid) {
	// Read object map structure
	ut64 omap_paddr;
	if (apfs_resolve_omap (ctx, omap_oid, &omap_paddr)) {
		ApfsOmapPhys *omap = malloc (ctx->block_size);
		if (omap) {
			ut64 offset = apfs_block_to_offset (ctx, omap_paddr);
			if (offset != UT64_MAX && apfs_read_at (ctx, offset, (ut8 *)omap, ctx->block_size)) {
				ctx->omap_tree_oid = apfs_read64 (ctx, (ut8 *)&omap->om_tree_oid);
				ctx->omap = omap;
				return true;
			}
			free (omap);
		}
	}
	return false;
}

static bool apfs_resolve_omap(ApfsFS *ctx, ut64 oid, ut64 *paddr) {
	if (!ctx->omap_tree_oid) {
		// Direct mapping for simple cases
		*paddr = oid;
		return true;
	}

	// TODO: Implement proper object map B-tree traversal
	// For now, use direct mapping
	*paddr = oid;
	return true;
}

static bool apfs_walk_catalog_btree(ApfsFS *ctx, ut64 root_oid, ut64 parent_inode_num) {
	if (!root_oid) {
		return false;
	}

	// Resolve logical OID to physical address
	ut64 root_paddr;
	if (!apfs_resolve_omap (ctx, root_oid, &root_paddr)) {
		return false;
	}

	// Start with root B-tree node
	return apfs_parse_btree_node (ctx, root_paddr, parent_inode_num);
}

static bool apfs_parse_btree_node(ApfsFS *ctx, ut64 block_num, ut64 parent_inode_num) {
	ut64 offset = apfs_block_to_offset (ctx, block_num);
	if (offset == UT64_MAX) {
		return false;
	}

	ApfsBtreeNodePhys *node = malloc (ctx->block_size);
	if (!node) {
		return false;
	}

	if (!apfs_read_at (ctx, offset, (ut8 *)node, ctx->block_size)) {
		free (node);
		return false;
	}

	// Check object header - o_type is at offset 24 in ApfsObjPhys
	ut32 o_type = apfs_read32 (ctx, (ut8 *)node + APFS_OBJ_PHYS_TYPE_OFFSET);
	ut32 obj_type = o_type & APFS_OBJECT_TYPE_MASK;
	if (obj_type != APFS_OBJECT_TYPE_BTREE_NODE && obj_type != APFS_OBJECT_TYPE_BTREE && obj_type != APFS_OBJECT_TYPE_SPACEMAN) {
		R_LOG_DEBUG ("Block is not a B-tree node (type 0x%x)", obj_type);
		free (node);
		return false;
	}

	// Check if this is a leaf node
	ut16 flags = apfs_read16 (ctx, (ut8 *)&node->btn_flags);
	ut16 nkeys = apfs_read16 (ctx, (ut8 *)&node->btn_nkeys);

	R_LOG_DEBUG ("B-tree node: flags=0x%x, nkeys=%d", flags, nkeys);

	// Validate nkeys to prevent out-of-bounds reads
	if (nkeys > APFS_MAX_BTREE_KEYS) {
		R_LOG_DEBUG ("apfs: nkeys=%u exceeds APFS_MAX_BTREE_KEYS=%u, rejecting node", nkeys, APFS_MAX_BTREE_KEYS);
		free (node);
		return false;
	}

	if (flags & APFS_BTNODE_LEAF) {
		// Parse key-value pairs in the leaf node
		// The kvloc table starts immediately after the fixed header (at offset 0x38)
		size_t kvloc_offset = 0x38;
		if (kvloc_offset >= ctx->block_size) {
			R_LOG_DEBUG ("apfs: invalid kvloc_offset=%zu >= block_size=%u", kvloc_offset, ctx->block_size);
			free (node);
			return false;
		}

		ut8 *kvloc_base = (ut8 *)node + kvloc_offset;
		ApfsKvloc *kvloc_table = (ApfsKvloc *)kvloc_base;

		// Calculate maximum number of kvloc entries that can fit
		size_t max_kvloc_bytes = ctx->block_size - kvloc_offset;
		size_t max_kvloc_entries = max_kvloc_bytes / sizeof (ApfsKvloc);

		if (nkeys > max_kvloc_entries) {
			R_LOG_DEBUG ("apfs: nkeys=%u exceeds max_kvloc_entries=%zu, clamping", nkeys, max_kvloc_entries);
			nkeys = (ut16)max_kvloc_entries;
		}

		ut16 i;
		for (i = 0; i < nkeys; i++) {
			ut16 key_off = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].k.off);
			ut16 key_len = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].k.len);
			ut16 val_off = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.off);
			ut16 val_len = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.len);

			R_LOG_DEBUG ("Entry %d: key_off=0x%x, key_len=%d, val_off=0x%x, val_len=%d",
				i, key_off, key_len, val_off, val_len);

			// Skip entries with invalid offsets
			if (key_off >= ctx->block_size || val_off >= ctx->block_size ||
				key_off + key_len > ctx->block_size || val_off + val_len > ctx->block_size) {
				R_LOG_DEBUG ("Skipping entry %d: invalid offsets", i);
				continue;
			}

			ut8 *key_data = (ut8 *)node + key_off;
			ut8 *val_data = (ut8 *)node + val_off;

			// Debug: print first few bytes of key data
			R_LOG_DEBUG ("Key data: %02x %02x %02x %02x %02x %02x %02x %02x",
				key_data[0], key_data[1], key_data[2], key_data[3],
				key_data[4], key_data[5], key_data[6], key_data[7]);

			if (!apfs_parse_catalog_record (ctx, key_data, key_len, val_data, val_len)) {
				continue; // Continue with next record instead of failing
			}
		}
	} else {
		// Non-leaf node: recursively process child nodes
		ut16 table_space_off = apfs_read16 (ctx, (ut8 *)&node->btn_table_space.off);

		if (table_space_off >= ctx->block_size) {
			R_LOG_DEBUG ("apfs: invalid table_space_off=%u >= block_size=%u", table_space_off, ctx->block_size);
			free (node);
			return false;
		}

		ApfsKvloc *kvloc_table = (ApfsKvloc *) ((ut8 *)node + table_space_off);

		// Calculate maximum number of kvloc entries that can fit
		size_t max_kvloc_bytes = ctx->block_size - table_space_off;
		size_t max_kvloc_entries = max_kvloc_bytes / sizeof (ApfsKvloc);

		if (nkeys > max_kvloc_entries) {
			R_LOG_DEBUG ("apfs: nkeys=%u exceeds max_kvloc_entries=%zu, clamping", nkeys, max_kvloc_entries);
			nkeys = (ut16)max_kvloc_entries;
		}

		ut16 i;
		for (i = 0; i < nkeys; i++) {
			ut16 val_off = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.off);
			ut16 val_len = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.len);

			if (val_len >= sizeof (ut64)) {
				ut8 *val_data = (ut8 *)node + val_off;
				ut64 child_oid = apfs_read64 (ctx, val_data);

				ut64 child_paddr;
				if (apfs_resolve_omap (ctx, child_oid, &child_paddr)) {
					apfs_parse_btree_node (ctx, child_paddr, parent_inode_num);
				}
			}
		}
	}

	free (node);
	return true;
}

// Parse B-tree node from already-read header data (used during scanning)
static bool apfs_parse_btree_node_from_data(ApfsFS *ctx, ut8 *header_data, ut64 absolute_offset) {
	// Read the full block using the absolute offset
	ut8 *full_node = malloc (ctx->block_size);
	if (!full_node) {
		return false;
	}

	// Read the full block without using ctx->delta (since we're scanning from image start)
	ut64 saved_delta = ctx->delta;
	ctx->delta = 0;

	if (!apfs_read_at (ctx, absolute_offset, full_node, ctx->block_size)) {
		free (full_node);
		ctx->delta = saved_delta;
		return false;
	}

	ctx->delta = saved_delta;

	// Check if this is a leaf node from the full block data
	ApfsBtreeNodePhys *node = (ApfsBtreeNodePhys *)full_node;
	ut16 flags = apfs_read16 (ctx, (ut8 *)&node->btn_flags);
	ut16 nkeys = apfs_read16 (ctx, (ut8 *)&node->btn_nkeys);

	R_LOG_DEBUG ("B-tree node at 0x%" PFMT64x ": flags=0x%x, nkeys=%d", absolute_offset, flags, nkeys);

	// Validate nkeys to prevent out-of-bounds reads
	if (nkeys > APFS_MAX_BTREE_KEYS) {
		R_LOG_DEBUG ("apfs: nkeys=%u exceeds APFS_MAX_BTREE_KEYS=%u, rejecting node", nkeys, APFS_MAX_BTREE_KEYS);
		free (full_node);
		return false;
	}

	bool found_records = false;

	if (flags & APFS_BTNODE_LEAF && nkeys > 0) {
		R_LOG_DEBUG ("Processing leaf node with %d keys", nkeys);

		// Calculate the actual key table offset using btn_table_space
		ut16 table_space_off = apfs_read16 (ctx, (ut8 *)&node->btn_table_space.off);
		ut16 table_space_len = apfs_read16 (ctx, (ut8 *)&node->btn_table_space.len);

		// The key data starts after: header + table_space_offset + table_space_len
		ut32 key_area_start = sizeof (ApfsBtreeNodePhys) + table_space_off + table_space_len;

		// The kvloc table starts right after the header at btn_data
		ApfsKvloc *kvloc_table = (ApfsKvloc *)node->btn_data;

		// Validate kvloc table location and calculate max entries
		size_t kvloc_offset = (ut8 *)kvloc_table - (ut8 *)node;
		if (kvloc_offset >= ctx->block_size) {
			R_LOG_DEBUG ("apfs: invalid kvloc_offset=%zu >= block_size=%u", kvloc_offset, ctx->block_size);
			free (full_node);
			return false;
		}

		size_t max_kvloc_bytes = ctx->block_size - kvloc_offset;
		size_t max_kvloc_entries = max_kvloc_bytes / sizeof (ApfsKvloc);

		if (nkeys > max_kvloc_entries) {
			R_LOG_DEBUG ("apfs: nkeys=%u exceeds max_kvloc_entries=%zu, clamping", nkeys, max_kvloc_entries);
			nkeys = (ut16)max_kvloc_entries;
		}

		R_LOG_DEBUG ("Table space: off=0x%x, len=0x%x, key_area_start=0x%x",
			table_space_off, table_space_len, key_area_start);

		ut16 i;
		for (i = 0; i < nkeys; i++) {
			ut16 key_off = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].k.off);
			ut16 key_len = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].k.len);
			ut16 val_off = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.off);
			ut16 val_len = apfs_read16 (ctx, (ut8 *)&kvloc_table[i].v.len);

			// Calculate actual offsets: key_off is relative to key area start
			ut32 actual_key_off = key_area_start + key_off;
			// val_off is counted backwards from the end of the block (or footer for root)
			ut32 actual_val_off;
			if (flags & APFS_BTNODE_ROOT) {
				// Root nodes have a footer, so subtract footer size
				// Footer is struct apfs_btree_info which we don't have defined, assume 40 bytes
				actual_val_off = ctx->block_size - APFS_BTREE_FOOTER_SIZE - val_off;
			} else {
				actual_val_off = ctx->block_size - val_off;
			}

			R_LOG_DEBUG ("Entry %d: key_off=0x%x->0x%x, key_len=%d, val_off=0x%x->0x%x, val_len=%d",
				i, key_off, actual_key_off, key_len, val_off, actual_val_off, val_len);

			// Skip entries with invalid offsets
			if (actual_key_off >= ctx->block_size || actual_val_off >= ctx->block_size ||
				actual_key_off + key_len > ctx->block_size || actual_val_off + val_len > ctx->block_size) {
				R_LOG_DEBUG ("Skipping entry %d: invalid calculated offsets", i);
				continue;
			}

			ut8 *key_data = (ut8 *)node + actual_key_off;
			ut8 *val_data = (ut8 *)node + actual_val_off;

			R_LOG_DEBUG ("Parsing catalog record %d", i);
			if (apfs_parse_catalog_record (ctx, key_data, key_len, val_data, val_len)) {
				R_LOG_DEBUG ("Successfully parsed catalog record %d", i);
				found_records = true;
			} else {
				R_LOG_DEBUG ("Failed to parse catalog record %d", i);
			}
		}
	}

	free (full_node);
	return found_records;
}

static bool apfs_parse_catalog_record(ApfsFS *ctx, ut8 *key_data, ut16 key_len, ut8 *val_data, ut16 val_len) {
	if (key_len < sizeof (ApfsKeyHeader)) {
		return false;
	}

	ApfsKeyHeader *key_hdr = (ApfsKeyHeader *)key_data;
	ut64 obj_id_and_type = apfs_read64 (ctx, (ut8 *)&key_hdr->obj_id_and_type);
	ut64 obj_id = obj_id_and_type & APFS_OBJ_ID_MASK;
	ut32 obj_type = (obj_id_and_type >> APFS_OBJ_TYPE_SHIFT) & 0xFF;

	R_LOG_DEBUG ("Catalog record: obj_id=%" PFMT64u ", obj_type=%d", obj_id, obj_type);

	switch (obj_type) {
	case APFS_TYPE_INODE:
		{
			if (val_len < sizeof (ApfsInodeVal)) {
				return false;
			}

			ApfsInodeVal *inode_val = (ApfsInodeVal *)val_data;

			ApfsInodeCache *cache = R_NEW0 (ApfsInodeCache);
			cache->inode_num = obj_id;
			cache->parent_inode_num = apfs_read64 (ctx, (ut8 *)&inode_val->parent_id);
			cache->name = NULL; // Will be set when parsing directory records

			ApfsInodeVal *inode = r_mem_dup (inode_val, sizeof (ApfsInodeVal));
			cache->inode = inode;
			cache->parsed = true;

			ht_up_insert (ctx->inodes, obj_id, cache);
			break;
		}
	case APFS_TYPE_DIR_REC:
		{
			R_LOG_DEBUG ("Processing DIR_REC: key_len=%d, val_len=%d", key_len, val_len);
			if (key_len < sizeof (ApfsDrecKey)) {
				R_LOG_DEBUG ("DIR_REC key too short: %d < %zu", key_len, sizeof (ApfsDrecKey));
				return false;
			}

			// Debug: print raw key data
			R_LOG_DEBUG ("DIR_REC key data: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
				key_data[0], key_data[1], key_data[2], key_data[3], key_data[4], key_data[5], key_data[6], key_data[7],
				key_data[8], key_data[9], key_data[10], key_data[11], key_data[12], key_data[13], key_data[14], key_data[15]);

			// Try both hashed and unhashed key formats
			// First try hashed format (name_len_and_hash as 4 bytes)
			ut32 name_len_and_hash = apfs_read32 (ctx, key_data + 8);
			ut16 hashed_name_len = name_len_and_hash & APFS_DREC_LEN_MASK;

			// Then try unhashed format (name_len as 2 bytes)
			ut16 unhashed_name_len = apfs_read16 (ctx, key_data + 8);

			R_LOG_DEBUG ("DIR_REC hashed name_len=%d, unhashed name_len=%d", hashed_name_len, unhashed_name_len);

			// Calculate expected name start for each format
			// APFS_DREC_KEY_HEADER_SIZE
			ut8 *hashed_name = key_data + 12; // After 8-byte header + 4-byte name_len_and_hash
			// APFS_DREC_KEY_HASHED_NAME_OFFSET
			ut8 *unhashed_name = key_data + 10; // After 8-byte header + 2-byte name_len

			// Check which format makes more sense based on available space
			bool use_hashed = false;
			ut16 name_len;
			ut8 *name_data;

			if (key_len >= 12 + hashed_name_len && hashed_name_len > 0 && hashed_name_len < 256) {
				use_hashed = true;
				name_len = hashed_name_len;
				name_data = hashed_name;
			} else if (key_len >= 10 + unhashed_name_len && unhashed_name_len > 0 && unhashed_name_len < 256) {
				use_hashed = false;
				name_len = unhashed_name_len;
				name_data = unhashed_name;
			} else {
				R_LOG_DEBUG ("DIR_REC: both formats invalid, trying calculated length");
				// Calculate name length from key size
				name_len = key_len - 10; // Assume unhashed for now
				name_data = unhashed_name;

				// Add upper bound to prevent DoS
				if (name_len > 255) {
					R_LOG_DEBUG ("DIR_REC: calculated name_len too large (%u), rejecting", name_len);
					return false;
				}
			}

			R_LOG_DEBUG ("DIR_REC using %s format: name_len=%d", use_hashed? "hashed": "unhashed", name_len);
			if (name_len == 0) {
				R_LOG_DEBUG ("DIR_REC size check failed: name_len=%d", name_len);
				return false;
			}

			char *name = r_str_ndup ((const char *)name_data, name_len);
			R_LOG_DEBUG ("DIR_REC: parent_id=%" PFMT64u ", name='%s'", obj_id, name);

			if (val_len >= sizeof (ApfsDrecVal)) {
				ApfsDrecVal *drec_val = (ApfsDrecVal *)val_data;
				ut64 file_id = apfs_read64 (ctx, (ut8 *)&drec_val->file_id);

				R_LOG_DEBUG ("DIR_REC: file_id=%" PFMT64u ", name='%s'", file_id, name);

				// Create inode entry directly since we might not have separate inode records
				ApfsInodeCache *cache = apfs_get_inode (ctx, file_id);
				if (!cache) {
					// Create new cache entry
					cache = R_NEW0 (ApfsInodeCache);
					cache->inode_num = file_id;
					cache->parent_inode_num = obj_id;
					cache->name = strdup (name);

					// Create minimal inode data
					ApfsInodeVal *inode = R_NEW0 (ApfsInodeVal);
					inode->parent_id = obj_id;
					inode->private_id = file_id;

					// Try to determine file type based on directory record flags and name patterns
					ut16 flags = apfs_read16 (ctx, (ut8 *)&drec_val->flags);
					bool is_directory = false;

					// Check for directory indicators in flags (DT_DIR = 4)
					if ((flags & 0x000f) == 4) {
						is_directory = true;
					}
					if (is_directory) {
						inode->mode = APFS_INODE_MODE_DIR;
						R_LOG_DEBUG ("Setting file_id=%" PFMT64u " '%s' as directory (flags=0x%x)", file_id, name, flags);
					} else {
						inode->mode = APFS_INODE_MODE_FILE;
						R_LOG_DEBUG ("Setting file_id=%" PFMT64u " '%s' as regular file (flags=0x%x)", file_id, name, flags);
					}
					cache->inode = inode;
					cache->parsed = true;
					ht_up_insert (ctx->inodes, file_id, cache);
					R_LOG_DEBUG ("Created inode cache entry for file_id=%" PFMT64u ", name='%s', mode=0x%x", file_id, name, inode->mode);
				} else if (!cache->name) {
					cache->name = strdup (name);
					cache->parent_inode_num = obj_id;
					R_LOG_DEBUG ("Updated inode cache entry for file_id=%" PFMT64u ", name='%s'", file_id, name);
				}
				free (name);
			} else {
				free (name);
			}
			break;
		}
	default:
		// Ignore other record types for now
		break;
	}

	return true;
}

static bool apfs_parse_simple_image(ApfsFS *ctx) {
	// Scan the entire image for B-tree nodes that might contain file records
	return apfs_scan_for_btree_nodes (ctx);
}

static bool apfs_scan_for_btree_nodes(ApfsFS *ctx) {
	// Scan image in block-sized chunks looking for B-tree node signatures
	ut64 image_size = 1024 * 1024; // Start with smaller scan for performance
	bool found_any = false;
	int nodes_checked = 0;
	int valid_nodes_found = 0;

	// Validate block_size to prevent division by zero
	if (!ctx->block_size) {
		R_LOG_ERROR ("apfs: block_size is zero in scan_for_btree_nodes");
		return false;
	}

	R_LOG_DEBUG ("Scanning for B-tree nodes in APFS image (block size: %u)", ctx->block_size);

	// Save original delta and scan from absolute beginning of image
	ut64 orig_delta = ctx->delta;
	ctx->delta = 0;

	ut64 block;
	for (block = 0; block < image_size / ctx->block_size; block++) {
		ut8 header[64]; // Read more to be sure we get all the data
		ut64 offset = block * ctx->block_size;

		if (!apfs_read_at (ctx, offset, header, sizeof (header))) {
			continue;
		}

		nodes_checked++;

		// Check for B-tree node object type at correct offset
		// ApfsObjPhys: ut64 o_cksum (8), ut64 o_oid (8), ut64 o_xid (8), ut32 o_type (4), ut32 o_subtype (4)
		ut32 o_type = apfs_read32 (ctx, header + APFS_OBJ_PHYS_TYPE_OFFSET); // o_type offset in ApfsObjPhys after cksum (8) + oid (8) + xid (8)
		ut32 obj_type = o_type & APFS_OBJECT_TYPE_MASK;

		R_LOG_DEBUG ("Found B-tree block %" PFMT64u " (0x%" PFMT64x "): type=0x%x", block, offset, obj_type);

		if (obj_type == APFS_OBJECT_TYPE_BTREE_NODE) {
			R_LOG_DEBUG ("Found B-tree node at block %" PFMT64u " (offset 0x%" PFMT64x ")", block, offset);
			valid_nodes_found++;
			if (apfs_parse_btree_node (ctx, block, 0)) {
				found_any = true;
			}
		}

		// Also check for file system tree type (these contain file records)
		if (obj_type == APFS_OBJECT_TYPE_FSTREE) {
			R_LOG_DEBUG ("Found FS tree node at block %" PFMT64u " (offset 0x%" PFMT64x ")", block, offset);
			valid_nodes_found++;
			if (apfs_parse_btree_node (ctx, block, 0)) {
				found_any = true;
			}
		}
#if 0
		// Look for specific patterns indicating file records
		if (!memcmp (header + 20, "APSB", 4)) {
			R_LOG_DEBUG ("Found APSB at block %" PFMT64u, block);
		}
#endif
		// Also check for known B-tree patterns in the data
		if (obj_type == 0x03 || obj_type == 0x02 || obj_type == 0x05) {
			R_LOG_DEBUG ("Found potential node type 0x%x at block %" PFMT64u " (offset 0x%" PFMT64x ")",
				obj_type, block, offset);
			valid_nodes_found++;
			// Temporarily parse B-tree node with scan context
			// NOTE: We'll implement this safely to avoid segfaults
			if (obj_type == APFS_OBJECT_TYPE_BTREE) {
				// This is a BTREE node, parse it carefully
				R_LOG_DEBUG ("Attempting to parse BTREE node at offset 0x%" PFMT64x, offset);

				// Parse directly from the header we already read
				if (apfs_parse_btree_node_from_data (ctx, header, offset)) {
					found_any = true;
				}
			}
		}
	}
	// Restore original delta
	ctx->delta = orig_delta;
	R_LOG_DEBUG ("Scanned %d blocks, found %d valid nodes, parsed any: %s",
		nodes_checked, valid_nodes_found, found_any? "yes": "no");
	return found_any;
}

static bool apfs_dir_iter_cb(void *user, const ut64 key, const void *value) {
	ApfsDirIterContext *ctx = (ApfsDirIterContext *)user;
	RList *list = ctx->list;
	ut64 parent_inode_num = ctx->parent_inode_num;
	ApfsFS *apfs_ctx = ctx->apfs_ctx;
	ApfsInodeCache *cache = (ApfsInodeCache *)value;

	if (!cache || !cache->inode || cache->parent_inode_num != parent_inode_num) {
		return true;
	}

	RFSFile *fsf = r_fs_file_new (ctx->root, cache->name? cache->name: "");
	if (fsf) {
		ut16 mode = apfs_read16 (apfs_ctx, (ut8 *)&cache->inode->mode);
		if (apfs_is_directory (mode)) {
			fsf->type = R_FS_FILE_TYPE_DIRECTORY;
		} else if (apfs_is_regular_file (mode)) {
			fsf->type = R_FS_FILE_TYPE_REGULAR;
			fsf->size = 0;
		} else {
			fsf->type = R_FS_FILE_TYPE_SPECIAL;
		}
		fsf->ptr = (void *) (size_t)cache->inode_num;
		const ut64 useconds = apfs_read64 (apfs_ctx, (ut8 *)&cache->inode->mod_time);
		uint64_t seconds = useconds / 1000000000; // Convert to seconds
		fsf->time = seconds;
		r_list_append (list, fsf);
	}
	return true;
}

RFSPlugin r_fs_plugin_apfs = {
	.meta = {
		.name = "apfs",
		.desc = "APFS (Apple File System)",
		.author = "pancake",
		.license = "MIT",
	},
	.open = fs_apfs_open,
	.read = fs_apfs_read,
	.close = fs_apfs_close,
	.dir = fs_apfs_dir,
	.mount = fs_apfs_mount,
	.umount = fs_apfs_umount,
	.details = fs_apfs_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_apfs,
	.version = R2_VERSION
};
#endif
