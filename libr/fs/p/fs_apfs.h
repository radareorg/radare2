
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
