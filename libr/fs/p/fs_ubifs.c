/* radare2: Unsorted Block Images File System - LGPL - Copyright 2025 - MiKi (mikelloc) */

#include <r_fs.h>
#include <r_lib.h>
#include <r_util.h>

#if __has_include(<lzo/lzo1x.h>)
#include <lzo/lzo1x.h>
#define HAVE_LZO 1
#endif

// UBI Magic numbers
#define UBI_EC_HDR_MAGIC       0x55424923 // "UBI#"
#define UBI_VID_HDR_MAGIC      0x55424921 // "UBI!"
#define UBI_CRC32_INIT         0xFFFFFFFF
#define UBI_EC_HDR_SZ          64
#define UBI_VID_HDR_SZ         64
#define UBI_VTBL_REC_SZ        172
#define UBI_MAX_VOLUMES        128
#define UBI_INTERNAL_VOL_START 2147479551U

// UBIFS Magic and constants
#define UBIFS_NODE_MAGIC    0x06101831 // Little-endian!
#define UBIFS_CRC32_INIT    0xFFFFFFFF
#define UBIFS_COMMON_HDR_SZ 24
#define UBIFS_BLOCK_SIZE    4096
#define UBIFS_MAX_KEY_LEN   16
#define UBIFS_SK_LEN        8
#define UBIFS_ROOT_INO      1

// UBIFS node types
#define UBIFS_INO_NODE  0
#define UBIFS_DATA_NODE 1
#define UBIFS_DENT_NODE 2
#define UBIFS_XENT_NODE 3
#define UBIFS_TRUN_NODE 4
#define UBIFS_PAD_NODE  5
#define UBIFS_SB_NODE   6
#define UBIFS_MST_NODE  7
#define UBIFS_REF_NODE  8
#define UBIFS_IDX_NODE  9
#define UBIFS_CS_NODE   10
#define UBIFS_ORPH_NODE 11
#define UBIFS_AUTH_NODE 12
#define UBIFS_SIG_NODE  13

// UBIFS key types
#define UBIFS_INO_KEY  0
#define UBIFS_DATA_KEY 1
#define UBIFS_DENT_KEY 2
#define UBIFS_XENT_KEY 3

// UBIFS inode types
#define UBIFS_ITYPE_REG  0
#define UBIFS_ITYPE_DIR  1
#define UBIFS_ITYPE_LNK  2
#define UBIFS_ITYPE_BLK  3
#define UBIFS_ITYPE_CHR  4
#define UBIFS_ITYPE_FIFO 5
#define UBIFS_ITYPE_SOCK 6

// Compression types
#define UBIFS_COMPR_NONE 0
#define UBIFS_COMPR_LZO  1
#define UBIFS_COMPR_ZLIB 2
#define UBIFS_COMPR_ZSTD 3

// Key parsing macros
#define UBIFS_S_KEY_BLOCK_MASK 0x1FFFFFFF

// Erase Counter Header
R_PACKED (
typedef struct {
	ut32 magic;
	ut8 version;
	ut8 padding1[3];
	ut64 ec;
	ut32 vid_hdr_offset;
	ut32 data_offset;
	ut32 image_seq;
	ut8 padding2[32];
	ut32 hdr_crc;
}) ubi_ec_hdr_t;

// Volume ID Header
R_PACKED (
typedef struct {
	ut32 magic;
	ut8 version;
	ut8 vol_type;
	ut8 copy_flag;
	ut8 compat;
	ut32 vol_id;
	ut32 lnum;
	ut8 padding1[4];
	ut32 data_size;
	ut32 used_ebs;
	ut32 data_pad;
	ut32 data_crc;
	ut8 padding2[4];
	ut64 sqnum;
	ut8 padding3[12];
	ut32 hdr_crc;
}) ubi_vid_hdr_t;

// Volume Table Record
R_PACKED (
typedef struct {
	ut32 reserved_pebs;
	ut32 alignment;
	ut32 data_pad;
	ut8 vol_type;
	ut8 upd_marker;
	ut16 name_len;
	char name[128];
	ut8 flags;
	ut8 padding[23];
	ut32 crc;
}) ubi_vtbl_rec_t;

// Common Header
R_PACKED (
typedef struct {
	ut32 magic;
	ut32 crc;
	ut64 sqnum;
	ut32 len;
	ut8 node_type;
	ut8 group_type;
	ut8 padding[2];
}) ubifs_ch_t;

// Superblock Node
R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut8 padding[2];
	ut8 key_hash;
	ut8 key_fmt;
	ut32 flags;
	ut32 min_io_size;
	ut32 leb_size;
	ut32 leb_cnt;
	ut32 max_leb_cnt;
	ut64 max_bud_bytes;
	ut32 log_lebs;
	ut32 lpt_lebs;
	ut32 orph_lebs;
	ut32 jhead_cnt;
	ut32 fanout;
	ut32 lsave_cnt;
	ut16 fmt_version;
	ut16 default_compr;
	ut8 padding1[2];
	ut32 rp_uid;
	ut32 rp_gid;
	ut64 rp_size;
	ut32 time_gran;
	ut8 uuid[16];
	ut32 ro_compat_version;
	ut8 hmac[64];
	ut8 hmac_wkm[64];
	ut16 hash_algo;
	ut8 hash_mst[64];
	ut8 padding2[3774];
}) ubifs_sb_node_t;

// Master Node
R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut64 highest_inum;
	ut64 cmt_no;
	ut32 flags;
	ut32 log_lnum;
	ut32 root_lnum;
	ut32 root_offs;
	ut32 root_len;
	ut32 gc_lnum;
	ut32 ihead_lnum;
	ut32 ihead_offs;
	ut64 index_size;
	ut64 total_free;
	ut64 total_dirty;
	ut64 total_used;
	ut64 total_dead;
	ut64 total_dark;
	ut32 lpt_lnum;
	ut32 lpt_offs;
	ut32 nhead_lnum;
	ut32 nhead_offs;
	ut32 ltab_lnum;
	ut32 ltab_offs;
	ut32 lsave_lnum;
	ut32 lsave_offs;
	ut32 lscan_lnum;
	ut32 empty_lebs;
	ut32 idx_lebs;
	ut32 leb_cnt;
	ut8 hash_root_idx[64];
	ut8 hash_lpt[64];
	ut8 hmac[64];
	ut8 padding[152];
}) ubifs_mst_node_t;

// Index Node
R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut16 child_cnt;
	ut16 level;
	// branches follow
}) ubifs_idx_node_t;

R_PACKED (
typedef struct {
	ut32 lnum;
	ut32 offs;
	ut32 len;
	ut8 key[UBIFS_SK_LEN];
}) ubifs_branch_t;

// Inode Node
R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut8 key[UBIFS_MAX_KEY_LEN];
	ut64 creat_sqnum;
	ut64 size;
	ut64 atime_sec;
	ut64 ctime_sec;
	ut64 mtime_sec;
	ut32 atime_nsec;
	ut32 ctime_nsec;
	ut32 mtime_nsec;
	ut32 nlink;
	ut32 uid;
	ut32 gid;
	ut32 mode;
	ut32 flags;
	ut32 data_len;
	ut32 xattr_cnt;
	ut32 xattr_size;
	ut8 padding1[4];
	ut32 xattr_names;
	ut16 compr_type;
	ut8 padding2[26];
	// data follows
}) ubifs_ino_node_t;

// Directory Entry Node
R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut8 key[UBIFS_MAX_KEY_LEN];
	ut64 inum;
	ut8 padding1;
	ut8 type;
	ut16 nlen;
	ut32 cookie;
	// name follows
}) ubifs_dent_node_t;

R_PACKED (
typedef struct {
	ubifs_ch_t ch;
	ut8 key[UBIFS_MAX_KEY_LEN];
	ut32 size;
	ut16 compr_type;
	ut16 plaintext_size;
	// data follows
}) ubifs_data_node_t;

// Parsed key structure
typedef struct {
	ut32 ino_num;
	ut32 key_type;
	ut32 khash;
} ubifs_key_t;

// Inode cache entry
typedef struct {
	ut64 ino_num;
	ubifs_ino_node_t *ino;
	RList *data_nodes;
	RList *dent_nodes;
} ubifs_inode_t;

// UBI volume mapping (for UBI containers)
typedef struct {
	ut32 peb_size;
	ut32 vid_hdr_offset;
	ut32 data_offset;
	ut64 ubi_base;  // Base offset of UBI container in file
	HtUP *leb_map;  // Hash table: lnum -> PEB number
} ubi_vol_t;

// Filesystem context
typedef struct {
	RIOBind *iob;
	ut64 delta;
	ut32 leb_size;
	ut32 min_io_size;
	ut32 leb_cnt;
	ut32 max_leb_cnt;
	ut16 default_compr;
	ut32 root_lnum;
	ut32 root_offs;
	HtUP *inodes; // Hash table: ino_num -> ubifs_inode_t
	bool mounted;
	ubi_vol_t *ubi_vol; // NULL for raw UBIFS, filled for UBI containers
} ubifs_ctx_t;

static ubifs_key_t ubifs_parse_key(const ut8 *key_buf) {
	ubifs_key_t key = { 0 };
	ut32 hkey = r_read_le32 (key_buf);
	ut32 lkey = r_read_le32 (key_buf + 4);

	key.ino_num = hkey & UBIFS_S_KEY_BLOCK_MASK;
	key.key_type = lkey >> 29;
	key.khash = lkey;

	return key;
}

static bool ubifs_walk_index(ubifs_ctx_t *ctx, ut32 lnum, ut32 offs);
static ubifs_inode_t *ubifs_get_inode(ubifs_ctx_t *ctx, ut64 ino_num);
static ut64 ubifs_lookup_path(ubifs_ctx_t *ctx, const char *path);

// Build UBI volume LEB-to-PEB mapping
static ubi_vol_t *ubi_build_volume_map(RIOBind *iob, ut64 base_offset, ut32 target_vol_id) {
	ut8 ec_hdr_buf[UBI_EC_HDR_SZ];

	if (!iob->read_at (iob->io, base_offset, ec_hdr_buf, UBI_EC_HDR_SZ)) {
		return NULL;
	}

	ut32 magic = r_read_be32 (ec_hdr_buf);
	if (magic != UBI_EC_HDR_MAGIC) {
		return NULL;
	}

	ut32 vid_hdr_offset = r_read_be32 (ec_hdr_buf + 16);
	ut32 data_offset = r_read_be32 (ec_hdr_buf + 20);

	// Determine PEB size
	ut32 peb_size = 0;
	ut32 try_peb;
	for (try_peb = 0x20000; try_peb <= 0x80000; try_peb += 0x20000) {
		ut8 next_magic[4];
		if (iob->read_at (iob->io, base_offset + try_peb, next_magic, 4)) {
			if (r_read_be32 (next_magic) == UBI_EC_HDR_MAGIC) {
				peb_size = try_peb;
				break;
			}
		}
	}

	if (peb_size == 0) {
		return NULL;
	}

	ubi_vol_t *vol = R_NEW0 (ubi_vol_t);
	if (!vol) {
		return NULL;
	}

	vol->peb_size = peb_size;
	vol->vid_hdr_offset = vid_hdr_offset;
	vol->data_offset = data_offset;
	vol->ubi_base = base_offset;
	vol->leb_map = ht_up_new0 ();

	// Scan all PEBs to build LEB mapping for target volume
	ut32 max_pebs = 1000;  // Safety limit
	ut32 peb_num;
	for (peb_num = 0; peb_num < max_pebs; peb_num++) {
		ut64 peb_offset = base_offset + (ut64)peb_num * peb_size;

		ut8 vid_hdr_buf[UBI_VID_HDR_SZ];
		if (!iob->read_at (iob->io, peb_offset + vid_hdr_offset, vid_hdr_buf, UBI_VID_HDR_SZ)) {
			break;
		}

		ut32 vid_magic = r_read_be32 (vid_hdr_buf);
		if (vid_magic != UBI_VID_HDR_MAGIC) {
			continue;  // Skip non-data PEBs
		}

		ut32 vol_id = r_read_be32 (vid_hdr_buf + 8);
		ut32 lnum = r_read_be32 (vid_hdr_buf + 12);

		if (vol_id == target_vol_id) {
			ut32 *peb_ptr = R_NEW (ut32);
			if (peb_ptr) {
				*peb_ptr = peb_num;
				ht_up_insert (vol->leb_map, lnum, peb_ptr);
			}
		}
	}

	return vol;
}

static ut64 ubi_find_ubifs_offset(RIOBind *iob, ut64 base_offset) {
	ut8 ec_hdr_buf[UBI_EC_HDR_SZ];

	if (!iob->read_at (iob->io, base_offset, ec_hdr_buf, UBI_EC_HDR_SZ)) {
		return 0;
	}

	ut32 magic = r_read_be32 (ec_hdr_buf);
	if (magic != UBI_EC_HDR_MAGIC) {
		// Not a UBI container, assume raw UBIFS
		return 0;
	}

	// Parse EC header to get offsets
	// EC header: magic(4) + version(1) + padding1(3) + ec(8) + vid_hdr_offset(4) + data_offset(4)
	ut32 vid_hdr_offset = r_read_be32 (ec_hdr_buf + 16);
	ut32 data_offset = r_read_be32 (ec_hdr_buf + 20);

	ut32 peb_size = 0;
	ut32 try_peb;

	for (try_peb = 0x20000; try_peb <= 0x80000; try_peb += 0x20000) {
		ut8 next_magic[4];
		if (iob->read_at (iob->io, base_offset + try_peb, next_magic, 4)) {
			if (r_read_be32 (next_magic) == UBI_EC_HDR_MAGIC) {
				peb_size = try_peb;
				break;
			}
		}
	}

	if (peb_size == 0) {
		R_LOG_ERROR ("Could not determine UBI PEB size");
		return 0;
	}

	ut32 peb_num;
	for (peb_num = 2; peb_num < 10; peb_num++) {
		ut64 peb_offset = base_offset + (ut64)peb_num * peb_size;

		ut8 vid_hdr_buf[UBI_VID_HDR_SZ];
		if (!iob->read_at (iob->io, peb_offset + vid_hdr_offset, vid_hdr_buf, UBI_VID_HDR_SZ)) {
			continue;
		}

		ut32 vid_magic = r_read_be32 (vid_hdr_buf);
		if (vid_magic != UBI_VID_HDR_MAGIC) {
			continue;
		}

		ut32 vol_id = r_read_be32 (vid_hdr_buf + 8);
		ut32 lnum = r_read_be32 (vid_hdr_buf + 12);

		if (vol_id >= UBI_INTERNAL_VOL_START) {
			continue;
		}

		if (lnum == 0) {
			ut64 ubifs_offset = peb_offset + data_offset;

			ut8 ubifs_magic[4];
			if (iob->read_at (iob->io, ubifs_offset, ubifs_magic, 4)) {
				ut32 magic = r_read_le32 (ubifs_magic);
				if (magic == UBIFS_NODE_MAGIC) {
					return ubifs_offset;
				}
			}
		}
	}

	R_LOG_ERROR ("Could not find UBIFS volume in UBI container");
	return 0;
}

static void ubifs_free_inode(ubifs_inode_t *inode) {
	if (!inode) {
		return;
	}
	r_list_free (inode->data_nodes);
	r_list_free (inode->dent_nodes);
	free (inode->ino);
	free (inode);
}

static bool ubifs_read_at(ubifs_ctx_t *ctx, ut64 offset, ut8 *buf, int len) {
	if (!ctx || !ctx->iob || !ctx->iob->read_at) {
		return false;
	}

	// If we have UBI volume mapping, translate LEB offset to PEB offset
	if (ctx->ubi_vol) {
		// Handle reads that may span multiple LEBs
		int bytes_read = 0;
		while (bytes_read < len) {
			ut32 lnum = (offset + bytes_read) / ctx->leb_size;
			ut32 leb_offs = (offset + bytes_read) % ctx->leb_size;

			bool found;
			ut32 *peb_ptr = ht_up_find (ctx->ubi_vol->leb_map, lnum, &found);
			if (!found || !peb_ptr) {
				R_LOG_ERROR ("LEB %u not found in UBI volume mapping", lnum);
				return false;
			}

			ut32 peb_num = *peb_ptr;
			ut64 peb_offset = ctx->ubi_vol->ubi_base + (ut64)peb_num * ctx->ubi_vol->peb_size;
			ut64 read_offset = peb_offset + ctx->ubi_vol->data_offset + leb_offs;

			// Calculate how much we can read from this LEB
			ut32 available_in_leb = ctx->leb_size - leb_offs;
			ut32 to_read = R_MIN (available_in_leb, len - bytes_read);

			if (!ctx->iob->read_at (ctx->iob->io, read_offset, buf + bytes_read, to_read)) {
				R_LOG_ERROR ("Failed to read %u bytes from PEB %u at offset 0x%"PFMT64x,
					to_read, peb_num, read_offset);
				return false;
			}

			bytes_read += to_read;
		}
		return true;
	}

	// Raw UBIFS (no UBI container)
	return ctx->iob->read_at (ctx->iob->io, ctx->delta + offset, buf, len);
}

static bool ubifs_read_ch(ubifs_ctx_t *ctx, ut64 offset, ubifs_ch_t *ch) {
	if (!ubifs_read_at (ctx, offset, (ut8 *)ch, UBIFS_COMMON_HDR_SZ)) {
		return false;
	}
	if (r_read_le32 ((ut8 *)&ch->magic) != UBIFS_NODE_MAGIC) {
		return false;
	}
	return true;
}

static bool ubifs_walk_index_depth(ubifs_ctx_t *ctx, ut32 lnum, ut32 offs, int depth);

static bool ubifs_walk_index(ubifs_ctx_t *ctx, ut32 lnum, ut32 offs) {
	return ubifs_walk_index_depth(ctx, lnum, offs, 0);
}

static bool ubifs_walk_index_depth(ubifs_ctx_t *ctx, ut32 lnum, ut32 offs, int depth) {
	if (depth > 20) {
		return false;
	}
	ut64 offset = (ut64)lnum * ctx->leb_size + offs;

	ubifs_ch_t ch;
	if (!ubifs_read_ch (ctx, offset, &ch)) {
		return false;
	}

	ut32 node_len = r_read_le32 ((ut8 *)&ch.len);
	ut8 node_type = ch.node_type;

	if (node_len == 0 || node_len > ctx->leb_size) {
		return false;
	}

	ut8 *buf = calloc (1, node_len);
	if (!buf) {
		return false;
	}

	if (!ubifs_read_at (ctx, offset, buf, node_len)) {
		free (buf);
		return false;
	}

	bool ret = true;

	switch (node_type) {
	case UBIFS_IDX_NODE: {
		ubifs_idx_node_t *idx = (ubifs_idx_node_t *)buf;
		ut16 child_cnt = r_read_le16 ((ut8 *)&idx->child_cnt);
		ut32 branches_size = node_len - sizeof (ubifs_idx_node_t);
		ut32 branch_size = child_cnt > 0 ? branches_size / child_cnt : 0;
		ut8 *branch_ptr;
		ut16 i;

		ut32 max_children = branches_size / sizeof (ubifs_branch_t);
		if (child_cnt == 0 || child_cnt > max_children || branch_size < sizeof (ubifs_branch_t)) {
			break;
		}

		branch_ptr = buf + sizeof (ubifs_idx_node_t);
		for (i = 0; i < child_cnt && ret; i++) {
			ubifs_branch_t *br = (ubifs_branch_t *)branch_ptr;
			ut32 br_lnum = r_read_le32 ((ut8 *)&br->lnum);
			ut32 br_offs = r_read_le32 ((ut8 *)&br->offs);

			ret = ubifs_walk_index_depth (ctx, br_lnum, br_offs, depth + 1);
			branch_ptr += branch_size;
		}
		break;
	}

	case UBIFS_INO_NODE: {
		ubifs_ino_node_t *ino = (ubifs_ino_node_t *)buf;
		ubifs_key_t key = ubifs_parse_key (ino->key);

		ubifs_inode_t *inode = ht_up_find (ctx->inodes, key.ino_num, NULL);
		if (!inode) {
			inode = R_NEW0 (ubifs_inode_t);
			if (inode) {
				inode->ino_num = key.ino_num;
				inode->data_nodes = r_list_new ();
				inode->dent_nodes = r_list_new ();
				ht_up_insert (ctx->inodes, key.ino_num, inode);
			}
		}

		if (inode && !inode->ino) {
			inode->ino = R_NEW0 (ubifs_ino_node_t);
			if (inode->ino) {
				memcpy (inode->ino, ino, sizeof (ubifs_ino_node_t));
			}
		}
		break;
	}

	case UBIFS_DENT_NODE: {
		ubifs_dent_node_t *dent = (ubifs_dent_node_t *)buf;
		ubifs_key_t key = ubifs_parse_key (dent->key);

		ubifs_inode_t *inode = ht_up_find (ctx->inodes, key.ino_num, NULL);
		if (!inode) {
			inode = R_NEW0 (ubifs_inode_t);
			if (inode) {
				inode->ino_num = key.ino_num;
				inode->data_nodes = r_list_new ();
				inode->dent_nodes = r_list_new ();
				ht_up_insert (ctx->inodes, key.ino_num, inode);
			}
		}

		if (inode) {
			ut64 *dent_off = R_NEW (ut64);
			if (dent_off) {
				*dent_off = offset;
				r_list_append (inode->dent_nodes, dent_off);
			}
		}
		break;
	}

	case UBIFS_DATA_NODE: {
		ubifs_data_node_t *data = (ubifs_data_node_t *)buf;
		ubifs_key_t key = ubifs_parse_key (data->key);

		ubifs_inode_t *inode = ht_up_find (ctx->inodes, key.ino_num, NULL);
		if (!inode) {
			inode = R_NEW0 (ubifs_inode_t);
			if (inode) {
				inode->ino_num = key.ino_num;
				inode->data_nodes = r_list_new ();
				inode->dent_nodes = r_list_new ();
				ht_up_insert (ctx->inodes, key.ino_num, inode);
			}
		}

		if (inode) {
			ut64 *data_off = R_NEW (ut64);
			if (data_off) {
				*data_off = offset;
				r_list_append (inode->data_nodes, data_off);
			}
		}
		break;
	}
	}

	free (buf);
	return ret;
}

static ubifs_inode_t *ubifs_get_inode(ubifs_ctx_t *ctx, ut64 ino_num) {
	return ht_up_find (ctx->inodes, ino_num, NULL);
}

static bool fs_ubifs_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);

	ubifs_ctx_t *ctx = R_NEW0 (ubifs_ctx_t);
	if (!ctx) {
		return false;
	}

	ctx->iob = &root->iob;
	ctx->delta = root->delta;
	ctx->inodes = ht_up_new0 ();
	ctx->ubi_vol = NULL;

	ut64 ubi_offset = ubi_find_ubifs_offset (ctx->iob, ctx->delta);
	bool is_ubi = (ubi_offset > 0);

	ubifs_ch_t ch;
	if (is_ubi) {
		if (!ctx->iob->read_at (ctx->iob->io, ubi_offset, (ut8 *)&ch, UBIFS_COMMON_HDR_SZ)) {
			R_LOG_ERROR ("Failed to read UBIFS superblock from UBI");
			goto fail;
		}
	} else {
		if (!ubifs_read_ch (ctx, 0, &ch)) {
			R_LOG_ERROR ("Failed to read UBIFS superblock");
			goto fail;
		}
	}

	if (ch.node_type != UBIFS_SB_NODE) {
		R_LOG_ERROR ("Invalid superblock node type: %d", ch.node_type);
		goto fail;
	}

	ut32 sb_len = r_read_le32 ((ut8 *)&ch.len);
	if (sb_len == 0 || sb_len > 65536) {
		R_LOG_ERROR ("Invalid superblock length: %u", sb_len);
		goto fail;
	}

	ut8 *sb_buf = calloc (1, sb_len);
	if (!sb_buf) {
		goto fail;
	}

	if (is_ubi) {
		if (!ctx->iob->read_at (ctx->iob->io, ubi_offset, sb_buf, sb_len)) {
			free (sb_buf);
			R_LOG_ERROR ("Failed to read UBIFS superblock data from UBI");
			goto fail;
		}
	} else {
		if (!ubifs_read_at (ctx, 0, sb_buf, sb_len)) {
			free (sb_buf);
			goto fail;
		}
	}

	// Read fields directly from the buffer at correct offsets to avoid structure packing issues
	// The C structure offsets don't match the on-disk format
	ctx->leb_size = r_read_le32 (sb_buf + 36);
	ctx->min_io_size = r_read_le32 (sb_buf + 32);
	ctx->leb_cnt = r_read_le32 (sb_buf + 40);
	ctx->max_leb_cnt = r_read_le32 (sb_buf + 44);
	ctx->default_compr = r_read_le16 (sb_buf + 0x54);

	free (sb_buf);

	if (is_ubi) {
		ctx->ubi_vol = ubi_build_volume_map (ctx->iob, ctx->delta, 0);
		if (!ctx->ubi_vol) {
			R_LOG_ERROR ("Failed to build UBI volume mapping");
			goto fail;
		}
		ctx->delta = 0;  // Use UBI mapping for all subsequent reads
	}

	ut64 mst_offset = ctx->leb_size;
	if (!ubifs_read_ch (ctx, mst_offset, &ch)) {
		R_LOG_ERROR ("Failed to read UBIFS master node");
		goto fail;
	}

	if (ch.node_type != UBIFS_MST_NODE) {
		R_LOG_ERROR ("Invalid master node type: %d", ch.node_type);
		goto fail;
	}

	ut32 mst_len = r_read_le32 ((ut8 *)&ch.len);
	ut8 *mst_buf = calloc (1, mst_len);
	if (!mst_buf) {
		goto fail;
	}

	if (!ubifs_read_at (ctx, mst_offset, mst_buf, mst_len)) {
		free (mst_buf);
		goto fail;
	}

	ubifs_mst_node_t *mst = (ubifs_mst_node_t *)mst_buf;
	ctx->root_lnum = r_read_le32 ((ut8 *)&mst->root_lnum);
	ctx->root_offs = r_read_le32 ((ut8 *)&mst->root_offs);

	free (mst_buf);

	if (!ubifs_walk_index (ctx, ctx->root_lnum, ctx->root_offs)) {
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

static bool ubifs_free_inode_cb(void *user, const ut64 key, const void *value) {
	ubifs_free_inode ((ubifs_inode_t *)value);
	return true;
}

static void fs_ubifs_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);

	ubifs_ctx_t *ctx = root->ptr;
	if (!ctx) {
		return;
	}

	if (ctx->inodes) {
		ht_up_foreach (ctx->inodes, ubifs_free_inode_cb, NULL);
		ht_up_free (ctx->inodes);
	}

	if (ctx->ubi_vol) {
		if (ctx->ubi_vol->leb_map) {
			ht_up_free (ctx->ubi_vol->leb_map);
		}
		free (ctx->ubi_vol);
	}

	free (ctx);
	root->ptr = NULL;
}

static RList *fs_ubifs_dir(RFSRoot *root, const char *path, int view) {
	R_RETURN_VAL_IF_FAIL (root, NULL);

	ubifs_ctx_t *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		return NULL;
	}

	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}

	ut64 dir_inum = ubifs_lookup_path (ctx, path);
	if (!dir_inum) {
		r_list_free (list);
		return NULL;
	}

	ubifs_inode_t *dir_inode = ubifs_get_inode (ctx, dir_inum);
	if (!dir_inode || !dir_inode->dent_nodes) {
		return list;
	}

	RListIter *iter;
	ut64 *dent_off;
	r_list_foreach (dir_inode->dent_nodes, iter, dent_off) {
		ut8 buf[512];
		if (!ubifs_read_at (ctx, *dent_off, buf, sizeof (buf))) {
			continue;
		}

		ubifs_dent_node_t *dent = (ubifs_dent_node_t *)buf;
		ut16 nlen = r_read_le16 ((ut8 *)&dent->nlen);
		ut64 target_inum = r_read_le64 ((ut8 *)&dent->inum);

		if (nlen == 0 || nlen > 255) {
			continue;
		}

		char name[256] = { 0 };
		ut8 *name_ptr = buf + sizeof (ubifs_dent_node_t);
		memcpy (name, name_ptr, R_MIN (nlen, 255));
		name[nlen] = 0;

		ubifs_inode_t *target_inode = ubifs_get_inode (ctx, target_inum);
		if (!target_inode || !target_inode->ino) {
			continue;
		}

		RFSFile *fsf = r_fs_file_new (NULL, name);
		if (!fsf) {
			continue;
		}

		ut32 mode = r_read_le32 ((ut8 *)&target_inode->ino->mode);
		ut32 itype = (mode >> 12) & 0xF;

		switch (itype) {
		case 4: // Directory
			fsf->type = R_FS_FILE_TYPE_DIRECTORY;
			break;
		case 8: // Regular file
			fsf->type = R_FS_FILE_TYPE_REGULAR;
			fsf->size = r_read_le64 ((ut8 *)&target_inode->ino->size);
			break;
		case 10: // Symlink
			fsf->type = R_FS_FILE_TYPE_SYMLINK;
			break;
		default:
			R_LOG_DEBUG ("Unknown itype %u for %s (mode=0x%x)", itype, name, mode);
			fsf->type = R_FS_FILE_TYPE_SPECIAL;
			break;
		}

		fsf->time = r_read_le64 ((ut8 *)&target_inode->ino->mtime_sec);

		r_list_append (list, fsf);
	}

	return list;
}

static ut64 ubifs_lookup_path(ubifs_ctx_t *ctx, const char *path) {
	if (!ctx || !path) {
		return 0;
	}

	ut64 dir_inum = UBIFS_ROOT_INO;

	if (!path || !*path || (path[0] == '/' && path[1] == 0)) {
		return UBIFS_ROOT_INO;
	}

	if (*path == '/') {
		path++;
	}
	char *path_copy = strdup (path);
	if (!path_copy) {
		return 0;
	}

	RList *components = r_str_split_list (path_copy, "/", 0);
	if (!components) {
		free (path_copy);
		return 0;
	}

	RListIter *comp_iter;
	char *component;
	r_list_foreach (components, comp_iter, component) {
		ubifs_inode_t *dir_inode = ubifs_get_inode (ctx, dir_inum);
		if (!dir_inode || !dir_inode->dent_nodes) {
			r_list_free (components);
			free (path_copy);
			return 0;
		}

		bool found = false;
		RListIter *iter;
		ut64 *dent_off;
		r_list_foreach (dir_inode->dent_nodes, iter, dent_off) {
			ut8 buf[512];
			if (!ubifs_read_at (ctx, *dent_off, buf, sizeof (buf))) {
				continue;
			}

			ubifs_dent_node_t *dent = (ubifs_dent_node_t *)buf;
			ut16 nlen = r_read_le16 ((ut8 *)&dent->nlen);

			if (nlen == 0 || nlen > 255) {
				continue;
			}

			char name[256] = { 0 };
			ut8 *name_ptr = buf + sizeof (ubifs_dent_node_t);
			memcpy (name, name_ptr, R_MIN (nlen, 255));
			name[nlen] = 0;

			if (strcmp (name, component) == 0) {
				dir_inum = r_read_le64 ((ut8 *)&dent->inum);
				found = true;
				break;
			}
		}

		if (!found) {
			r_list_free (components);
			free (path_copy);
			return 0;
		}
	}

	r_list_free (components);
	free (path_copy);
	return dir_inum;
}

static RFSFile *fs_ubifs_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);

	ubifs_ctx_t *ctx = root->ptr;
	if (!ctx || !ctx->mounted) {
		R_LOG_ERROR ("Open: filesystem not mounted");
		return NULL;
	}

	if (create) {
		return NULL;
	}

	ut64 ino_num = ubifs_lookup_path (ctx, path);
	if (ino_num == 0) {
		R_LOG_ERROR ("Open: path not found: %s", path);
		return NULL;
	}

	ubifs_inode_t *inode = ubifs_get_inode (ctx, ino_num);
	if (!inode || !inode->ino) {
		R_LOG_ERROR ("Open: cannot get inode %" PFMT64u, ino_num);
		return NULL;
	}

	ut32 mode = r_read_le32 ((ut8 *)&inode->ino->mode);
	ut32 itype = (mode >> 12) & 0xF;

	if (itype != 8) {
		R_LOG_ERROR ("Open: not a regular file (itype=%u, mode=0x%x)", itype, mode);
		return NULL;
	}

	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		R_LOG_ERROR ("Open: r_fs_file_new failed");
		return NULL;
	}

	file->ptr = inode;
	file->size = r_read_le64 ((ut8 *)&inode->ino->size);
	file->type = R_FS_FILE_TYPE_REGULAR;

	if (inode->data_nodes && r_list_length (inode->data_nodes) > 0) {
		ut64 *first_data_off = (ut64 *)r_list_get_n (inode->data_nodes, 0);
		if (first_data_off) {
			// Point to actual data, not header
			file->off = *first_data_off + sizeof (ubifs_data_node_t);
		}
	}

	return file;
}

static int fs_ubifs_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);

	if (!file->ptr) {
		R_LOG_ERROR ("Read: file->ptr is NULL");
		return -1;
	}

	ubifs_inode_t *inode = (ubifs_inode_t *)file->ptr;
	if (!inode->data_nodes) {
		return 0;
	}

	RFSRoot *root = file->root;
	if (!root || !root->ptr) {
		return -1;
	}

	ubifs_ctx_t *ctx = (ubifs_ctx_t *)root->ptr;
	ut64 file_size = r_read_le64 ((ut8 *)&inode->ino->size);

	if (addr >= file_size) {
		return 0;
	}

	if (addr + len > file_size) {
		len = file_size - addr;
	}

	if (file->data) {
		free (file->data);
	}

	ut64 max_fs_size = (ut64)ctx->leb_size * ctx->leb_cnt;
	if (file_size > max_fs_size) {
		R_LOG_ERROR ("File size (%"PFMT64u") exceeds filesystem size (%"PFMT64u")", file_size, max_fs_size);
		return -1;
	}

	file->data = calloc (1, file_size);
	if (!file->data) {
		return -1;
	}

	RListIter *iter;
	ut64 *data_off;
	r_list_foreach (inode->data_nodes, iter, data_off) {
		ut8 hdr_buf[sizeof (ubifs_data_node_t)];
		if (!ubifs_read_at (ctx, *data_off, hdr_buf, sizeof (hdr_buf))) {
			R_LOG_ERROR ("Failed to read data node header");
			continue;
		}

		ubifs_data_node_t *data_node = (ubifs_data_node_t *)hdr_buf;
		ut32 node_len = r_read_le32 ((ut8 *)&data_node->ch.len);
		ut32 uncomp_size = r_read_le32 ((ut8 *)&data_node->size);
		ut16 compr_type = r_read_le16 ((ut8 *)&data_node->compr_type);

		// Compressed data length is the node length minus the header size
		ut32 comp_len = node_len - sizeof (ubifs_data_node_t);

		if (uncomp_size == 0 || uncomp_size > UBIFS_BLOCK_SIZE * 2 || comp_len == 0 || comp_len > UBIFS_BLOCK_SIZE * 2) {
			continue;
		}

		ubifs_key_t key = ubifs_parse_key (data_node->key);
		ut32 block_num = key.khash & UBIFS_S_KEY_BLOCK_MASK;
		ut64 file_offset = (ut64)block_num * UBIFS_BLOCK_SIZE;

		if (file_offset >= file_size) {
			R_LOG_ERROR ("File offset 0x%"PFMT64x" >= file_size %"PFMT64u", skipping", file_offset, file_size);
			continue;
		}

		ut8 *comp_buf = calloc (1, comp_len);
		if (!comp_buf) {
			continue;
		}

		if (!ubifs_read_at (ctx, *data_off + sizeof (ubifs_data_node_t), comp_buf, comp_len)) {
			free (comp_buf);
			continue;
		}

		ut8 *uncomp_buf = NULL;
		ut32 actual_uncomp_size = 0;
		bool need_free = false;

		// Decompress data based on compression type
		if (compr_type == UBIFS_COMPR_NONE) {
			uncomp_buf = comp_buf;
			actual_uncomp_size = comp_len;
		} else if (compr_type == UBIFS_COMPR_ZLIB) {
			// Decompress ZLIB (raw deflate format)
			int src_consumed = 0;
			int dst_len = 0;
			uncomp_buf = r_inflate_raw (comp_buf, comp_len, &src_consumed, &dst_len);
			if (uncomp_buf && dst_len > 0) {
				actual_uncomp_size = dst_len;
				need_free = true;
			} else {
				R_LOG_ERROR ("ZLIB decompression failed");
			}
		} else if (compr_type == UBIFS_COMPR_LZO) {
#ifdef HAVE_LZO
			// UBIFS uses raw LZO without prefix
			// Use the uncompressed size from the data node as the output buffer size
			lzo_uint out_len = (lzo_uint)uncomp_size;

			uncomp_buf = malloc (out_len);
			if (uncomp_buf) {
				int ret = lzo1x_decompress_safe (comp_buf, comp_len, uncomp_buf, &out_len, NULL);
				if (ret == LZO_E_OK) {
					actual_uncomp_size = out_len;
					need_free = true;
				} else {
					R_LOG_ERROR ("LZO decompression failed: %d (in=%u, out_len=%u)",
						ret, comp_len, (ut32)out_len);
					free (uncomp_buf);
					uncomp_buf = NULL;
				}
			}
#else
			R_LOG_ERROR ("LZO compression detected but liblzo2 not available");
#endif
		} else if (compr_type == UBIFS_COMPR_ZSTD) {
			// ZSTD decompression not implemented
			// Files using ZSTD compression cannot be read yet
		}

		if (uncomp_buf && actual_uncomp_size > 0) {
			ut32 copy_size = R_MIN (actual_uncomp_size, file_size - file_offset);
			memcpy (file->data + file_offset, uncomp_buf, copy_size);
		}

		if (need_free && uncomp_buf) {
			free (uncomp_buf);
		}
		free (comp_buf);
	}

	return len;
}

static void fs_ubifs_close(RFSFile *file) {
	R_RETURN_IF_FAIL (file);

	if (file->data) {
		free (file->data);
		file->data = NULL;
	}
}

static void fs_ubifs_details(RFSRoot *root, RStrBuf *sb) {
	R_RETURN_IF_FAIL (root && sb);

	ubifs_ctx_t *ctx = (ubifs_ctx_t *)root->ptr;
	if (!ctx) {
		return;
	}

	const char *compr_name = "Unknown";
	switch (ctx->default_compr) {
	case UBIFS_COMPR_NONE:
		compr_name = "None";
		break;
	case UBIFS_COMPR_LZO:
		compr_name = "LZO";
		break;
	case UBIFS_COMPR_ZLIB:
		compr_name = "ZLIB";
		break;
	case UBIFS_COMPR_ZSTD:
		compr_name = "ZSTD";
		break;
	}

	ut64 total_size = (ut64)ctx->leb_size * ctx->leb_cnt;
	ut64 max_size = (ut64)ctx->leb_size * ctx->max_leb_cnt;

	r_strbuf_append (sb, "Type: UBIFS (Unsorted Block Image File System)\n");
	r_strbuf_appendf (sb, "Block Size (LEB): %u bytes\n", ctx->leb_size);
	r_strbuf_appendf (sb, "Min I/O Size: %u bytes\n", ctx->min_io_size);
	r_strbuf_appendf (sb, "LEB Count: %u\n", ctx->leb_cnt);
	r_strbuf_appendf (sb, "Max LEB Count: %u\n", ctx->max_leb_cnt);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Max Size: %"PFMT64u" bytes (%.2f MB)\n", max_size, (double)max_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Compression: %s\n", compr_name);
	r_strbuf_append (sb, "Purpose: Flash filesystem for embedded devices (MTD/UBI)\n");
}

RFSPlugin r_fs_plugin_ubifs = {
	.meta = {
		.name = "ubifs",
		.desc = "UBIFS (Unsorted Block Images File System)",
		.author = "MiKi (mikelloc)",
		.license = "LGPL-3.0-only",
	},
	.open = fs_ubifs_open,
	.read = fs_ubifs_read,
	.close = fs_ubifs_close,
	.dir = fs_ubifs_dir,
	.mount = fs_ubifs_mount,
	.umount = fs_ubifs_umount,
	.details = fs_ubifs_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_ubifs,
	.version = R2_VERSION
};
#endif
