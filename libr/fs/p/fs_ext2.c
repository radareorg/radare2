/* radare - LGPL - Copyright 2011-2025 pancake, MiKi (mikelloc) */

#include <r_userconf.h>
#include <r_fs.h>

#define FSP(x) ext2_##x
#define FSS(x) x##_ext2
#define FSNAME "ext2"
#define FSDESC "ext2 filesystem"
#define FSPRFX ext2
#define FSIPTR grub_ext2_fs

#if WITH_GPL

R_PACKED(
typedef struct {
	ut32 s_inodes_count;
	ut32 s_blocks_count;
	ut32 s_r_blocks_count;
	ut32 s_free_blocks_count;
	ut32 s_free_inodes_count;
	ut32 s_first_data_block;
	ut32 s_log_block_size;
	ut32 s_log_frag_size;
	ut32 s_blocks_per_group;
	ut32 s_frags_per_group;
	ut32 s_inodes_per_group;
	ut32 s_mtime;
	ut32 s_wtime;
	ut16 s_mnt_count;
	ut16 s_max_mnt_count;
	ut16 s_magic;
	ut16 s_state;
	ut16 s_errors;
	ut16 s_minor_rev_level;
	ut32 s_lastcheck;
	ut32 s_checkinterval;
	ut32 s_creator_os;
	ut32 s_rev_level;
	ut16 s_def_resuid;
	ut16 s_def_resgid;
	ut32 s_first_ino;
	ut16 s_inode_size;
	ut16 s_block_group_nr;
	ut32 s_feature_compat;
	ut32 s_feature_incompat;
	ut32 s_feature_ro_compat;
	ut8  s_uuid[16];
	char s_volume_name[16];
	char s_last_mounted[64];
	ut32 s_algorithm_usage_bitmap;
	ut8  s_prealloc_blocks;
	ut8  s_prealloc_dir_blocks;
	ut16 s_reserved_gdt_blocks;
	ut8  s_journal_uuid[16];
	ut32 s_journal_inum;
	ut32 s_journal_dev;
	ut32 s_last_orphan;
}) ext2_superblock_t;

static void details_ext2(RFSRoot *root, RStrBuf *sb) {
	ext2_superblock_t super;
	// Superblock is at offset 1024
	ut64 sb_offset = root->delta + 1024;

	if (!root->iob.read_at (root->iob.io, sb_offset, (ut8 *)&super, sizeof (super))) {
		r_strbuf_append (sb, "ERROR: Could not read ext2/3/4 superblock\n");
		return;
	}

	ut16 magic = r_read_le16 ((ut8 *)&super.s_magic);
	if (magic != 0xEF53) {
		r_strbuf_append (sb, "ERROR: Invalid ext2/3/4 magic number\n");
		return;
	}

	ut32 feature_incompat = r_read_le32 ((ut8 *)&super.s_feature_incompat);
	const char *fs_type = "ext2";
	if (feature_incompat & 0x0004) { // EXT3_FEATURE_INCOMPAT_RECOVER
		fs_type = "ext3";
	}
	if (feature_incompat & 0x0040) { // EXT4_FEATURE_INCOMPAT_EXTENTS
		fs_type = "ext4";
	}

	ut32 inodes_count = r_read_le32 ((ut8 *)&super.s_inodes_count);
	ut32 blocks_count = r_read_le32 ((ut8 *)&super.s_blocks_count);
	ut32 r_blocks_count = r_read_le32 ((ut8 *)&super.s_r_blocks_count);
	ut32 free_blocks_count = r_read_le32 ((ut8 *)&super.s_free_blocks_count);
	ut32 free_inodes_count = r_read_le32 ((ut8 *)&super.s_free_inodes_count);
	ut32 log_block_size = r_read_le32 ((ut8 *)&super.s_log_block_size);
	ut32 blocks_per_group = r_read_le32 ((ut8 *)&super.s_blocks_per_group);
	ut32 inodes_per_group = r_read_le32 ((ut8 *)&super.s_inodes_per_group);
	ut32 mtime = r_read_le32 ((ut8 *)&super.s_mtime);
	ut32 wtime = r_read_le32 ((ut8 *)&super.s_wtime);
	ut32 lastcheck = r_read_le32 ((ut8 *)&super.s_lastcheck);
	ut16 mnt_count = r_read_le16 ((ut8 *)&super.s_mnt_count);
	ut16 max_mnt_count = r_read_le16 ((ut8 *)&super.s_max_mnt_count);
	ut16 state = r_read_le16 ((ut8 *)&super.s_state);
	ut32 rev_level = r_read_le32 ((ut8 *)&super.s_rev_level);
	ut32 creator_os = r_read_le32 ((ut8 *)&super.s_creator_os);
	ut32 feature_compat = r_read_le32 ((ut8 *)&super.s_feature_compat);
	ut32 feature_ro_compat = r_read_le32 ((ut8 *)&super.s_feature_ro_compat);

	ut32 block_size = 1024 << log_block_size;
	ut64 total_size = (ut64)blocks_count * block_size;
	ut64 used_size = (ut64)(blocks_count - free_blocks_count) * block_size;
	ut64 free_size = (ut64)free_blocks_count * block_size;
	ut64 reserved_size = (ut64)r_blocks_count * block_size;

	char volume_name[17] = {0};
	char last_mounted[65] = {0};
	int i;
	memcpy (volume_name, super.s_volume_name, 16);
	volume_name[16] = 0;
	for (i = 15; i >= 0 && volume_name[i] == ' '; i--) {
		volume_name[i] = 0;
	}

	memcpy (last_mounted, super.s_last_mounted, 64);
	last_mounted[64] = 0;

	r_strbuf_appendf (sb, "Filesystem Type: %s\n", fs_type);
	if (*volume_name) {
		r_strbuf_appendf (sb, "Volume Name: %s\n", volume_name);
	}

	r_strbuf_append (sb, "UUID: ");
	for (i = 0; i < 16; i++) {
		r_strbuf_appendf (sb, "%02x", super.s_uuid[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9) {
			r_strbuf_append (sb, "-");
		}
	}
	r_strbuf_append (sb, "\n");

	if (*last_mounted) {
		r_strbuf_appendf (sb, "Last Mounted: %s\n", last_mounted);
	}

	if (mtime) {
		time_t t = (time_t)mtime;
		struct tm *tm = gmtime (&t);
		if (tm) {
			r_strbuf_appendf (sb, "Last Mount Time: %04d-%02d-%02d %02d:%02d:%02d\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}
	if (wtime) {
		time_t t = (time_t)wtime;
		struct tm *tm = gmtime (&t);
		if (tm) {
			r_strbuf_appendf (sb, "Last Write Time: %04d-%02d-%02d %02d:%02d:%02d\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}
	if (lastcheck) {
		time_t t = (time_t)lastcheck;
		struct tm *tm = gmtime (&t);
		if (tm) {
			r_strbuf_appendf (sb, "Last Check Time: %04d-%02d-%02d %02d:%02d:%02d\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}

	r_strbuf_appendf (sb, "Block Size: %u bytes\n", block_size);
	r_strbuf_appendf (sb, "Total Blocks: %u\n", blocks_count);
	r_strbuf_appendf (sb, "Free Blocks: %u\n", free_blocks_count);
	r_strbuf_appendf (sb, "Reserved Blocks: %u\n", r_blocks_count);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Used Size: %"PFMT64u" bytes (%.2f MB)\n", used_size, (double)used_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Free Size: %"PFMT64u" bytes (%.2f MB)\n", free_size, (double)free_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Reserved Size: %"PFMT64u" bytes (%.2f MB)\n", reserved_size, (double)reserved_size / (1024.0 * 1024.0));

	r_strbuf_appendf (sb, "Inodes Count: %u\n", inodes_count);
	r_strbuf_appendf (sb, "Free Inodes: %u\n", free_inodes_count);
	r_strbuf_appendf (sb, "Inodes per Group: %u\n", inodes_per_group);
	r_strbuf_appendf (sb, "Blocks per Group: %u\n", blocks_per_group);

	if (rev_level >= 1) {
		ut16 inode_size = r_read_le16 ((ut8 *)&super.s_inode_size);
		r_strbuf_appendf (sb, "Inode Size: %u bytes\n", inode_size);
	}

	const char *state_str = "unknown";
	if (state == 1) state_str = "cleanly unmounted";
	else if (state == 2) state_str = "errors detected";
	else if (state == 4) state_str = "orphans being recovered";
	r_strbuf_appendf (sb, "Filesystem State: %s\n", state_str);

	r_strbuf_appendf (sb, "Mount Count: %u\n", mnt_count);
	r_strbuf_appendf (sb, "Max Mount Count: %d\n", (st16)max_mnt_count);

	const char *os_str = "unknown";
	if (creator_os == 0) os_str = "Linux";
	else if (creator_os == 1) os_str = "Hurd";
	else if (creator_os == 2) os_str = "Masix";
	else if (creator_os == 3) os_str = "FreeBSD";
	else if (creator_os == 4) os_str = "Lites";
	r_strbuf_appendf (sb, "Creator OS: %s\n", os_str);

	r_strbuf_appendf (sb, "Revision Level: %u\n", rev_level);

	// Feature flags
	if (feature_compat) {
		r_strbuf_append (sb, "Compatible Features:");
		if (feature_compat & 0x0001) r_strbuf_append (sb, " DIR_PREALLOC");
		if (feature_compat & 0x0002) r_strbuf_append (sb, " IMAGIC_INODES");
		if (feature_compat & 0x0004) r_strbuf_append (sb, " HAS_JOURNAL");
		if (feature_compat & 0x0008) r_strbuf_append (sb, " EXT_ATTR");
		if (feature_compat & 0x0010) r_strbuf_append (sb, " RESIZE_INODE");
		if (feature_compat & 0x0020) r_strbuf_append (sb, " DIR_INDEX");
		r_strbuf_append (sb, "\n");
	}

	if (feature_incompat) {
		r_strbuf_append (sb, "Incompatible Features:");
		if (feature_incompat & 0x0001) r_strbuf_append (sb, " COMPRESSION");
		if (feature_incompat & 0x0002) r_strbuf_append (sb, " FILETYPE");
		if (feature_incompat & 0x0004) r_strbuf_append (sb, " RECOVER");
		if (feature_incompat & 0x0008) r_strbuf_append (sb, " JOURNAL_DEV");
		if (feature_incompat & 0x0010) r_strbuf_append (sb, " META_BG");
		if (feature_incompat & 0x0040) r_strbuf_append (sb, " EXTENTS");
		if (feature_incompat & 0x0080) r_strbuf_append (sb, " 64BIT");
		if (feature_incompat & 0x0100) r_strbuf_append (sb, " MMP");
		if (feature_incompat & 0x0200) r_strbuf_append (sb, " FLEX_BG");
		r_strbuf_append (sb, "\n");
	}

	if (feature_ro_compat) {
		r_strbuf_append (sb, "Read-Only Compatible Features:");
		if (feature_ro_compat & 0x0001) r_strbuf_append (sb, " SPARSE_SUPER");
		if (feature_ro_compat & 0x0002) r_strbuf_append (sb, " LARGE_FILE");
		if (feature_ro_compat & 0x0004) r_strbuf_append (sb, " BTREE_DIR");
		if (feature_ro_compat & 0x0008) r_strbuf_append (sb, " HUGE_FILE");
		if (feature_ro_compat & 0x0010) r_strbuf_append (sb, " GDT_CSUM");
		if (feature_ro_compat & 0x0020) r_strbuf_append (sb, " DIR_NLINK");
		if (feature_ro_compat & 0x0040) r_strbuf_append (sb, " EXTRA_ISIZE");
		r_strbuf_append (sb, "\n");
	}
}
#define FSDETAILS details_ext2
#endif

#include "fs_grub_base.inc.c"
