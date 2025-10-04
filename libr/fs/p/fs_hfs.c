/* radare - LGPL - Copyright 2011-2025 pancake, MiKi (mikelloc) */

#include <r_userconf.h>
#include <r_fs.h>

#define FSP(x) grub_hfs##x
#define FSS(x) x##_hfs
#define FSNAME "hfs"
#define FSDESC "HFS filesystem"
#define FSPRFX hfs
#define FSIPTR grub_hfs_fs

#if WITH_GPL

R_PACKED(
typedef struct {
	ut16 signature;
	ut32 create_date;
	ut32 modify_date;
	ut16 attributes;
	ut16 root_file_count;
	ut16 volume_bitmap_block;
	ut16 alloc_block_start;
	ut16 total_blocks;
	ut32 block_size;
	ut32 clump_size;
	ut16 first_alloc_block;
	ut32 next_cnid;
	ut16 free_blocks;
	ut8 volume_name_length;
	char volume_name[27];
	ut32 backup_date;
	ut16 backup_seq_num;
	ut32 write_count;
	ut32 extents_clump_size;
	ut32 catalog_clump_size;
	ut16 root_dir_count;
	ut32 file_count;
	ut32 dir_count;
	ut32 finder_info[8];
	ut16 embed_sig;
	ut16 embed_extent_block;
	ut16 embed_extent_count;
	ut32 extents_size;
	ut32 extents_first_blocks[3];
	ut32 catalog_size;
	ut32 catalog_first_blocks[3];
}) hfs_mdb_t;

static void details_hfs(RFSRoot *root, RStrBuf *sb) {
	hfs_mdb_t mdb;
	// MDB is at offset 1024 from the start
	ut64 mdb_offset = root->delta + 1024;

	if (!root->iob.read_at (root->iob.io, mdb_offset, (ut8 *)&mdb, sizeof (mdb))) {
		r_strbuf_append (sb, "ERROR: Could not read HFS Master Directory Block\n");
		return;
	}

	ut16 signature = r_read_be16 ((ut8 *)&mdb.signature);
	// Check for HFS signature (0x4244 = "BD")
	if (signature != 0x4244) {
		r_strbuf_append (sb, "ERROR: Invalid HFS signature\n");
		return;
	}

	char volume_name[28] = {0};
	ut8 name_len = mdb.volume_name_length;
	if (name_len > 27) {
		name_len = 27;
	}
	memcpy (volume_name, mdb.volume_name, name_len);
	volume_name[name_len] = 0;

	ut16 total_blocks = r_read_be16 ((ut8 *)&mdb.total_blocks);
	ut32 block_size = r_read_be32 ((ut8 *)&mdb.block_size);
	ut16 free_blocks = r_read_be16 ((ut8 *)&mdb.free_blocks);
	ut32 file_count = r_read_be32 ((ut8 *)&mdb.file_count);
	ut32 dir_count = r_read_be32 ((ut8 *)&mdb.dir_count);
	ut32 create_date = r_read_be32 ((ut8 *)&mdb.create_date);
	ut32 modify_date = r_read_be32 ((ut8 *)&mdb.modify_date);
	ut32 backup_date = r_read_be32 ((ut8 *)&mdb.backup_date);

	ut64 total_size = (ut64)total_blocks * block_size;
	ut64 used_size = (ut64)(total_blocks - free_blocks) * block_size;
	ut64 free_size = (ut64)free_blocks * block_size;

	r_strbuf_append (sb, "Filesystem Type: HFS\n");
	if (*volume_name) {
		r_strbuf_appendf (sb, "Volume Name: %s\n", volume_name);
	}

	// HFS uses Mac epoch (January 1, 1904) - convert to Unix epoch
	// Mac epoch is 2082844800 seconds before Unix epoch (Jan 1, 1970)
	const ut64 mac_epoch_offset = 2082844800ULL;

	if (create_date) {
		time_t unix_time = (time_t)(create_date - mac_epoch_offset);
		struct tm *tm = gmtime (&unix_time);
		if (tm) {
			r_strbuf_appendf (sb, "Create Date: %04d-%02d-%02d %02d:%02d:%02d (HFS timestamp: %u)\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, create_date);
		}
	}
	if (modify_date) {
		time_t unix_time = (time_t)(modify_date - mac_epoch_offset);
		struct tm *tm = gmtime (&unix_time);
		if (tm) {
			r_strbuf_appendf (sb, "Modify Date: %04d-%02d-%02d %02d:%02d:%02d (HFS timestamp: %u)\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, modify_date);
		}
	}
	if (backup_date) {
		time_t unix_time = (time_t)(backup_date - mac_epoch_offset);
		struct tm *tm = gmtime (&unix_time);
		if (tm) {
			r_strbuf_appendf (sb, "Backup Date: %04d-%02d-%02d %02d:%02d:%02d (HFS: %u)\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, backup_date);
		}
	}

	r_strbuf_appendf (sb, "Block Size: %u bytes\n", block_size);
	r_strbuf_appendf (sb, "Total Blocks: %u\n", total_blocks);
	r_strbuf_appendf (sb, "Free Blocks: %u\n", free_blocks);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Used Size: %"PFMT64u" bytes (%.2f MB)\n", used_size, (double)used_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Free Size: %"PFMT64u" bytes (%.2f MB)\n", free_size, (double)free_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "File Count: %u\n", file_count);
	r_strbuf_appendf (sb, "Directory Count: %u\n", dir_count);

	ut32 clump_size = r_read_be32 ((ut8 *)&mdb.clump_size);
	ut32 catalog_clump_size = r_read_be32 ((ut8 *)&mdb.catalog_clump_size);
	ut32 extents_clump_size = r_read_be32 ((ut8 *)&mdb.extents_clump_size);

	r_strbuf_appendf (sb, "Allocation Clump Size: %u bytes\n", clump_size);
	r_strbuf_appendf (sb, "Catalog Clump Size: %u bytes\n", catalog_clump_size);
	r_strbuf_appendf (sb, "Extents Clump Size: %u bytes\n", extents_clump_size);
}
#define FSDETAILS details_hfs
#endif

#include "fs_grub_base.inc.c"
