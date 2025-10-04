/* radare - LGPL - Copyright 2011-2025 pancake, MiKi (mikelloc) */

#include <r_userconf.h>
#include <r_fs.h>

#define FSP(x) fat_##x
#define FSS(x) x##_fat
#define FSNAME "fat"
#define FSDESC "FAT filesystem"
#define FSPRFX fat
#define FSIPTR grub_fat_fs

#if WITH_GPL

R_PACKED(
typedef struct {
	ut8 jmp_boot[3];
	ut8 oem_name[8];
	ut16 bytes_per_sector;
	ut8 sectors_per_cluster;
	ut16 num_reserved_sectors;
	ut8 num_fats;
	ut16 num_root_entries;
	ut16 num_total_sectors_16;
	ut8 media;
	ut16 sectors_per_fat_16;
	ut16 sectors_per_track;
	ut16 num_heads;
	ut32 num_hidden_sectors;
	ut32 num_total_sectors_32;
	union {
		struct {
			ut8 num_ph_drive;
			ut8 reserved;
			ut8 boot_sig;
			ut32 num_serial;
			ut8 label[11];
			ut8 fstype[8];
		} fat12_or_fat16;
		struct {
			ut32 sectors_per_fat_32;
			ut16 extended_flags;
			ut16 fs_version;
			ut32 root_cluster;
			ut16 fs_info;
			ut16 backup_boot_sector;
			ut8 reserved[12];
			ut8 num_ph_drive;
			ut8 reserved1;
			ut8 boot_sig;
			ut32 num_serial;
			ut8 label[11];
			ut8 fstype[8];
		} fat32;
	} version_specific;
}) fat_bpb_t;

static void details_fat(RFSRoot *root, RStrBuf *sb) {
	fat_bpb_t bpb;
	if (!root->iob.read_at (root->iob.io, root->delta, (ut8 *)&bpb, sizeof (bpb))) {
		r_strbuf_append (sb, "ERROR: Could not read boot sector\n");
		return;
	}

	ut16 bytes_per_sector = r_read_le16 ((ut8 *)&bpb.bytes_per_sector);
	ut8 sectors_per_cluster = bpb.sectors_per_cluster;
	ut16 reserved_sectors = r_read_le16 ((ut8 *)&bpb.num_reserved_sectors);
	ut16 root_entries = r_read_le16 ((ut8 *)&bpb.num_root_entries);
	ut32 total_sectors = r_read_le16 ((ut8 *)&bpb.num_total_sectors_16);
	if (total_sectors == 0) {
		total_sectors = r_read_le32 ((ut8 *)&bpb.num_total_sectors_32);
	}

	ut32 sectors_per_fat = r_read_le16 ((ut8 *)&bpb.sectors_per_fat_16);
	bool is_fat32 = false;
	ut32 root_cluster = 0;
	if (sectors_per_fat == 0) {
		sectors_per_fat = r_read_le32 ((ut8 *)&bpb.version_specific.fat32.sectors_per_fat_32);
		root_cluster = r_read_le32 ((ut8 *)&bpb.version_specific.fat32.root_cluster);
		is_fat32 = true;
	}

	ut32 root_dir_sectors = ((root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector;
	ut32 first_data_sector = reserved_sectors + (bpb.num_fats * sectors_per_fat) + root_dir_sectors;
	ut32 data_sectors = total_sectors - first_data_sector;
	ut32 total_clusters = data_sectors / sectors_per_cluster;

	const char *fat_type = "FAT12";
	if (is_fat32) {
		fat_type = "FAT32";
	} else if (total_clusters >= 4085) {
		fat_type = "FAT16";
	}

	char label[12] = {0};
	char fstype[9] = {0};
	char oem[9] = {0};
	ut32 serial = 0;
	ut8 boot_sig = 0;
	ut8 bpb_buf[90];
	int i;

	if (!root->iob.read_at (root->iob.io, root->delta, bpb_buf, sizeof (bpb_buf))) {
		r_strbuf_append (sb, "ERROR: Could not re-read boot sector\n");
		return;
	}

	if (is_fat32) {
		// FAT32: offsets 0x47, 0x47+4, 0x47+4+1, 0x47+4+1+1
		boot_sig = bpb_buf[0x42];
		serial = r_read_le32 (bpb_buf + 0x43);
		memcpy (label, bpb_buf + 0x47, 11);
		memcpy (fstype, bpb_buf + 0x52, 8);
	} else {
		// FAT12/16: offsets 0x26 (boot_sig), 0x27 (serial), 0x2B (label), 0x36 (fstype)
		boot_sig = bpb_buf[0x26];
		serial = r_read_le32 (bpb_buf + 0x27);
		memcpy (label, bpb_buf + 0x2B, 11);
		memcpy (fstype, bpb_buf + 0x36, 8);
	}
	label[11] = 0;
	fstype[8] = 0;

	// Trim trailing spaces and non-printable characters
	for (i = 10; i >= 0 && (label[i] == ' ' || label[i] < 32); i--) {
		label[i] = 0;
	}
	for (i = 7; i >= 0 && (fstype[i] == ' ' || fstype[i] < 32); i--) {
		fstype[i] = 0;
	}

	memcpy (oem, bpb.oem_name, 8);
	oem[8] = 0;
	for (i = 7; i >= 0 && (oem[i] == ' ' || oem[i] < 32); i--) {
		oem[i] = 0;
	}

	ut64 total_size = (ut64)total_sectors * bytes_per_sector;
	ut32 cluster_size = bytes_per_sector * sectors_per_cluster;
	ut64 fat_size = (ut64)sectors_per_fat * bytes_per_sector;

	r_strbuf_appendf (sb, "Filesystem Type: %s\n", fat_type);
	if (*label) {
		r_strbuf_appendf (sb, "Volume Label: %s\n", label);
	}
	if (*oem) {
		r_strbuf_appendf (sb, "OEM Name: %s\n", oem);
	}
	if (boot_sig == 0x29) {
		r_strbuf_appendf (sb, "Serial Number: %08X\n", serial);
	}
	if (*fstype) {
		r_strbuf_appendf (sb, "FS Type String: %s\n", fstype);
	}
	r_strbuf_appendf (sb, "Media Type: 0x%02x\n", bpb.media);
	r_strbuf_appendf (sb, "Bytes per Sector: %u\n", bytes_per_sector);
	r_strbuf_appendf (sb, "Sectors per Cluster: %u\n", sectors_per_cluster);
	r_strbuf_appendf (sb, "Cluster Size: %u bytes\n", cluster_size);
	r_strbuf_appendf (sb, "Reserved Sectors: %u\n", reserved_sectors);
	r_strbuf_appendf (sb, "Number of FATs: %u\n", bpb.num_fats);
	r_strbuf_appendf (sb, "Sectors per FAT: %u\n", sectors_per_fat);
	r_strbuf_appendf (sb, "FAT Size: %"PFMT64u" bytes\n", fat_size);

	if (!is_fat32) {
		r_strbuf_appendf (sb, "Root Directory Entries: %u\n", root_entries);
		r_strbuf_appendf (sb, "Root Directory Sectors: %u\n", root_dir_sectors);
	} else {
		r_strbuf_appendf (sb, "Root Directory Cluster: %u\n", root_cluster);
	}
	r_strbuf_appendf (sb, "Total Sectors: %u\n", total_sectors);
	r_strbuf_appendf (sb, "Data Sectors: %u\n", data_sectors);
	r_strbuf_appendf (sb, "Total Clusters: %u\n", total_clusters);
	r_strbuf_appendf (sb, "First Data Sector: %u\n", first_data_sector);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
}
#define FSDETAILS details_fat
#endif

#include "fs_grub_base.inc.c"
