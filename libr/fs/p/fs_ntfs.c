/* radare - LGPL - Copyright 2011-2025 pancake, MiKi (mikelloc) */

#include <r_userconf.h>
#include <r_fs.h>

#define FSP(x) ntfs_##x
#define FSS(x) x##_ntfs
#define FSNAME "ntfs"
#define FSDESC "NTFS filesystem"
#define FSPRFX ntfs
#define FSIPTR grub_ntfs_fs

#if WITH_GPL

R_PACKED(
typedef struct {
	ut8 jump[3];
	char oem_id[8];
	ut16 bytes_per_sector;
	ut8 sectors_per_cluster;
	ut16 reserved_sectors;
	ut8 unused1[3];
	ut16 unused2;
	ut8 media_descriptor;
	ut16 unused3;
	ut16 sectors_per_track;
	ut16 num_heads;
	ut32 hidden_sectors;
	ut32 unused4;
	ut32 unused5;
	ut64 total_sectors;
	ut64 mft_cluster;
	ut64 mft_mirror_cluster;
	st8 clusters_per_mft_record;
	ut8 unused6[3];
	st8 clusters_per_index_block;
	ut8 unused7[3];
	ut64 volume_serial;
	ut32 checksum;
}) ntfs_bpb_t;

R_PACKED(
typedef struct {
	char signature[4];           // "FILE"
	ut16 update_seq_offset;
	ut16 update_seq_size;
	ut64 logfile_seq_number;
	ut16 sequence_number;
	ut16 hard_link_count;
	ut16 first_attr_offset;
	ut16 flags;
	ut32 used_size;
	ut32 allocated_size;
	ut64 base_record;
	ut16 next_attr_id;
}) ntfs_mft_record_t;

R_PACKED(
typedef struct {
	ut32 type;
	ut32 length;
	ut8 non_resident;
	ut8 name_length;
	ut16 name_offset;
	ut16 flags;
	ut16 id;
	ut32 value_length;
	ut16 value_offset;
}) ntfs_attr_header_t;

R_PACKED(
typedef struct {
	ut64 creation_time;
	ut64 modification_time;
	ut64 mft_modification_time;
	ut64 access_time;
	ut32 file_attributes;
}) ntfs_std_info_t;

// Convert NTFS FILETIME (100-nanosecond intervals since 1601-01-01) to Unix time
static time_t ntfs_filetime_to_unix(ut64 filetime) {
	// NTFS epoch (1601-01-01) to Unix epoch (1970-01-01) is 11644473600 seconds
	const ut64 ntfs_epoch_offset = 11644473600ULL;
	ut64 seconds = filetime / 10000000ULL;
	if (seconds < ntfs_epoch_offset) {
		return 0;
	}
	return (time_t)(seconds - ntfs_epoch_offset);
}

static void details_ntfs(RFSRoot *root, RStrBuf *sb) {
	ntfs_bpb_t bpb;
	if (!root->iob.read_at (root->iob.io, root->delta, (ut8 *)&bpb, sizeof (bpb))) {
		r_strbuf_append (sb, "ERROR: Could not read NTFS boot sector\n");
		return;
	}

	char oem_id[9] = {0};
	int i;
	memcpy (oem_id, bpb.oem_id, 8);
	if (memcmp (oem_id, "NTFS    ", 8) != 0) {
		r_strbuf_append (sb, "ERROR: Invalid NTFS signature\n");
		return;
	}
	// Trim trailing spaces and non-printable characters
	for (i = 7; i >= 0 && (oem_id[i] == ' ' || oem_id[i] < 32); i--) {
		oem_id[i] = 0;
	}

	ut16 bytes_per_sector = r_read_le16 ((ut8 *)&bpb.bytes_per_sector);
	ut8 sectors_per_cluster = bpb.sectors_per_cluster;
	ut64 total_sectors = r_read_le64 ((ut8 *)&bpb.total_sectors);
	ut64 mft_cluster = r_read_le64 ((ut8 *)&bpb.mft_cluster);
	ut64 mft_mirror_cluster = r_read_le64 ((ut8 *)&bpb.mft_mirror_cluster);
	ut64 volume_serial = r_read_le64 ((ut8 *)&bpb.volume_serial);

	ut32 cluster_size = bytes_per_sector * sectors_per_cluster;
	ut64 total_size = total_sectors * bytes_per_sector;
	ut64 mft_offset = root->delta + (mft_cluster * cluster_size);

	st8 clusters_per_mft = bpb.clusters_per_mft_record;
	ut32 mft_record_size;
	if (clusters_per_mft > 0) {
		mft_record_size = clusters_per_mft * cluster_size;
	} else {
		mft_record_size = 1 << (-clusters_per_mft);
	}

	st8 clusters_per_index = bpb.clusters_per_index_block;
	ut32 index_block_size;
	if (clusters_per_index > 0) {
		index_block_size = clusters_per_index * cluster_size;
	} else {
		index_block_size = 1 << (-clusters_per_index);
	}

	char volume_label[256] = {0};
	ut64 creation_time = 0;
	ut64 modification_time = 0;

	if (mft_record_size == 0 || mft_record_size > 65536) {
		goto print_info;
	}

	ut8 *mft_record = calloc(1, mft_record_size);
	if (mft_record) {
		ut64 volume_mft_offset = mft_offset + (3 * mft_record_size);
		if (root->iob.read_at (root->iob.io, volume_mft_offset, mft_record, mft_record_size)) {
			ntfs_mft_record_t *mft = (ntfs_mft_record_t *)mft_record;

			if (memcmp (mft->signature, "FILE", 4) == 0) {
				ut16 attr_offset = r_read_le16 ((ut8 *)&mft->first_attr_offset);

				while (attr_offset < mft_record_size - sizeof (ntfs_attr_header_t)) {
					ntfs_attr_header_t *attr = (ntfs_attr_header_t *)(mft_record + attr_offset);
					ut32 attr_type = r_read_le32 ((ut8 *)&attr->type);
					ut32 attr_length = r_read_le32 ((ut8 *)&attr->length);

					if (attr_type == 0xFFFFFFFF || attr_length == 0 || attr_length > mft_record_size) {
						break;
					}

					// 0x10 = $STANDARD_INFORMATION
					if (attr_type == 0x10 && !attr->non_resident) {
						ut16 value_offset = r_read_le16 ((ut8 *)&attr->value_offset);
						ntfs_std_info_t *std_info = (ntfs_std_info_t *)(mft_record + attr_offset + value_offset);
						creation_time = r_read_le64 ((ut8 *)&std_info->creation_time);
						modification_time = r_read_le64 ((ut8 *)&std_info->modification_time);
					}

					// 0x60 = $VOLUME_NAME
					if (attr_type == 0x60 && !attr->non_resident) {
						ut32 value_length = r_read_le32 ((ut8 *)&attr->value_length);
						ut16 value_offset = r_read_le16 ((ut8 *)&attr->value_offset);

						if (value_length > 0 && value_length < 512) {
							// Volume name is in UTF-16LE, simple conversion to ASCII
							// Better conversion needed for non ASCII characters
							ut8 *name_utf16 = mft_record + attr_offset + value_offset;
							int name_chars = value_length / 2;
							int j;
							if (name_chars > 127) {
								name_chars = 127;
							}
							for (j = 0; j < name_chars; j++) {
								ut16 c = r_read_le16(name_utf16 + (j * 2));
								volume_label[j] = (c < 128) ? (char)c : '?';
							}
							volume_label[name_chars] = 0;
						}
					}

					attr_offset += attr_length;
				}
			}
		}
		free (mft_record);
	}

print_info:
	r_strbuf_append (sb, "Filesystem Type: NTFS\n");
	r_strbuf_appendf (sb, "OEM ID: %s\n", oem_id);

	if (*volume_label) {
		r_strbuf_appendf (sb, "Volume Label: %s\n", volume_label);
	}

	r_strbuf_appendf (sb, "Volume Serial Number: %016"PFMT64x"\n", volume_serial);

	if (creation_time) {
		time_t t = ntfs_filetime_to_unix(creation_time);
		struct tm *tm = gmtime(&t);
		if (tm) {
			r_strbuf_appendf (sb, "Volume Creation Time: %04d-%02d-%02d %02d:%02d:%02d\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}
	if (modification_time) {
		time_t t = ntfs_filetime_to_unix(modification_time);
		struct tm *tm = gmtime(&t);
		if (tm) {
			r_strbuf_appendf (sb, "Volume Modification Time: %04d-%02d-%02d %02d:%02d:%02d\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}

	r_strbuf_appendf (sb, "Bytes per Sector: %u\n", bytes_per_sector);
	r_strbuf_appendf (sb, "Sectors per Cluster: %u\n", sectors_per_cluster);
	r_strbuf_appendf (sb, "Cluster Size: %u bytes\n", cluster_size);
	r_strbuf_appendf (sb, "Total Sectors: %"PFMT64u"\n", total_sectors);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "MFT Cluster: %"PFMT64u"\n", mft_cluster);
	r_strbuf_appendf (sb, "MFT Offset: 0x%"PFMT64x"\n", mft_offset - root->delta);
	r_strbuf_appendf (sb, "MFT Mirror Cluster: %"PFMT64u"\n", mft_mirror_cluster);
	r_strbuf_appendf (sb, "MFT Record Size: %u bytes\n", mft_record_size);
	r_strbuf_appendf (sb, "Index Block Size: %u bytes\n", index_block_size);
	r_strbuf_appendf (sb, "Media Descriptor: 0x%02x\n", bpb.media_descriptor);
}
#define FSDETAILS details_ntfs
#endif

#include "fs_grub_base.inc.c"
