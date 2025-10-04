/* radare - LGPL - Copyright 2011-2025 pancake, MiKi (mikelloc) */

#include <r_userconf.h>
#include <r_fs.h>

#define FSP(x) iso9660_##x
#define FSS(x) x##_iso9660
#define FSNAME "iso9660"
#define FSDESC "ISO9660 filesystem"
#define FSPRFX iso9660
#define FSIPTR grub_iso9660_fs

#if WITH_GPL

R_PACKED(
typedef struct {
	ut8 type;
	char id[5];
	ut8 version;
	ut8 unused1;
	char system_id[32];
	char volume_id[32];
	ut8 unused2[8];
	ut32 volume_space_size_le;
	ut32 volume_space_size_be;
	ut8 unused3[32];
	ut16 volume_set_size_le;
	ut16 volume_set_size_be;
	ut16 volume_sequence_number_le;
	ut16 volume_sequence_number_be;
	ut16 logical_block_size_le;
	ut16 logical_block_size_be;
	ut32 path_table_size_le;
	ut32 path_table_size_be;
	ut32 type_l_path_table;
	ut32 opt_type_l_path_table;
	ut32 type_m_path_table;
	ut32 opt_type_m_path_table;
	ut8 root_directory_record[34];
	char volume_set_id[128];
	char publisher_id[128];
	char preparer_id[128];
	char application_id[128];
	char copyright_file_id[37];
	char abstract_file_id[37];
	char bibliographic_file_id[37];
	char creation_date[17];
	char modification_date[17];
	char expiration_date[17];
	char effective_date[17];
	ut8 file_structure_version;
	ut8 unused4;
	ut8 application_data[512];
	ut8 reserved[653];
}) iso9660_pvd_t;

static void details_iso9660(RFSRoot *root, RStrBuf *sb) {
	iso9660_pvd_t pvd;
	// Primary Volume Descriptor is at sector 16
	ut64 pvd_offset = root->delta + (16 * 2048);

	if (!root->iob.read_at (root->iob.io, pvd_offset, (ut8 *)&pvd, sizeof (pvd))) {
		r_strbuf_append (sb, "ERROR: Could not read Primary Volume Descriptor\n");
		return;
	}

	if (pvd.type != 1 || memcmp (pvd.id, "CD001", 5) != 0) {
		r_strbuf_append (sb, "ERROR: Invalid Primary Volume Descriptor\n");
		return;
	}

	char volume_id[33] = {0};
	char system_id[33] = {0};
	char publisher_id[129] = {0};
	char preparer_id[129] = {0};
	char application_id[129] = {0};
	char volume_set_id[129] = {0};
	int i;

	memcpy (volume_id, pvd.volume_id, 32);
	memcpy (system_id, pvd.system_id, 32);
	memcpy (publisher_id, pvd.publisher_id, 128);
	memcpy (preparer_id, pvd.preparer_id, 128);
	memcpy (application_id, pvd.application_id, 128);
	memcpy (volume_set_id, pvd.volume_set_id, 128);

	for (i = 31; i >= 0 && volume_id[i] == ' '; i--) {
		volume_id[i] = 0;
	}
	for (i = 31; i >= 0 && system_id[i] == ' '; i--) {
		system_id[i] = 0;
	}
	for (i = 127; i >= 0 && publisher_id[i] == ' '; i--) {
		publisher_id[i] = 0;
	}
	for (i = 127; i >= 0 && preparer_id[i] == ' '; i--) {
		preparer_id[i] = 0;
	}
	for (i = 127; i >= 0 && application_id[i] == ' '; i--) {
		application_id[i] = 0;
	}
	for (i = 127; i >= 0 && volume_set_id[i] == ' '; i--) {
		volume_set_id[i] = 0;
	}

	ut16 logical_block_size = r_read_le16 ((ut8 *)&pvd.logical_block_size_le);
	ut32 volume_space_size = r_read_le32 ((ut8 *)&pvd.volume_space_size_le);
	ut16 volume_set_size = r_read_le16 ((ut8 *)&pvd.volume_set_size_le);
	ut16 volume_sequence_number = r_read_le16 ((ut8 *)&pvd.volume_sequence_number_le);
	ut32 path_table_size = r_read_le32 ((ut8 *)&pvd.path_table_size_le);

	ut64 total_size = (ut64)volume_space_size * logical_block_size;

	r_strbuf_append (sb, "Filesystem Type: ISO9660\n");
	if (*volume_id) {
		r_strbuf_appendf (sb, "Volume ID: %s\n", volume_id);
	}
	if (*system_id) {
		r_strbuf_appendf (sb, "System ID: %s\n", system_id);
	}
	if (*volume_set_id) {
		r_strbuf_appendf (sb, "Volume Set ID: %s\n", volume_set_id);
	}
	if (*publisher_id) {
		r_strbuf_appendf (sb, "Publisher: %s\n", publisher_id);
	}
	if (*preparer_id) {
		r_strbuf_appendf (sb, "Preparer: %s\n", preparer_id);
	}
	if (*application_id) {
		r_strbuf_appendf (sb, "Application: %s\n", application_id);
	}

	// Parse ISO9660 timestamp format: YYYYMMDDHHMMSSmmz (mm = centiseconds, z = timezone offset)
	char creation_date[18] = {0};
	memcpy (creation_date, pvd.creation_date, 17);
	if (creation_date[0] != '0' && creation_date[0] != ' ' && creation_date[0] >= '1' && creation_date[0] <= '9') {
		char year[5] = {0}, month[3] = {0}, day[3] = {0};
		char hour[3] = {0}, minute[3] = {0}, second[3] = {0}, centisec[3] = {0};
		memcpy (year, creation_date, 4);
		memcpy (month, creation_date + 4, 2);
		memcpy (day, creation_date + 6, 2);
		memcpy (hour, creation_date + 8, 2);
		memcpy (minute, creation_date + 10, 2);
		memcpy (second, creation_date + 12, 2);
		memcpy (centisec, creation_date + 14, 2);
		r_strbuf_appendf (sb, "Creation Date: %s-%s-%s %s:%s:%s.%s\n",
			year, month, day, hour, minute, second, centisec);
	}

	r_strbuf_appendf (sb, "Logical Block Size: %u bytes\n", logical_block_size);
	r_strbuf_appendf (sb, "Volume Space Size: %u blocks\n", volume_space_size);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", total_size, (double)total_size / (1024.0 * 1024.0));
	r_strbuf_appendf (sb, "Path Table Size: %u bytes\n", path_table_size);
	r_strbuf_appendf (sb, "Volume Set Size: %u\n", volume_set_size);
	r_strbuf_appendf (sb, "Volume Sequence Number: %u\n", volume_sequence_number);
	r_strbuf_appendf (sb, "File Structure Version: %u\n", pvd.file_structure_version);
}
#define FSDETAILS details_iso9660
#endif

#include "fs_grub_base.inc.c"
