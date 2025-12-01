/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>
#include <r_types.h>

#define GPT_SIGNATURE "EFI PART"
#define GPT_SIGNATURE_LEN 8

R_PACKED(
	typedef struct {
		ut8 signature[8];
		ut32 revision;
		ut32 header_size;
		ut32 crc32;
		ut32 reserved;
		ut64 current_lba;
		ut64 backup_lba;
		ut64 first_usable_lba;
		ut64 last_usable_lba;
		ut8 disk_guid[16];
		ut64 partition_entries_lba;
		ut32 num_partition_entries;
		ut32 partition_entry_size;
		ut32 partition_entries_crc32;
	})
GPTHeader;

R_PACKED(
	typedef struct {
		ut8 type_guid[16];
		ut8 unique_guid[16];
		ut64 first_lba;
		ut64 last_lba;
		ut64 attributes;
		ut16 name[36]; // UTF-16
	})
GPTEntry;

static int fs_part_gpt(void *disk, void *ptr, void *closure) {
	GPTHeader header;
	RFS *fs = (RFS *)disk;
	RFSPartition *par = NULL;
	RFSPartitionIterator iterate = (RFSPartitionIterator)ptr;
	RList *list = (RList *)closure;

	// Read GPT header at LBA 1
	fs->iob.read_at (fs->iob.io, 512, (ut8 *)&header, sizeof (header));
	if (memcmp (header.signature, GPT_SIGNATURE, GPT_SIGNATURE_LEN) != 0) {
		R_LOG_ERROR ("Invalid GPT signature");
		return 0;
	}

	ut64 entries_lba = header.partition_entries_lba * 512;
	ut32 num_entries = header.num_partition_entries;
	ut32 entry_size = header.partition_entry_size;

	if (entry_size != 128) {
		R_LOG_ERROR ("Unsupported partition entry size: %u", entry_size);
		return 0;
	}

	// Bounds checking for num_entries and multiplication overflow
	if (num_entries == 0 || num_entries > 1024) {
		R_LOG_ERROR ("Invalid number of partition entries: %u", num_entries);
		return 0;
	}
	if (entry_size == 0 || entry_size > 4096) {
		R_LOG_ERROR ("Invalid partition entry size: %u", entry_size);
		return 0;
	}
	if ((size_t)entry_size > SIZE_MAX / (size_t)num_entries) {
		R_LOG_ERROR ("Partition entries allocation size overflow");
		return 0;
	}
	size_t alloc_size = (size_t)num_entries * (size_t)entry_size;
	if (alloc_size > (4 * 1024 * 1024)) { // 4MB sanity check
		R_LOG_ERROR ("Partition entries allocation size too large: %zu", alloc_size);
		return 0;
	}
	ut8 *entries = malloc (alloc_size);
	if (!entries) {
		return 0;
	}
	fs->iob.read_at (fs->iob.io, entries_lba, entries, num_entries * entry_size);

	int i;
	for (i = 0; i < num_entries; i++) {
		GPTEntry *e = (GPTEntry *)&entries[i * entry_size];
		// Check if type_guid is not all zeros
		bool is_empty = true;
		int j;
		for (j = 0; j < 16; j++) {
			if (e->type_guid[j] != 0) {
				is_empty = false;
				break;
			}
		}
		if (!is_empty) {
			ut64 start = e->first_lba * 512;
			ut64 length = (e->last_lba - e->first_lba + 1) * 512;
			par = r_fs_partition_new (i, start, length);
			par->type = 0; // GPT doesn't have byte type, maybe use index or something
			iterate (disk, par, list);
		}
	}

	free (entries);
	return 0;
}
