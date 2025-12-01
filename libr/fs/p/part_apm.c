/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>
#include <r_types.h>

#define APM_SIGNATURE "PM"
#define APM_SIGNATURE_LEN 2

R_PACKED(
	typedef struct {
		ut8 signature[2]; // "PM"
		ut8 reserved_1[2];
		ut32 number_of_partitions;
		ut32 partition_start; // First sector
		ut32 partition_size; // Number of sectors
		char partition_name[32];
		char partition_type[32];
		ut32 data_start; // First sector
		ut32 data_size; // Number of sectors
		ut32 partition_status;
		ut32 boot_code_start; // First sector
		ut32 boot_code_size; // Number of bytes
		ut32 boot_loader_address;
		ut8 reserved_2[4];
		ut32 boot_code_entry;
		ut8 reserved_3[4];
		ut32 boot_code_cksum;
		char processor_type[16];
		// Rest of sector should be 0x00
	})
APMEntry;

static int fs_part_apm(void *disk, void *ptr, void *closure) {
	RFS *fs = (RFS *)disk;
	RFSPartition *par = NULL;
	RFSPartitionIterator iterate = (RFSPartitionIterator)ptr;
	RList *list = (RList *)closure;

	// Read first APM entry at sector 1 to get number of partitions
	APMEntry first_entry;
	if (!fs->iob.read_at (fs->iob.io, 512, (ut8 *)&first_entry, sizeof (first_entry))) {
		R_LOG_ERROR ("Failed to read APM entry");
		return 0;
	}

	if (memcmp (first_entry.signature, APM_SIGNATURE, APM_SIGNATURE_LEN) != 0) {
		R_LOG_ERROR ("Invalid APM signature");
		return 0;
	}

	ut32 num_partitions = r_read_be32 ((ut8 *)&first_entry.number_of_partitions);
	if (num_partitions == 0 || num_partitions > 1024) {
		R_LOG_ERROR ("Invalid number of APM partitions: %u", num_partitions);
		return 0;
	}

	// Allocate memory for all partition entries
	size_t alloc_size = (size_t)num_partitions * 512;
	if (alloc_size > (4 * 1024 * 1024)) { // 4MB sanity check
		R_LOG_ERROR ("APM partition entries allocation size too large: %zu", alloc_size);
		return 0;
	}
	APMEntry *entries = malloc (alloc_size);
	if (!entries) {
		R_LOG_ERROR ("Failed to allocate memory for APM partition entries");
		return 0;
	}

	// Read all partition entries starting from sector 1
	bool success = fs->iob.read_at (fs->iob.io, 512, (ut8 *)entries, alloc_size);
	int bytes_read = (int) (success ? alloc_size : -1);
	if (bytes_read < 0 || (size_t)bytes_read != alloc_size) {
		R_LOG_ERROR ("Failed to read APM partition entries: expected %zu bytes, got %zd", alloc_size, bytes_read);
		free (entries);
		return 0;
	}

	int i;
	for (i = 0; i < num_partitions; i++) {
		APMEntry *e = (APMEntry *)((ut8 *)entries + i * 512);

		// Check signature
		if (memcmp (e->signature, APM_SIGNATURE, APM_SIGNATURE_LEN) != 0) {
			continue; // Skip invalid entries
		}

		// Check if partition is valid/allocated (bit 0 of partition_status indicates allocation/validity per APM spec)
		if (! (r_read_be32 ((ut8 *)&e->partition_status) & 1)) {
			continue; // Skip invalid partitions
		}

		// Skip if partition size is 0
		if (e->partition_size == 0) {
			continue;
		}

		ut32 partition_start = r_read_be32 ((ut8 *)&e->partition_start);
		ut32 partition_size = r_read_be32 ((ut8 *)&e->partition_size);
		ut64 start = (ut64)partition_start * 512;
		ut64 size = (ut64)partition_size * 512;

		par = r_fs_partition_new (i, start, size);
		par->type = 0; // APM doesn't have byte type, maybe use index

		iterate (fs, par, list);
	}

	free (entries);
	return 0;
}
