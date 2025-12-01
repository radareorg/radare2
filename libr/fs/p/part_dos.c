/* radare2 - LGPL - Copyright 2015-2022 - pancake */

#include <r_fs.h>
#include <r_types.h>

R_PACKED (
typedef struct {
	ut8 flag; // 0x80 if active
	ut8 start_head;
	ut8 start_sector;
	ut8 start_cylinder;
	ut8 type;
	ut8 end_head;
	ut8 end_sector;
	ut8 end_cylinder;
	ut32 start; // sector count (starting from 0)
	ut32 length; // in sector
}) DOS_ENTRY;
R_PACKED (
typedef struct {
	ut8 code[446]; // code
	DOS_ENTRY entries[4];
	ut16 aa55; // the signature
}) MBR;

static void parse_ebr(RFS *fs, RFSPartitionIterator iterate, RList *list, ut64 extended_start, ut64 ebr_sector, int *part_index) {
	MBR ebr;
	ut64 addr, aend;
	DOS_ENTRY *e;

	memset (&ebr, 0, sizeof (ebr));
	fs->iob.read_at (fs->iob.io, ebr_sector * 512, (ut8*)&ebr, sizeof (ebr));
	if (ebr.aa55 != 0xaa55) {
		R_LOG_ERROR ("Invalid EBR signature at sector 0x%" PFMT64x, ebr_sector);
		return;
	}

	// First entry: logical partition
	e = &ebr.entries[0];
	if (e->type != 0) {
		addr = extended_start + e->start;
		addr *= 512;
		aend = e->length;
		aend *= 512;
		RFSPartition *par = r_fs_partition_new (*part_index, addr, aend);
		par->index = 0;
		par->type = e->type;
		iterate (fs, par, list);
		(*part_index)++;
	}

	// Second entry: next EBR
	e = &ebr.entries[1];
	if (e->type != 0) {
		ut64 next_ebr_sector = extended_start + e->start;
		parse_ebr (fs, iterate, list, extended_start, next_ebr_sector, part_index);
	}
}

static int fs_part_dos(void *disk, void *ptr, void *closure) {
	int i;
	MBR mbr;
	RFS *fs = (RFS*)disk;
	RFSPartition *par = NULL;
	RFSPartitionIterator iterate = (RFSPartitionIterator)ptr;
	RList *list = (RList*)closure;
	int part_index = 0;

	memset (&mbr, 0, sizeof (mbr));
	fs->iob.read_at (fs->iob.io, 0, (ut8*)&mbr, sizeof (mbr));
	if (mbr.aa55 != 0xaa55) {
		R_LOG_ERROR ("Invalid DOS signature at 0x%x", (int)r_offsetof (MBR, aa55));
		return 0;
	}
	for (i = 0; i < 4; i++) {
		ut64 addr, aend;
		DOS_ENTRY *e = &mbr.entries[i];
		if (e->type != 0) {
			if (e->type == 0x05 || e->type == 0x0F) { // Extended partition
				// Parse EBR chain
				ut64 extended_start = e->start;
				parse_ebr (fs, iterate, list, extended_start, extended_start, &part_index);
			} else {
				// Primary partition
				addr = e->start;
				addr *= 512;

				aend = e->length;
				aend *= 512;
				par = r_fs_partition_new (part_index, addr, aend);
				par->index = 0;
				par->type = e->type;
				iterate (disk, par, list);
				part_index++;
			}
		} else {
			// TODO: make deleted entries accessible?
		}
	}
	return 0;
}
