/* radare2 - LGPL - Copyright 2015-2017 - pancake */

/* XXX: maybe this should be implemented in RBin */
/* we need to extract the code section and get offset flags */

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

static int fs_part_dos(void *disk, void *ptr, void *closure) {
	int i;
	MBR mbr;
	RFS *fs = (RFS*)disk;
	RFSPartition *par = NULL;
	RFSPartitionIterator iterate = (RFSPartitionIterator)ptr;
	RList *list = (RList*)closure;

	memset (&mbr, 0, sizeof (mbr));
	fs->iob.read_at (fs->iob.io, 0, (ut8*)&mbr, sizeof (mbr));
	if (mbr.aa55 != 0xaa55) {
		eprintf ("Invalid DOS signature at 0x%x\n",
			(int)r_offsetof (MBR, aa55));
		return 0;
	}
	for (i=0; i<4; i++) {
		ut64 addr, aend;
		DOS_ENTRY *e = &mbr.entries[i];
		if (e->type != 0) {
			//int is_active = (e->flag == 0x80);
			addr = e->start;
			addr *= 512;

			aend = 0; //e->start;
			aend += e->length;
			aend *= 512;
			par = r_fs_partition_new (i, addr, aend);
			par->index = 0;
			par->type = e->type;
			iterate (disk, par, list);
		} else {
			// TODO: make deleted entries accessible?
		}
	}
	return 0;
}
