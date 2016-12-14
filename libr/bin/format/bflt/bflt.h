/* radare - LGPL - Copyright 2016 - Oscar Salvador */

#ifndef BFLT_H
#define BFLT_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

/* Version 2 */
#define OLD_FLAT_VERSION	0x00000002L
#define FLAT_RELOC_TYPE_TEXT	0x0
#define FLAT_RELOC_TYPE_DATA	0x1
#define FLAT_RELOC_TYPE_BSS	0x2

/*
struct bflt_relocation {
#if defined(__BIG_ENDIAN_BITFIELD)
        ut32 type : 2;
        signed long offset : 30;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
        signed long offset : 30;
        ut32 type : 2;
#endif
};
*/
/* */

/* Version 4 */
#define FLAT_VERSION            0x00000004L
#define FLAT_FLAG_RAM		0x1	/* load program entirely into RAM */
#define FLAT_FLAG_GOTPIC 	0x2 	/* program is PIC with GOT */
#define FLAT_FLAG_GZIP   	0x4	/* all but the header is compressed */
#define FLAT_FLAG_GZDATA	0x8	/* only data/relocs are compressed (for XIP) */
#define FLAT_FLAG_KTRACE	0x10	/* output useful kernel trace for debugging */

struct bflt_hdr {
	char magic[4];
	ut32 rev;
	ut32 entry;
	ut32 data_start;
	ut32 data_end;
	ut32 bss_end;
	ut32 stack_size;
	ut32 reloc_start;
	ut32 reloc_count;
	ut32 flags;
	ut32 build_date;
	ut32 filler[5];
};

struct bflt_relocation_t {
	ut32 addr_to_patch;
	ut32 data;
};

struct r_bin_bflt_obj {
	struct bflt_hdr *hdr;
	struct bflt_relocation_t *bflt_reloc_table;
	RBuffer *b;
	Sdb *kv;
	ut8 endian;
	size_t size;
};

#define BFLT_HDR_SIZE		sizeof (struct bflt_hdr)
#define VALID_GOT_ENTRY(x)	(x != 0xFFFFFFFF)

RBinAddr *r_bflt_get_entry(struct r_bin_bflt_obj *bin);
struct r_bin_bflt_obj *r_bin_bflt_new_buf(struct r_buf_t *buf);
void r_bin_bflt_free(struct r_bin_bflt_obj *obj);

#endif
