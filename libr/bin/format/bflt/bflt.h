/* radare - LGPL - Copyright 2016-2022 - Oscar Salvador */

#ifndef BFLT_H
#define BFLT_H

#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

/* Version 4 */
#define	FLAT_VERSION		0x00000004L
#define FLAT_FLAG_RAM		0x1	/* load program entirely into RAM */
#define FLAT_FLAG_GOTPIC	0x2 	/* program is PIC with GOT */
#define FLAT_FLAG_GZIP		0x4	/* all but the header is compressed */
#define FLAT_FLAG_GZDATA	0x8	/* only data/relocs are compressed (for XIP) */
#define FLAT_FLAG_KTRACE	0x10	/* output useful kernel trace for debugging */

/* CPU architecture constants */
#define BFLT_CPU_68K		0x0001	/* Motorola 68000 */
#define BFLT_CPU_386		0x0002	/* Intel x86 */
#define BFLT_CPU_ARM		0x0004	/* ARM */
#define BFLT_CPU_MIPS		0x0008	/* MIPS */
#define BFLT_CPU_PPC		0x0010	/* PowerPC */
#define BFLT_CPU_SH		0x0020	/* SuperH */
#define BFLT_CPU_COLDFIRE	0x0040	/* ColdFire */

typedef struct bflt_hdr {
	ut8 magic[4];
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
} RBinBfltHeader;

typedef struct reloc_struct_t {
	ut32 addr_to_patch;
	ut32 data_offset;
} RBinBfltReloc;

typedef struct r_bin_bflt_obj {
	RBinBfltHeader *hdr;
	RBinBfltReloc *reloc_table;
	RBinBfltReloc *got_table;
	RList *relocs_list;
	RBuffer *b;
	ut8 endian;
	size_t size;
	ut32 n_got;
	ut32 cpu_type;
} RBinBfltObj;

#define BFLT_HDR_SIZE sizeof (RBinBfltHeader)
#define VALID_GOT_ENTRY(x) (x != UT32_MAX)

R_IPI RBinAddr *r_bflt_get_entry(RBinBfltObj *bin);
R_IPI RBinBfltObj *r_bin_bflt_new_buf(RBuffer *buf);
R_IPI void r_bin_bflt_free(RBinBfltObj *obj);

#endif
