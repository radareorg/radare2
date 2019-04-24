/* radare - LGPL - Copyright 2015 riq */
#ifndef VSF_SPECS_H
#define VSF_SPECS_H

#include <r_types_base.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

/* Snapshot format for VICE: http://vice-emu.sourceforge.net/ */

R_PACKED (
struct vsf_hdr {
	char id[19];		/* "VICE Snapshot File" */
	char major;
	char minor;
	char machine[16];	/* "C64" or "C128" or... */
});

R_PACKED (
struct vsf_module {
	char module_name[16];	/* looking for "C64MEM", ... */
	char major;
	char minor;
	ut32 length;		/* little endian */
});

R_PACKED (
struct vsf_maincpu {
	ut32 clk;		/* CPU clock value */
	ut8 ac;			/* A */
	ut8 xr;			/* X */
	ut8 yr;			/* Y */
	ut8 sp;			/* stack pointer */
	ut16 pc;		/* program counter */
	ut8 st;			/* Status register */
	ut32 lastopcode;	/* ? */
	ut32 ba_low_flags;	/* ? */
});

R_PACKED (
struct vsf_c64mem {
	ut8 cpudata;		/* CPU port data byte */
	ut8 cpudir;		/* CPU port direction byte */
	ut8 exrom;		/* state of the EXROM line (?) */
	ut8 game;		/* state of the GAME line (?) */
	ut8 ram[1024 * 64];	/* 64k RAM dump */
});

R_PACKED (
struct vsf_c64rom {
	ut8 kernal[1024 * 8];	/* Kernal ROM */
	ut8 basic[1024 * 8];	/* BASIC  ROM */
	ut8 chargen[1024 * 4];	/* Charset */
});

R_PACKED (
struct vsf_c128mem {
	ut8 mmu[12];		/* dump of the 12 MMU registers */
	ut8 ram[1024 * 128];	/* 128k RAM dump: banks 0 and 1 */
});

R_PACKED (
struct vsf_c128rom {
	ut8 kernal[1024 * 8];	/* Kernal ROM */
	ut8 basic[1024 * 32];	/* BASIC  ROM */
	ut8 editor[1024 * 4];	/* Dump of the editor ROM */
	ut8 chargen[1024 * 4];	/* Charset */
});

/* Internal structure */
struct r_bin_vsf_obj {
	int machine_idx;	/* 0=C64, 1=C128, ... see bin_vsf.c */
	ut64 rom;		/* ptr to C64/C128 rom */
	ut64 mem;		/* ptr to C64/C128 ram */
	struct vsf_maincpu* maincpu;
	Sdb* kv;
};

#endif /* VSF_SPECS_H */

