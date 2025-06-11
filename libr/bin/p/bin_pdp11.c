/* radare2 - LGPL - Copyright 2023 - pancake */

#include <r_bin.h>

#define MENUET_VERSION(x) x[7]

// #define BADDR 0x800000
#define BADDR 0
#if 0

// https://gunkies.org/wiki/UNIX_a.out_file

#------------------------------------------------------------------------------
# pdp:  file(1) magic for PDP-11 executable/object and APL workspace
#
0	lelong		0101555		PDP-11 single precision APL workspace
0	lelong		0101554		PDP-11 double precision APL workspace
#
# PDP-11 a.out
#
0	leshort		0407		PDP-11 executable
>8	leshort		>0		not stripped
>15	byte		>0		- version %ld

0	leshort		0401		PDP-11 UNIX/RT ldp
0	leshort		0405		PDP-11 old overlay

0	leshort		0410		PDP-11 pure executable
>8	leshort		>0		not stripped
>15	byte		>0		- version %ld

0	leshort		0411		PDP-11 separate I&D executable
>8	leshort		>0		not stripped
>15	byte		>0		- version %ld

0	leshort		0437		PDP-11 kernel overlay

# These last three are derived from 2.11BSD file(1)
0	leshort		0413		PDP-11 demand-paged pure executable
>8	leshort		>0		not stripped

0	leshort		0430		PDP-11 overlaid pure executable
>8	leshort		>0		not stripped

0	leshort		0431		PDP-11 overlaid separate executable
>8	leshort		>0		not stripped
#	$OpenBSD: perl,v 1.3 2009/04/24 18:54:34 chl Exp $

#define	A_MAGIC1	OMAGIC
#define OMAGIC		0407	/* ...object file or impure executable.  */
#define	A_MAGIC2	NMAGIC
#define NMAGIC		0410	/* Pure executable.  */
#define ZMAGIC		0413	/* Demand-paged executable.  */
#define	A_MAGIC3	0411	/* Separated I&D.  */
#define	A_MAGIC4	0405	/* Overlay.  */
#define	A_MAGIC5	0430	/* Auto-overlay (nonseparate).  */
#define	A_MAGIC6	0431	/* Auto-overlay (separate).  */
#define QMAGIC		0
#define BMAGIC		0

Magic number values are:
- 0407 (text is not write-protected and not shared),
- 0410 (text is write-protected, and one copy in main memory will be shared by all processes executing that file), or
- 0411 (as for 0410, but instruction and data space are separate, with both beginning at 0; i.e. 'split I&D').

The origin of the '0407' will be obvious to anyone familiar with PDP-11 object code; in the early days of UNIX,
an executable binary file was loaded into memory without stripping off the header, and started at location '0';
the '0407' is a BR instruction which skips over the header to the first location after it.

# header
0	A magic number (below)
2	Program text size
4	Initialized data size
6	Uninitialized (BSS) data size
010	Symbol table size
012	Entry location
014	Unused
016	Flag indicating relocation information has been suppressed

#

00	the reference is absolute
02	the reference is to the text segment
04	the reference is to initialized data
06	the reference is to BSS
10	the reference is to an un-defined external symbol

#endif

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 buf[16];
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	ut64 bs = r_buf_size (b);
	if (bs >= 32 && bs < 0x1ffff) {
		// pure executable for DEMOS pdp11 DVK clone
		ut16 magic = r_read_le16 (buf);
		if (magic == 0407) { // 0x0701
#if 1
			ut32 textsize = r_read_le16 (buf + 2);
			ut32 datasize = r_read_le16 (buf + 4);
			ut32 bss_size = r_read_le16 (buf + 6);
			ut32 sym_size = r_read_le16 (buf + 8);
			ut32 entrypoi = r_read_le16 (buf + 10);
			ut32 derelocs = r_read_le16 (buf + 12);
			ut32 mustzero = r_read_le16 (buf + 14);
			if (mustzero > 8) {
				return false;
			}
			eprintf ("TS 0x%08x\n", textsize);
			eprintf ("DS 0x%08x\n", datasize);
			eprintf ("EP 0x%08x\n", entrypoi);
			eprintf ("BS 0x%08x\n", bss_size);
			eprintf ("SY 0x%08x\n", sym_size);
			eprintf ("RL 0x%08x\n", derelocs);
#else
			ut32 mustzero = r_read_be16 (buf + 14);
			if (mustzero > 8) {
				// return false;
			}
#endif
			return true;
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static ut64 baddr(RBinFile *bf) {
	return BADDR;
}

static RList* entries(RBinFile *bf) {
	RList* ret;
	ut8 buf[64] = {0};
	RBinAddr *ptr = NULL;
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (bf->buf));

	r_buf_read_at (bf->buf, 0, buf, buf_size);
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 0x10;
		ptr->vaddr = 0x10 + BADDR;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut8 buf[64] = {0};
	ut64 bs = r_buf_size (bf->buf);
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (bf->buf));

	r_buf_read_at (bf->buf, 0, buf, buf_size);
	if (!bf->bo->info) {
		return NULL;
	}

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	// header
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->size = 16;
	ptr->vsize = 16;
	ptr->paddr = 0;
	ptr->format = strdup ("Cd 2[8]");
	ptr->vaddr = BADDR;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);
	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->size = bs;
	ptr->vsize = bs;
	ptr->paddr = 16;
	ptr->vaddr = BADDR + 16;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);

	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("executable");
	ret->rclass = strdup ("pure");
	ret->os = strdup ("demos");
	ret->arch = strdup ("pdp11");
	ret->machine = strdup ("dvk");
	ret->subsystem = strdup ("DVK");
	ret->type = strdup ("EXEC");
	ret->bits = 16;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = false;
	return ret;
}

static ut64 size(RBinFile *bf) {
	// TODO improve
	return UT16_MAX;
}

RBinPlugin r_bin_plugin_pdp11 = {
	.meta = {
		.name = "pdp11",
		.desc = "DEC's executables for Programmed Data Processors",
		.author = "pancake",
		.license = "MIT",
	},
	.load = &load,
	.size = &size,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pdp11,
	.version = R2_VERSION
};
#endif
