/* radare - LGPL - Copyright 2021-2024 - pancake */

// https://github.com/nesbox/TIC-80/wiki/tic-File-Format

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"

#define CHUNK_TILES	1 // BG sprites (0...255). This is copied to RAM at 0x4000...0x5FFF.
#define CHUNK_SPRITES	2 // FG sprites (256...511). This is copied to RAM at 0x6000...0x7FFF.
#define CHUNK_COVER_DEP 3 // deprecated in 0.90
#define CHUNK_MAP	4 // map data. This is copied to RAM at0x8000...0xFF7F.
#define CHUNK_CODE	5
#define CHUNK_FLAGS	6 // sprite flags data. This is copied to RAM at 0x14404...0x14603.
#define CHUNK_SAMPLES	9 // SFX. This is copied to RAM at0x100E4...0x11163.
#define CHUNK_WAVEFORM	10 // This is copied to RAM at0x0FFE4...0x100E3.
#define CHUNK_PALETTE	12 // The SCN palette is copied to RAM at0x3FC0...0x3FEF.
#define CHUNK_PATTERNS_DEP 13 // deprecated in 0.90
#define CHUNK_MUSIC	14 // This is copied to RAM at 0x13E64...0x13FFB.
#define CHUNK_PATTERNS	15 //  This is copied to RAM at 0x11164...0x13E63.
#define CHUNK_CODE_ZIP	16
#define CHUNK_DEFAULT   17 // serves as a flag for default palette and waveforms should be loaded or not.
#define CHUNK_SCREEN	18 // 16kb in length Stores a 240 x 136 x 4bpp raw buffer (ie, VRAM).


#if 0
Each chunk consists of a 4-byte header, followed by the chunk data. This pattern is then repeated for each chunk.

Offset	Bits (7...0)	Description
0	BBBCCCCC	B = Bank number (0...7), C = Chunk type (0...31)
1...2	SSSSSSSS
SSSSSSSS	Size of chunk (16 bits, max. 65535 bytes)
3		Reserved for future use
4+	DDDDDDDD	Chunk data

typedef struct {
	ut8 bank_and_type; // BBBCCCCC (BANK NUMBER + CHUNK TYPE)
	ut16 size;
	ut8 reserved;
	ut8 *data;
} TicChunk;
#endif
static const char *chunk_name(int chunk_type) {
	switch (chunk_type) {
	case CHUNK_TILES: return "tiles";
	case CHUNK_SPRITES: return "sprites";
	case CHUNK_COVER_DEP: return "cover";
	case CHUNK_MAP: return "map";
	case CHUNK_CODE: return "code";
	case CHUNK_FLAGS: return "flags";
	case CHUNK_SAMPLES: return "samples";
	case CHUNK_WAVEFORM: return "waveform";
	case CHUNK_PALETTE: return "palette";
	case CHUNK_PATTERNS_DEP: return "patterns";
	case CHUNK_MUSIC: return "music";
	case CHUNK_PATTERNS: return "patterns";
	case CHUNK_CODE_ZIP: return "zip";
	case CHUNK_DEFAULT: return "default";
	case CHUNK_SCREEN: return "screen";
	}
	return "";
}

static bool check(RBinFile *bf, RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, false);
	if (bf && !r_str_endswith (bf->file, ".tic")) {
		return false;
	}
	ut64 sz = r_buf_size (buf);
	// max rom size is 10MB
	if (sz <= 0xff || sz > (10 * 1024 * 1024)) {
		// TOO SMELL?
		return false;
	}
	ut64 off = 0;
	for (;off < sz;) {
		ut8 hb;
		if (r_buf_read_at (buf, off, &hb, 1) != 1) {
			break;
		}
		off++;
		int bank_number = (hb >> 5) & 7;
		int chunk_type = hb & 0x1f;
		ut16 chunk_length = 0;
		if (r_buf_read_at (buf, off, (ut8*)&chunk_length, 2) != 2) {
			return false;
		}
		off += 3; // 16bit for length + 1 byte for padding
		switch (chunk_type) {
		case CHUNK_TILES:
		case CHUNK_SPRITES:
		case CHUNK_COVER_DEP:
		case CHUNK_MAP:
		case CHUNK_CODE:
		case CHUNK_FLAGS:
		case CHUNK_SAMPLES:
		case CHUNK_WAVEFORM:
		case CHUNK_PALETTE:
		case CHUNK_PATTERNS_DEP:
		case CHUNK_MUSIC:
		case CHUNK_PATTERNS:
		case CHUNK_CODE_ZIP:
		case CHUNK_DEFAULT:
		case CHUNK_SCREEN:
			R_LOG_DEBUG ("BANK %d CHUNK %2d (%s) LENGTH %d",
				bank_number, chunk_type,
				chunk_name (chunk_type), chunk_length);
			break;
		default:
			R_LOG_DEBUG ("Invalid chunk at offset 0x%"PFMT64x, off);
			return false;
		}
		// data
		off += chunk_length;
	}
	// first 3 bytes can be anything! lots of false positives here
	return true;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	if (!check (bf, buf)) {
		return false;
	}
	bf->bo->bin_obj = r_buf_ref (buf);
	return true;
}

static void destroy(RBinFile *bf) {
	r_buf_free (bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("tic");
	ret->bclass = strdup ("1.0");
	ret->rclass = strdup ("TIC-80");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("tic-80");
	ret->arch = strdup ("z80"); // should be zlua or sthg
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

static void add_section(RList *list, const char *name, ut64 paddr, int size, ut64 vaddr) {
	RBinSection *ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ptr->name = strdup (name);
		ptr->vsize = ptr->size = size;
		ptr->paddr = paddr;
		ptr->vaddr = vaddr;
		ptr->perm = R_PERM_RW;
		ptr->add = true; // paddr != vaddr;
		ptr->is_segment = paddr == vaddr;
		r_list_append (list, ptr);
	}
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBuffer *buf = bf->bo->bin_obj;

	if (!(ret = r_list_newf ((RListFree) r_bin_section_free))) {
		return NULL;
	}
	ut64 sz = r_buf_size (buf);
	// max rom size is 10MB
	if (sz <= 0xff || sz > (10 * 1024 * 1024)) {
		// TOO SMELL?
		return false;
	}
	ut64 off = 0;
	for (;off < sz;) {
		ut8 hb;
		if (r_buf_read_at (buf, off, &hb, 1) != 1) {
			break;
		}
		off++;
		int bank_number = (hb >> 5) & 7;
		int chunk_type = hb & 0x1f;
		ut16 chunk_length = 0;
		if (r_buf_read_at (buf, off, (ut8*)&chunk_length, 2) != 2) {
			return false;
		}
		off += 3; // 16bit for length + 1 byte for padding
		ut64 vaddr = off;
		switch (chunk_type) {
		case CHUNK_TILES:
			vaddr = 0x4000;
			break;
		case CHUNK_SPRITES:
			vaddr = 0x6000;
			break;
		case CHUNK_MAP:
			vaddr = 0x8000;
			break;
		case CHUNK_FLAGS:
			vaddr = 0x14404;
			break;
		case CHUNK_SAMPLES:
			vaddr = 0x100e4;
			break;
		case CHUNK_WAVEFORM:
			vaddr = 0xffea;
			break;
		case CHUNK_PALETTE:
			vaddr = 0x3fc0;
			break;
		case CHUNK_MUSIC:
			vaddr = 0x13e64;
			break;
		case CHUNK_PATTERNS:
			vaddr = 0x11164;
			break;
		case CHUNK_SCREEN:
			// 16kb of data
			break;
		}
		switch (chunk_type) {
		case CHUNK_TILES:
		case CHUNK_SPRITES:
		case CHUNK_COVER_DEP:
		case CHUNK_MAP:
		case CHUNK_CODE:
		case CHUNK_FLAGS:
		case CHUNK_SAMPLES:
		case CHUNK_WAVEFORM:
		case CHUNK_PALETTE:
		case CHUNK_PATTERNS_DEP:
		case CHUNK_MUSIC:
		case CHUNK_PATTERNS:
		case CHUNK_CODE_ZIP:
		case CHUNK_DEFAULT:
		case CHUNK_SCREEN:
			{
				char *n = r_str_newf ("%s.%d", chunk_name (chunk_type), bank_number);
				add_section (ret, n, off, chunk_length, vaddr);
				free (n);
			}
			R_LOG_DEBUG ("BANK %d CHUNK %2d (%s) LENGTH %d",
				bank_number, chunk_type,
				chunk_name (chunk_type), chunk_length);
			break;
		default:
			R_LOG_ERROR ("Invalid chunk at offset 0x%"PFMT64x, off);
			return false;
		}
		// data
		off += chunk_length;
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	// begin of code section
	ptr->paddr = 0; // 0x70000;
	ptr->vaddr = 0xffff0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_tic = {
	.meta = {
		.name = "tic",
		.author = "pancake",
		.desc = "TIC-80 Cartridge",
		.license = "MIT",
	},
	.weak_guess = true,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_tic,
	.version = R2_VERSION
};
#endif
