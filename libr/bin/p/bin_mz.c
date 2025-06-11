/* radare - LGPL - Copyright 2015-2024 nodepad, pancake */

#include <r_bin.h>
#include "mz/mz.h"

/* half-magic */
#define HM(x) (int)((int)(x[0]<<8)|(int)(x[1]))

static Sdb *get_sdb(RBinFile *bf) {
	const struct r_bin_mz_obj_t *bin;
	if (bf && bf->bo && bf->bo->bin_obj) {
		bin = (struct r_bin_mz_obj_t *)bf->bo->bin_obj;
		if (bin && bin->kv) {
			return bin->kv;
		}
	}
	return NULL;
}

static bool knownHeaderBuffer(RBuffer *b, ut16 offset) {
	ut8 h[2] = {0};
	if (r_buf_read_at (b, offset, h, sizeof (h)) != sizeof (h)) {
		return false;
	}
	if (!memcmp (h, "PE", 2)) {
		if (offset + 0x20 < r_buf_size (b)) {
			if (r_buf_read_at (b, offset + 0x18, h, sizeof (h)) != 2) {
				return false;
			}
			if (!memcmp (h, "\x0b\x01", 2)) {
				return true;
			}
		}
	} else {
		if (!memcmp (h, "NE", 2)
		 || !memcmp (h, "LE", 2)
		 || !memcmp (h, "LX", 2)
		 || !memcmp (h, "PL", 2)) {
			return true;
		}
	}
	return false;
}

static bool checkEntrypointBuffer(RBuffer *b) {
	st16 cs = r_buf_read_le16_at (b, 0x16);
	ut16 ip = r_buf_read_le16_at (b, 0x14);
	ut16 v = r_buf_read_le16_at (b, 0x08);
	if ((st16)v < 1) {
		return false;
	}
	ut32 pa = ((v + cs) << 4) + ip;

	/* A minimal MZ header is 0x1B bytes.  Header length is measured in
	 * 16-byte paragraphs so the minimum header must occupy 2 paragraphs.
	 * This means that the entrypoint should be at least 0x20 unless someone
	 * cleverly fit a few instructions inside the header.
	 */
	pa &= 0xffff;
	ut64 length = r_buf_size (b);
	if (pa >= 0x20 && pa + 1 < length) {
		ut16 pe = r_buf_read_le16_at (b,  0x3c);
		if (pe + 2 < length && length > 0x104) {
			ut8 h[2];
			if (r_buf_read_at (b, pe, h, 2) == 2) {
				if (!memcmp (h, "PE", 2)) {
					return false;
				}
			}
		}
		return true;
	}
	return false;
}

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut64 b_size = r_buf_size (b);
	if (b_size <= 0x3d) {
		return false;
	}

	// Check for MZ magic.
	ut8 h[2];
	if (r_buf_read_at (b, 0, h, 2) != 2) {
		return false;
	}
	if (memcmp (h, "MZ", 2)) {
		return false;
	}

	// See if there is a new exe header.
	ut16 new_exe_header_offset = r_buf_read_le16_at (b, 0x3c);
	if (b_size > new_exe_header_offset + 2) {
		if (knownHeaderBuffer (b, new_exe_header_offset)) {
			return false;
		}
	}

	// Raw plain MZ executable (watcom)
	if (!checkEntrypointBuffer (b)) {
		return false;
	}
	return true;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	struct r_bin_mz_obj_t *mz_obj = r_bin_mz_new_buf (buf);
	if (mz_obj) {
		sdb_ns_set (bf->sdb, "info", mz_obj->kv);
		bf->bo->bin_obj = mz_obj;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_mz_free ((struct r_bin_mz_obj_t *)bf->bo->bin_obj);
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	RBinAddr *mzaddr = NULL;
	if (bf && bf->bo && bf->bo->bin_obj) {
		switch (type) {
		case R_BIN_SYM_MAIN:
			mzaddr = r_bin_mz_get_main_vaddr (bf->bo->bin_obj);
			break;
		}
	}
	return mzaddr;
}

static RList *entries(RBinFile *bf) {
	RList *res = r_list_newf (free);
	if (R_LIKELY (res)) {
		RBinAddr *ptr = r_bin_mz_get_entrypoint (bf->bo->bin_obj);
		if (R_LIKELY (ptr)) {
			r_list_append (res, ptr);
		}
	}
	return res;
}

static RList *sections(RBinFile *bf) {
	return r_bin_mz_get_segments (bf->bo->bin_obj);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *const ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("MZ");
	ret->rclass = strdup ("mz");
	ret->os = strdup ("DOS");
	ret->arch = strdup ("x86");
	ret->machine = strdup ("i386");
	ret->type = strdup ("EXEC (Executable file)");
	ret->subsystem = strdup ("DOS");
	ret->bits = 16;
	ret->dbg_info = false;
	ret->big_endian = false;
	ret->has_crypto = false;
	ret->has_canary = false;
	ret->has_retguard = -1;
	ret->has_nx = false;
	ret->has_pi = false;
	ret->has_va = true;
	return ret;
}

static void header(RBinFile *bf) {
#define p bf->rbin->cb_printf
	const struct r_bin_mz_obj_t *mz = (struct r_bin_mz_obj_t *)bf->bo->bin_obj;
	const MZ_image_dos_header *dh = mz->dos_header;
	p ("[0000:0000]  Signature           %c%c\n",
		dh->signature & 0xFF,
		dh->signature >> 8);
	p ("[0000:0002]  BytesInLastBlock    0x%04x\n", dh->bytes_in_last_block);
	p ("[0000:0004]  BlocksInFile        0x%04x\n", dh->blocks_in_file);
	p ("[0000:0006]  NumRelocs           0x%04x\n", dh->num_relocs);
	p ("[0000:0008]  HeaderParagraphs    0x%04x\n", dh->header_paragraphs);
	p ("[0000:000a]  MinExtraParagraphs  0x%04x\n", dh->min_extra_paragraphs);
	p ("[0000:000c]  MaxExtraParagraphs  0x%04x\n", dh->max_extra_paragraphs);
	p ("[0000:000e]  InitialSs           0x%04x\n", dh->ss);
	p ("[0000:0010]  InitialSp           0x%04x\n", dh->sp);
	p ("[0000:0012]  Checksum            0x%04x\n", dh->checksum);
	p ("[0000:0014]  InitialIp           0x%04x\n", dh->ip);
	p ("[0000:0016]  InitialCs           0x%04x\n", dh->cs);
	p ("[0000:0018]  RelocTableOffset    0x%04x\n", dh->reloc_table_offset);
	p ("[0000:001a]  OverlayNumber       0x%04x\n", dh->overlay_number);
}

static RList *relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	const struct r_bin_mz_reloc_t *relocs = NULL;
	int i;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	if (!(relocs = r_bin_mz_get_relocs (bf->bo->bin_obj))) {
		return ret;
	}
	for (i = 0; !relocs[i].last; i++) {
		RBinReloc *rel = R_NEW0 (RBinReloc);
		rel->type = R_BIN_RELOC_16;
		rel->vaddr = relocs[i].vaddr;
		rel->paddr = relocs[i].paddr;
		r_list_append (ret, rel);
	}
	free ((void *)relocs);
	return ret;
}

static RList* fields(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}
	#define ROW(nam, fmt, cmt) { \
		ut16 word = r_buf_read_le16_at (bf->buf, addr); \
		RBinField *f = r_bin_field_new (addr, addr, word, 2, nam, cmt, fmt, false); \
		r_list_append (ret, f); \
		addr += 2; }
	ut64 addr = 0;
	ROW ("Signature", "w", "Magic number");
	ROW ("LastBlockBytes", "w", "Bytes in the last page");
	ROW ("Blocks", "w", "Total amount of pages");
	ROW ("NumRelocs", "w", "Number of relocations");
	ROW ("SizeOfHeader", "w", "In paragraphs (16 bytes)");
	ROW ("MinAlloc", "w", "Minimum amount of extra paragraphs");
	ROW ("MaxAlloc", "w", "Maximum amount of extra paragraphs");
	ROW ("InitialSs", "w", "Initial value for the stack segment");
	ROW ("InitialSp", "w", "Initial value for the stack pointer");
	ROW ("Checksum", "w", "Optional. Usually zero");
	ROW ("InitialIp", "w", "Initial value for the instruction pointer");
	ROW ("InitialCs", "w", "Initial value for the code segment");
	ROW ("RelocTable", "w", "Relocation Table offset");
	ROW ("OverlayNumber", "w", "Overlay Number");
	ROW ("OemId", "w", "OEM identifier (optional)");
	ROW ("OemInfo", "w", "OEM information (optional)");
#if 0
	ROW ("Reserved", "w", "reserved padding 20 bytes");
	ROW ("LFANew", "w", "Offset to the PE header");
#endif
	return ret;
}

RBinPlugin r_bin_plugin_mz = {
	.meta = {
		.name = "mz",
		.author = "pancake",
		.desc = "Mark Zbikowski's Modern Executable from MS-DOS",
		.license = "MIT",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.header = &header,
	.fields = &fields,
	.relocs = &relocs,
	.minstrlen = 4,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mz,
	.version = R2_VERSION
};
#endif
