/* radare - LGPL - Copyright 2015-2019 nodepad */

#include <r_types.h>
#include <r_bin.h>
#include <r_lib.h>
#include "mz/mz.h"


/* half-magic */
#define HM(x) (int)((int)(x[0]<<8)|(int)(x[1]))

static Sdb *get_sdb(RBinFile *bf) {
	const struct r_bin_mz_obj_t *bin;
	if (bf && bf->o && bf->o->bin_obj) {
		bin = (struct r_bin_mz_obj_t *)bf->o->bin_obj;
		if (bin && bin->kv) {
			return bin->kv;
		}
	}
	return NULL;
}

static bool knownHeaderBuffer(RBuffer *b, ut16 offset) {
	ut8 h[2];
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
	ut32 pa = ((r_buf_read_le16_at (b, 0x08) + cs) << 4) + ip;

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

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);
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

static bool load(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	struct r_bin_mz_obj_t *mz_obj = r_bin_mz_new_buf (buf);
	if (mz_obj) {
		sdb_ns_set (sdb, "info", mz_obj->kv);
		*bin_obj = mz_obj;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_mz_free ((struct r_bin_mz_obj_t *)bf->o->bin_obj);
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	RBinAddr *mzaddr = NULL;
	if (bf && bf->o && bf->o->bin_obj) {
		switch (type) {
		case R_BIN_SYM_MAIN:
			mzaddr = r_bin_mz_get_main_vaddr (bf->o->bin_obj);
			break;
		}
	}
	return mzaddr;
}

static RList *entries(RBinFile *bf) {
	RBinAddr *ptr = NULL;
	RList *res = NULL;
	if (!(res = r_list_newf (free))) {
		return NULL;
	}
	ptr = r_bin_mz_get_entrypoint (bf->o->bin_obj);
	if (ptr) {
		r_list_append (res, ptr);
	}
	return res;
}

static RList *sections(RBinFile *bf) {
	return r_bin_mz_get_segments (bf->o->bin_obj);
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
	ret->dbg_info = 0;
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
	const struct r_bin_mz_obj_t *mz = (struct r_bin_mz_obj_t *)bf->o->bin_obj;
	eprintf ("[0000:0000]  Signature           %c%c\n",
		mz->dos_header->signature & 0xFF,
		mz->dos_header->signature >> 8);
	eprintf ("[0000:0002]  BytesInLastBlock    0x%04x\n",
		mz->dos_header->bytes_in_last_block);
	eprintf ("[0000:0004]  BlocksInFile        0x%04x\n",
		mz->dos_header->blocks_in_file);
	eprintf ("[0000:0006]  NumRelocs           0x%04x\n",
		mz->dos_header->num_relocs);
	eprintf ("[0000:0008]  HeaderParagraphs    0x%04x\n",
		mz->dos_header->header_paragraphs);
	eprintf ("[0000:000a]  MinExtraParagraphs  0x%04x\n",
		mz->dos_header->min_extra_paragraphs);
	eprintf ("[0000:000c]  MaxExtraParagraphs  0x%04x\n",
		mz->dos_header->max_extra_paragraphs);
	eprintf ("[0000:000e]  InitialSs           0x%04x\n",
		mz->dos_header->ss);
	eprintf ("[0000:0010]  InitialSp           0x%04x\n",
		mz->dos_header->sp);
	eprintf ("[0000:0012]  Checksum            0x%04x\n",
		mz->dos_header->checksum);
	eprintf ("[0000:0014]  InitialIp           0x%04x\n",
		mz->dos_header->ip);
	eprintf ("[0000:0016]  InitialCs           0x%04x\n",
		mz->dos_header->cs);
	eprintf ("[0000:0018]  RelocTableOffset    0x%04x\n",
		mz->dos_header->reloc_table_offset);
	eprintf ("[0000:001a]  OverlayNumber       0x%04x\n",
		mz->dos_header->overlay_number);
}

static RList *relocs(RBinFile *bf) {
	RList *ret = NULL;
	RBinReloc *rel = NULL;
	const struct r_bin_mz_reloc_t *relocs = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(relocs = r_bin_mz_get_relocs (bf->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !relocs[i].last; i++) {
		if (!(rel = R_NEW0 (RBinReloc))) {
			free ((void *)relocs);
			r_list_free (ret);
			return NULL;
		}
		rel->type = R_BIN_RELOC_16;
		rel->vaddr = relocs[i].vaddr;
		rel->paddr = relocs[i].paddr;
		r_list_append (ret, rel);
	}
	free ((void *)relocs);
	return ret;
}

RBinPlugin r_bin_plugin_mz = {
	.name = "mz",
	.desc = "MZ bin plugin",
	.license = "MIT",
	.get_sdb = &get_sdb,
	.load_buffer = &load,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.header = &header,
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
