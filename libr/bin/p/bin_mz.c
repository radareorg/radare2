/* radare - LGPL - Copyright 2015-2018 nodepad */

#include <r_types.h>
#include <r_bin.h>
#include "mz/mz.h"

static Sdb * get_sdb(RBinFile *bf) {
	const struct r_bin_mz_obj_t *bin;
	if (bf && bf->o && bf->o->bin_obj) {
		bin = (struct r_bin_mz_obj_t *) bf->o->bin_obj;
		if (bin && bin->kv) {
			return bin->kv;
		}
	}
	return NULL;
}

static bool checkEntrypoint(const ut8 *buf, ut64 length) {
	st16 cs = r_read_ble16 (buf + 0x16, false);
	ut16 ip = r_read_ble16 (buf + 0x14, false);
	ut32 pa = ((r_read_ble16 (buf + 8 , false) + cs) << 4) + ip;

	/* A minimal MZ header is 0x1B bytes.  Header length is measured in
	 * 16-byte paragraphs so the minimum header must occupy 2 paragraphs.
	 * This means that the entrypoint should be at least 0x20 unless someone
	 * cleverly fit a few instructions inside the header.
	 */
	pa &= 0xffff;
	if (pa >= 0x20 && pa + 1 < length) {
		ut16 pe = r_read_ble16 (buf + 0x3c, false);
		if (pe + 2 < length && length > 0x104 && !memcmp (buf + pe, "PE", 2)) {
			return false;
		}
		return true;
	}
	return false;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	ut16 new_exe_header_offset;
	if (!buf || length <= 0x3d) {
		return false;
	}

	// Check for MZ magic.
	if (memcmp (buf, "MZ", 2) && memcmp (buf, "ZM", 2)) {
		return false;
	}

	// See if there is a new exe header.
	new_exe_header_offset = r_read_ble16 (buf + 0x3c, false);
	if (length > new_exe_header_offset + 2) {
		// check for PE
		if (!memcmp (buf + new_exe_header_offset, "PE", 2) &&
		    (length > new_exe_header_offset + 0x20) &&
		    !memcmp (buf + new_exe_header_offset + 0x18, "\x0b\x01", 2)) {
			return false;
		}

		// Check for New Executable, LE/LX or Phar Lap executable
		if (!memcmp (buf + new_exe_header_offset, "NE", 2) ||
		    !memcmp (buf + new_exe_header_offset, "LE", 2) ||
		    !memcmp (buf + new_exe_header_offset, "LX", 2) ||
		    !memcmp (buf + new_exe_header_offset, "PL", 2)) {
			if (!checkEntrypoint (buf, length)) {
				return false;
			}
		}
	}

	// Raw plain MZ executable (watcom)
	if (!checkEntrypoint (buf, length)) {
		return false;
	}

	return true;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz,
		ut64 loadaddr, Sdb *sdb) {
	struct r_bin_mz_obj_t *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || !sz || sz == UT64_MAX) {
		return false;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_mz_new_buf (tbuf);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	*bin_obj = res;
	return true;
}

static bool load(RBinFile *bf) {
	if (!bf || !bf->o) {
		return false;
	}
	const ut8 *bytes = r_buf_buffer (bf->buf);
	ut64 sz = r_buf_size (bf->buf);
	return load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
}

static int destroy(RBinFile *bf) {
	r_bin_mz_free ((struct r_bin_mz_obj_t*)bf->o->bin_obj);
	return true;
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	ut64 mzaddr = 0;
	RBinAddr *ret = NULL;
	if (bf && bf->o && bf->o->bin_obj) {
		switch(type) {
		case R_BIN_SYM_MAIN:
			mzaddr = r_bin_mz_get_main_vaddr (bf->o->bin_obj);
			break;
		}
	}
	if (mzaddr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = mzaddr;
		ret->vaddr = mzaddr;
	}
	return ret;
}

static RList * entries(RBinFile *bf) {
	RBinAddr *ptr = NULL;
	RList *res = NULL;
	if (!(res = r_list_newf (free))) {
		return NULL;
	}
	int entry = r_bin_mz_get_entrypoint (bf->o->bin_obj);
	if (entry >= 0) {
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = (ut64) entry;
			ptr->vaddr = (ut64) entry;
			r_list_append (res, ptr);
		}
	}
	return res;
}

static RList * sections(RBinFile *bf) {
	const struct r_bin_mz_segment_t *segments = NULL;
	RBinSection *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(segments = r_bin_mz_get_segments (bf->o->bin_obj))){
		r_list_free (ret);
		return NULL;
	}
	for (i = 0; !segments[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			free ((void *)segments);
			r_list_free (ret);
			return NULL;
		}
		sprintf ((char*)ptr->name, "seg_%03d", i);
		ptr->size = segments[i].size;
		ptr->vsize = segments[i].size;
		ptr->paddr = segments[i].paddr;
		ptr->vaddr = segments[i].paddr;
		ptr->perm = r_str_rwx ("rwx");
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	free ((void *)segments);
	return ret;
}

static RBinInfo * info(RBinFile *bf) {
	RBinInfo * const ret = R_NEW0 (RBinInfo);
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
	ret->has_va = false;
	return ret;
}

static void header(RBinFile *bf) {
	const struct r_bin_mz_obj_t *mz = (struct r_bin_mz_obj_t *) bf->o->bin_obj;
	eprintf("[0000:0000]  Signature           %c%c\n",
		mz->dos_header->signature & 0xFF,
		mz->dos_header->signature >> 8);
	eprintf("[0000:0002]  BytesInLastBlock    0x%04x\n",
	   mz->dos_header->bytes_in_last_block);
	eprintf("[0000:0004]  BlocksInFile        0x%04x\n",
	    mz->dos_header->blocks_in_file);
	eprintf("[0000:0006]  NumRelocs           0x%04x\n",
	    mz->dos_header->num_relocs);
	eprintf("[0000:0008]  HeaderParagraphs    0x%04x\n",
	    mz->dos_header->header_paragraphs);
	eprintf("[0000:000a]  MinExtraParagraphs  0x%04x\n",
	    mz->dos_header->min_extra_paragraphs);
	eprintf("[0000:000c]  MaxExtraParagraphs  0x%04x\n",
	    mz->dos_header->max_extra_paragraphs);
	eprintf("[0000:000e]  InitialSs           0x%04x\n",
	    mz->dos_header->ss);
	eprintf("[0000:0010]  InitialSp           0x%04x\n",
	    mz->dos_header->sp);
	eprintf("[0000:0012]  Checksum            0x%04x\n",
	    mz->dos_header->checksum);
	eprintf("[0000:0014]  InitialIp           0x%04x\n",
	    mz->dos_header->ip);
	eprintf("[0000:0016]  InitialCs           0x%04x\n",
	    mz->dos_header->cs);
	eprintf("[0000:0018]  RelocTableOffset    0x%04x\n",
	    mz->dos_header->reloc_table_offset);
	eprintf("[0000:001a]  OverlayNumber       0x%04x\n",
	    mz->dos_header->overlay_number);
}

static RList * relocs(RBinFile *bf) {
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
		rel->vaddr = relocs[i].paddr;
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
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.header = &header,
	.relocs = &relocs,
	.minstrlen = 4,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mz,
	.version = R2_VERSION
};
#endif
