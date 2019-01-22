/* radare - LGPL - Copyright 2015-2018 - ampotos, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "omf/omf.h"

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 size, ut64 loadaddrn, Sdb *sdb) {
	if (!buf || !size || size == UT64_MAX) {
		return false;
	}
	*bin_obj = r_bin_internal_omf_load (buf, size);
	return true;
}

static bool load(RBinFile *bf) {
	const ut8 *byte = bf? r_buf_buffer (bf->buf): NULL;
	ut64 size = bf? r_buf_size (bf->buf): 0;
	if (!bf || !bf->o) {
		return false;
	}
	return load_bytes (bf, &bf->o->bin_obj, byte, size, bf->o->loadaddr, bf->sdb);
}

static int destroy(RBinFile *bf) {
	r_bin_free_all_omf_obj (bf->o->bin_obj);
	bf->o->bin_obj = NULL;
	return true;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	int i;
	if (!buf || length < 4) {
		return false;
	}
	if ((*buf != 0x80 && *buf != 0x82) || length < 4) {
		return false;
	}
	ut16 rec_size = ut8p_bw (buf + 1);
	ut8 str_size = *(buf + 3);
	if (str_size + 2 != rec_size || length < rec_size + 3) {
		return false;
	}
	// check that the string is ASCII
	for (i = 4; i < str_size + 4; ++i) {
		if (buf[i] > 0x7f) {
			return false;
		}
	}
	return r_bin_checksum_omf_ok (buf, length);
}

static ut64 baddr(RBinFile *bf) {
	return OMF_BASE_ADDR;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *addr;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(addr = R_NEW0 (RBinAddr))) {
		r_list_free (ret);
		return NULL;
	}
	if (!r_bin_omf_get_entry (bf->o->bin_obj, addr)) {
		R_FREE (addr);
	} else {
		r_list_append (ret, addr);
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret;
	ut32 ct_omf_sect = 0;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	r_bin_omf_obj *obj = bf->o->bin_obj;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	while (ct_omf_sect < obj->nb_section) {
		if (!r_bin_omf_send_sections (ret,\
			    obj->sections[ct_omf_sect++], bf->o->bin_obj)) {
			return ret;
		}
	}
	return ret;
}

static RList *symbols(RBinFile *bf) {
	RList *ret;
	RBinSymbol *sym;
	OMF_symbol *sym_omf;
	int ct_sym = 0;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	ret->free = free;

	while (ct_sym < ((r_bin_omf_obj *) bf->o->bin_obj)->nb_symbol) {
		if (!(sym = R_NEW0 (RBinSymbol))) {
			return ret;
		}
		sym_omf = ((r_bin_omf_obj *) bf->o->bin_obj)->symbols[ct_sym++];
		sym->name = strdup (sym_omf->name);
		sym->forwarder = r_str_const ("NONE");
		sym->paddr = r_bin_omf_get_paddr_sym (bf->o->bin_obj, sym_omf);
		sym->vaddr = r_bin_omf_get_vaddr_sym (bf->o->bin_obj, sym_omf);
		sym->ordinal = ct_sym;
		sym->size = 0;
		r_list_append (ret, sym);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("OMF");
	ret->rclass = strdup ("omf");
	// the "E" is here to made rva return the same value for 16 bit en 32 bits files
	ret->type = strdup ("E OMF (Relocatable Object Module Format)");
	ret->os = strdup ("any");
	ret->machine = strdup ("i386");
	ret->arch = strdup ("x86");
	ret->big_endian = false;
	ret->has_va = true;
	ret->has_lit = true;
	ret->bits = r_bin_omf_get_bits (bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

RBinPlugin r_bin_plugin_omf = {
	.name = "omf",
	.desc = "omf bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.get_vaddr = &get_vaddr,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_omf,
	.version = R2_VERSION
};
#endif
