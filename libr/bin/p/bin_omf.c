/* radare - LGPL - Copyright 2015-2019 - ampotos, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "omf/omf.h"

static bool load_buffer (RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = r_buf_data (b, &size);
	r_return_val_if_fail (buf, false);
	*bin_obj = r_bin_internal_omf_load (buf, size);
	return *bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_free_all_omf_obj (bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static bool check_buffer(RBuffer *b) {
	int i;
	ut8 ch;
	if (r_buf_read_at (b, 0, &ch, 1) != 1) {
		return false;
	}
	if (ch != 0x80 && ch != 0x82) {
		return false;
	}
	ut16 rec_size = r_buf_read_le16_at (b, 1);
	ut8 str_size; (void)r_buf_read_at (b, 3, &str_size, 1);
	ut64 length = r_buf_size (b);
	if (str_size + 2 != rec_size || length < rec_size + 3) {
		return false;
	}
	// check that the string is ASCII
	for (i = 4; i < str_size + 4; i++) {
		if (r_buf_read_at (b, i, &ch, 1) != 1) {
			break;
		}
		if (ch > 0x7f) {
			return false;
		}
	}
	const ut8 *buf = r_buf_data (b, NULL);
	if (buf == NULL) {
		// hackaround until we make this plugin not use RBuf.data
		ut8 buf[1024] = {0};
		r_buf_read_at (b, 0, buf, sizeof (buf));
		return r_bin_checksum_omf_ok (buf, sizeof (buf));
	}
	r_return_val_if_fail (buf, false);
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
		sym->forwarder = "NONE";
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
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.get_vaddr = &get_vaddr,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_omf,
	.version = R2_VERSION
};
#endif
