/* radare - LGPL - Copyright 2015-2024 - ampotos, pancake */

#include <r_bin.h>
#include "omf/omf.h"

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && b, false);
	ut64 size;
	const ut8 *buf = r_buf_data (b, &size);
	R_RETURN_VAL_IF_FAIL (buf, false);
	bf->bo->bin_obj = r_bin_internal_omf_load (buf, size);
	return bf->bo->bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_free_all_omf_obj (bf->bo->bin_obj);
	bf->bo->bin_obj = NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
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
	R_RETURN_VAL_IF_FAIL (buf, false);
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
	if (!r_bin_omf_get_entry (bf->bo->bin_obj, addr)) {
		R_FREE (addr);
	} else {
		r_list_append (ret, addr);
	}
	return ret;
}

static bool append_omf_sections(RBinFile *bf, OMF_segment *section, r_bin_omf_obj *obj) {
	OMF_data *data = section->data;
	ut32 ct_name = 1;

	while (data) {
		RBinSection *new = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		if (section->name_idx && section->name_idx - 1 < obj->nb_name) {
			new->name = r_str_newf ("%s_%d", obj->names[section->name_idx - 1], ct_name++);
		} else {
			new->name = r_str_newf ("no_name_%d", ct_name++);
		}
		new->size = data->size;
		new->vsize = data->size;
		new->paddr = data->paddr;
		new->vaddr = section->vaddr + data->offset + OMF_BASE_ADDR;
		new->perm = R_PERM_RWX;
		new->add = true;
		data = data->next;
	}
	return true;
}

static bool sections_vec(RBinFile *bf) {
	ut32 ct_omf_sect = 0;

	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return false;
	}
	r_bin_omf_obj *obj = bf->bo->bin_obj;

	RVecRBinSection_clear (&bf->bo->sections_vec);
	while (ct_omf_sect < obj->nb_section) {
		if (!append_omf_sections (bf, obj->sections[ct_omf_sect++], obj)) {
			return false;
		}
	}
	return true;
}

static bool symbols_vec(RBinFile *bf) {
	OMF_symbol *sym_omf;
	int ct_sym = 0;
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return false;
	}
	RVecRBinSymbol *ret = &bf->bo->symbols_vec;

	while (ct_sym < ((r_bin_omf_obj *) bf->bo->bin_obj)->nb_symbol) {
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (ret);
		sym_omf = ((r_bin_omf_obj *) bf->bo->bin_obj)->symbols[ct_sym++];
		sym->name = r_bin_name_new (sym_omf->name);
		sym->forwarder = "NONE";
		sym->paddr = r_bin_omf_get_paddr_sym (bf->bo->bin_obj, sym_omf);
		sym->vaddr = r_bin_omf_get_vaddr_sym (bf->bo->bin_obj, sym_omf);
		sym->ordinal = ct_sym;
	}
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
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
	ret->bits = r_bin_omf_get_bits (bf->bo->bin_obj);
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

RBinPlugin r_bin_plugin_omf = {
	.meta = {
		.name = "omf",
		.desc = "Object Module Format for 80x86",
		.author = "ampotos",
		.license = "LGPL-3.0-only",
	},
	.weak_guess = true,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
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
