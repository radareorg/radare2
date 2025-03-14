/* radare - LGPL - Copyright 2023 - terorie */

#include <r_lib.h>
#include <r_bin.h>
#include "coff/xcoff64.h"

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	bf->bo->bin_obj = r_bin_xcoff64_new_buf (buf, bf->rbin->options.verbose);
	return bf->bo->bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_xcoff64_free ((struct r_bin_xcoff64_obj*)bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	return NULL;
}

static bool _fill_bin_symbol(RBin *rbin, struct r_bin_xcoff64_obj *bin, int idx, RBinSymbol **sym) {
	RBinSymbol *ptr = *sym;
	struct xcoff64_symbol *s = NULL;
	if (idx < 0 || idx > bin->hdr.f_nsyms) {
		return false;
	}
	if (!bin->symbols) {
		return false;
	}
	s = &bin->symbols[idx].sym;
	char *coffname = r_xcoff64_symbol_name (bin, s->n_offset);
	if (!coffname) {
		return false;
	}
	ptr->name = r_bin_name_new_from (coffname);
	ptr->forwarder = "NONE";
	ptr->bind = R_BIN_BIND_LOCAL_STR;
	ptr->is_imported = false;

	switch (s->n_sclass) {
	case COFF_SYM_CLASS_FUNCTION:
		ptr->type = R_BIN_TYPE_FUNC_STR;
		break;
	case COFF_SYM_CLASS_FILE:
		ptr->type = R_BIN_TYPE_FILE_STR;
		break;
	case COFF_SYM_CLASS_SECTION:
		ptr->type = R_BIN_TYPE_SECTION_STR;
		break;
	}

	ptr->size = 4;
	ptr->ordinal = 0;
	return true;
}

static RList *entries(RBinFile *bf) {
	struct r_bin_xcoff64_obj *obj = (struct r_bin_xcoff64_obj*)bf->bo->bin_obj;
	RList *ret;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	RBinAddr *ptr = r_xcoff64_get_entry (obj);
	if (ptr) {
		r_list_append (ret, ptr);
	}
	return ret;
}

/* parse_section_flags: parses the scn_hdr flags field and returns a "type" string (rodata).
 * Also writes permission bits out to perm. Permission depends on the file magic. */
static inline const char *parse_section_flags(ut32 i, ut32 *perm, ut16 magic) {
	switch (i & 0xFFFF) {
	case XCOFF_SCN_TYPE_TEXT:
		switch (magic) {
		case XCOFF32_FILE_MACHINE_U800WR:
		case XCOFF32_FILE_MACHINE_U802WR:
			*perm |= R_PERM_R|R_PERM_W|R_PERM_X;
			break;
		default:
			*perm |= R_PERM_R|R_PERM_X;
			break;
		}
		return "TEXT";
	case XCOFF_SCN_TYPE_DATA:
	case XCOFF_SCN_TYPE_TDATA:
		*perm |= R_PERM_R|R_PERM_W;
		return "DATA";
	case XCOFF_SCN_TYPE_BSS:
	case XCOFF_SCN_TYPE_TBSS:
		*perm |= R_PERM_R|R_PERM_W;
		return "BSS";
	case XCOFF_SCN_TYPE_LOADER:
		return "LOADER";
	case XCOFF_SCN_TYPE_DEBUG:
		return "DEBUG";
	case XCOFF_SCN_TYPE_DWARF:
		return "DWARF";
	case XCOFF_SCN_TYPE_EXCEPT:
		return "EXCEPT";
	case XCOFF_SCN_TYPE_INFO:
		return "INFO";
	case XCOFF_SCN_TYPE_TYPCHK:
		return "TYPCHK";
	case XCOFF_SCN_TYPE_OVRFLO:
		return "OVRFLO";
	case XCOFF_SCN_TYPE_REG:
		return "REG";
	case XCOFF_SCN_TYPE_PAD:
		return "PAD";
	default:
		return "";
	}
}

static RList *sections(RBinFile *bf) {
	char *tmp = NULL;
	size_t i;
	RBinSection *ptr = NULL;
	struct r_bin_xcoff64_obj *obj = (struct r_bin_xcoff64_obj*)bf->bo->bin_obj;

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	if (!ret) {
		return NULL;
	}
	if (obj && obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			tmp = r_str_ndup (obj->scn_hdrs[i].s_name, 8);
			if (!tmp) {
				r_list_free (ret);
				return NULL;
			}
			ptr = R_NEW0 (RBinSection);
			if (!ptr) {
				free (tmp);
				return ret;
			}
			ptr->name = tmp;
			if (strstr (ptr->name, "data")) {
				ptr->is_data = true;
			}
			ptr->size = obj->scn_hdrs[i].s_size;
			ptr->vsize = obj->scn_hdrs[i].s_size;
			ptr->paddr = obj->scn_hdrs[i].s_scnptr;
			ptr->perm = 0;
			ptr->type = parse_section_flags (obj->scn_hdrs[i].s_flags, &ptr->perm, obj->hdr.f_magic);
			if (obj->scn_va) {
				ptr->vaddr = obj->scn_va[i];
			}
			ptr->add = true;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static RList *symbols(RBinFile *bf) {
	int i;
	RBinSymbol *ptr = NULL;
	struct r_bin_xcoff64_obj *obj = (struct r_bin_xcoff64_obj*)bf->bo->bin_obj;
	RList *ret = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	if (obj->symbols) {
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			if (_fill_bin_symbol (bf->rbin, obj, i, &ptr)) {
				r_list_append (ret, ptr);
				ht_up_insert (obj->sym_ht, (ut64)i, ptr);
			} else {
				free (ptr);
			}
			i += obj->symbols[i].sym.n_numaux;
		}
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	struct r_bin_xcoff64_obj *obj = (struct r_bin_xcoff64_obj*)bf->bo->bin_obj;

	ret->file = bf->file? strdup (bf->file): NULL;
	ret->rclass = strdup ("xcoff64");
	ret->bclass = strdup ("xcoff64");
	ret->type = strdup ("XCOFF64 (Executable file)");
	ret->os = strdup ("aix");
	ret->subsystem = strdup ("unknown");
	ret->big_endian = obj->endian;
	ret->has_va = true;
	ret->dbg_info = 0;
	ret->has_lit = true;

	switch (obj->hdr.f_magic) {
	case XCOFF64_FILE_MACHINE_U803TOC:
	case XCOFF64_FILE_MACHINE_U803XTOC:
	case XCOFF64_FILE_MACHINE_U64:
		ret->machine = strdup ("ppc");
		ret->arch = strdup ("ppc");
		ret->big_endian = true;
		ret->bits = 64;
		break;
	default:
		ret->machine = strdup ("unknown");
	}

	return ret;
}

static RList *fields(RBinFile *bf) {
	return NULL;
}

static ut64 size(RBinFile *bf) {
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 tmp[24];
	int r = r_buf_read_at (b, 0, tmp, sizeof (tmp));
	return r >= 24 && r_xcoff64_supported_arch (tmp);
}

RBinPlugin r_bin_plugin_xcoff64 = {
	.meta = {
		.name = "xcoff64",
		.author = "terorie",
		.desc = "xcoff64 r_bin plugin",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.fields = &fields,
	.size = &size
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xcoff64,
	.version = R2_VERSION
};
#endif
