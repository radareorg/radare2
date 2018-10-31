/* radare - LGPL - Copyright 2014-2017 - Fedor Sakharov */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff/coff.h"

static Sdb* get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj *) o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}
	return NULL;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (!buf || !sz || sz == UT64_MAX) {
		return false;
	}
	RBuffer *tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	*bin_obj = r_bin_coff_new_buf (tbuf, bf->rbin->verbose);
	r_buf_free (tbuf);
	return true;
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf): 0;

	if (!bf || !bf->o) {
		return false;
	}
	return load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
}

static int destroy(RBinFile *bf) {
	r_bin_coff_free((struct r_bin_coff_obj*)bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	return NULL;
}

static bool _fill_bin_symbol(struct r_bin_coff_obj *bin, int idx, RBinSymbol **sym) {
	RBinSymbol *ptr = *sym;
	char * coffname = NULL;
	struct coff_symbol *s = NULL;
	if (idx < 0 || idx > bin->hdr.f_nsyms) {
		return false;
	}
	if (!bin->symbols) {
		return false;
	}
	s = &bin->symbols[idx];
	coffname = r_coff_symbol_name (bin, s);
	if (!coffname) {
		return false;
	}
	ptr->name = strdup (coffname);
	free (coffname);
	ptr->forwarder = r_str_const ("NONE");

	switch (s->n_sclass) {
	case COFF_SYM_CLASS_FUNCTION:
		ptr->type = r_str_const (R_BIN_TYPE_FUNC_STR);
		break;
	case COFF_SYM_CLASS_FILE:
		ptr->type = r_str_const ("FILE");
		break;
	case COFF_SYM_CLASS_SECTION:
		ptr->type = r_str_const (R_BIN_TYPE_SECTION_STR);
		break;
	case COFF_SYM_CLASS_EXTERNAL:
		ptr->type = r_str_const ("EXTERNAL");
		break;
	case COFF_SYM_CLASS_STATIC:
		ptr->type = r_str_const ("STATIC");
		break;
	default:
		ptr->type = r_str_const (sdb_fmt ("%i", s->n_sclass));
		break;
	}
	if (bin->symbols[idx].n_scnum < bin->hdr.f_nscns &&
	    bin->symbols[idx].n_scnum > 0) {
		//first index is 0 that is why -1
		ptr->paddr = bin->scn_hdrs[s->n_scnum - 1].s_scnptr + s->n_value;
	}
	ptr->size = 4;
	ptr->ordinal = 0;
	return true;
}

static RList *entries(RBinFile *bf) {
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->o->bin_obj;
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	ptr = r_coff_get_entry (obj);
	r_list_append (ret, ptr);
	return ret;
}

static RList *sections(RBinFile *bf) {
	char *tmp, *coffname = NULL;
	size_t i;
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->o->bin_obj;

	ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	if (obj && obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			free (coffname);
			tmp = r_coff_symbol_name (obj, &obj->scn_hdrs[i]);
			if (!tmp) {
				r_list_free (ret);
				return NULL;
			}
			//IO does not like sections with the same name append idx
			//since it will update it
			coffname = r_str_newf ("%s-%d", tmp, i);
			free (tmp);
			ptr = R_NEW0 (RBinSection);
			if (!ptr) {
				free (coffname);
				return ret;
			}
			strncpy (ptr->name, coffname, R_BIN_SIZEOF_STRINGS);
			if (strstr (ptr->name, "data")) {
				ptr->is_data = true;
			}
			ptr->size = obj->scn_hdrs[i].s_size;
			ptr->vsize = obj->scn_hdrs[i].s_size;
			ptr->paddr = obj->scn_hdrs[i].s_scnptr;
			ptr->add = true;
			ptr->perm = 0;
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_READ) {
				ptr->perm |= R_PERM_R;
			}
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_WRITE) {
				ptr->perm |= R_PERM_W;
			}
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_EXECUTE) {
				ptr->perm |= R_PERM_X;
			}
			r_list_append (ret, ptr);
		}
	}
	free (coffname);
	return ret;
}

static RList *symbols(RBinFile *bf) {
	int i;
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->o->bin_obj;
	if (!(ret = r_list_new ())) {
		return ret;
	}
	ret->free = free;
	if (obj->symbols) {
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			if (_fill_bin_symbol (obj, i, &ptr)) {
				r_list_append (ret, ptr);
			} else {
				free (ptr);
			}
			i += obj->symbols[i].n_numaux;
		}
	}
	return ret;
}

static RList *imports(RBinFile *bf) {
	return NULL;
}

static RList *libs(RBinFile *bf) {
	return NULL;
}

static RList *relocs(RBinFile *bf) {
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj*)bf->o->bin_obj;
	RBinReloc *reloc;
	struct coff_reloc *rel;
	int j, i = 0;
	RList *list_rel;
	list_rel = r_list_new ();
	if (!list_rel || !bin || !bin->scn_hdrs) {
		r_list_free (list_rel);
		return NULL;
	}
	for (i = 0; i < bin->hdr.f_nscns; i++) {
		if (bin->scn_hdrs[i].s_nreloc) {
			int len = 0, size = bin->scn_hdrs[i].s_nreloc * sizeof (struct coff_reloc);
			if (size < 0) {
				return list_rel;
			}
			rel = calloc (1, size + sizeof (struct coff_reloc));
			if (!rel) {
				return list_rel;
			}
			if (bin->scn_hdrs[i].s_relptr > bin->size ||
				bin->scn_hdrs[i].s_relptr + size > bin->size) {
				free (rel);
				return list_rel;
			}
			len = r_buf_read_at (bin->b, bin->scn_hdrs[i].s_relptr, (ut8*)rel, size);
			if (len != size) {
				free (rel);
				return list_rel;
			}
			for (j = 0; j < bin->scn_hdrs[i].s_nreloc; j++) {
				RBinSymbol *symbol = R_NEW0 (RBinSymbol);
				if (!symbol) {
					continue;
				}
				if (!_fill_bin_symbol (bin, rel[j].r_symndx, &symbol)) {
					free (symbol);
					continue;
				}
				reloc = R_NEW0 (RBinReloc);
				if (!reloc) {
					free (symbol);
					continue;
				}
				reloc->type = rel[j].r_type; //XXX the type if different from what r2 expects
				reloc->symbol = symbol;
				reloc->paddr = bin->scn_hdrs[i].s_scnptr + rel[j].r_vaddr;
				reloc->vaddr = reloc->paddr;
				r_list_append (list_rel, reloc);
			}
			free (rel);
		}
	}
	return list_rel;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0(RBinInfo);
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->o->bin_obj;

	ret->file = bf->file? strdup (bf->file): NULL;
	ret->rclass = strdup ("coff");
	ret->bclass = strdup ("coff");
	ret->type = strdup ("COFF (Executable file)");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->big_endian = obj->endian;
	ret->has_va = false;
	ret->dbg_info = 0;
	ret->has_lit = true;

	if (r_coff_is_stripped (obj)) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	} else {
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_RELFLG)) {
			ret->dbg_info |= R_BIN_DBG_RELOCS;
		}
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_LNNO)) {
			ret->dbg_info |= R_BIN_DBG_LINENUMS;
		}
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_EXEC)) {
			ret->dbg_info |= R_BIN_DBG_SYMS;
		}
	}

	switch (obj->hdr.f_magic) {
	case COFF_FILE_MACHINE_I386:
		ret->machine = strdup ("i386");
		ret->arch = strdup ("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD64:
		ret->machine = strdup ("AMD64");
		ret->arch = strdup ("x86");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_H8300:
		ret->machine = strdup ("H8300");
		ret->arch = strdup ("h8300");
		ret->bits = 16;
		break;
	case COFF_FILE_TI_COFF:
		switch (obj->target_id) {
		case COFF_FILE_MACHINE_TMS320C54:
			ret->machine = strdup ("c54x");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55:
			ret->machine = strdup ("c55x");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55PLUS:
			ret->machine = strdup ("c55x+");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		}
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

static bool check_bytes(const ut8 *buf, ut64 length) {
#if 0
TODO: do more checks here to avoid false positives

ut16 MACHINE
ut16 NSECTIONS
ut32 DATE
ut32 PTRTOSYMTABLE
ut32 NUMOFSYMS
ut16 OPTHDRSIZE
ut16 CHARACTERISTICS
#endif
	if (buf && length >= 20) {
		return r_coff_supported_arch (buf);
	}
	return false;
}

RBinPlugin r_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_coff,
	.version = R2_VERSION
};
#endif
