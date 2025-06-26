/* radare - LGPL - Copyright 2014-2025 - Fedor Sakharov */

#include <r_bin.h>
#include <sdb/ht_uu.h>

#include "coff/coff.h"

static Sdb* get_sdb(RBinFile *bf) {
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj *) R_UNWRAP3 (bf, bo, bin_obj);
	return bin? bin->kv: NULL;
}

static bool r_coff_is_stripped(struct r_bin_coff_obj *obj) {
	ut16 flags = obj->type == COFF_TYPE_BIGOBJ? obj->bigobj_hdr.f_flags: obj->hdr.f_flags;
	return !!(flags & (COFF_FLAGS_TI_F_RELFLG | COFF_FLAGS_TI_F_LNNO | COFF_FLAGS_TI_F_LSYMS));
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	bf->bo->bin_obj = r_bin_coff_new_buf (buf, bf->rbin->options.verbose);
	return bf->bo->bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_coff_free ((struct r_bin_coff_obj *)bf->bo->bin_obj);
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	return NULL;
}

#define DTYPE_IS_FUNCTION(type)	(COFF_SYM_GET_DTYPE (type) == COFF_SYM_DTYPE_FUNCTION)

static bool _fill_bin_symbol(RBin *rbin, struct r_bin_coff_obj *bin, int idx, RBinSymbol **sym) {
	RBinSymbol *ptr = *sym;
	// struct coff_symbol *s = NULL;
	void *s = NULL;
	struct coff_scn_hdr *sc_hdr = NULL;
	ut32 f_nsyms = 0;
	ut32 f_nscns = 0;
	ut32 n_scnum = 0;
	ut32 n_value = 0;
	ut16 n_type = 0;
	ut8 n_sclass = 0;
	char *n_name;

	if ((bin->type == COFF_TYPE_BIGOBJ && !bin->bigobj_symbols) || (bin->type != COFF_TYPE_BIGOBJ && !bin->symbols)) {
		return false;
	}

	if (bin->type == COFF_TYPE_BIGOBJ) {
		f_nsyms = bin->bigobj_hdr.f_nsyms;
		f_nscns = bin->bigobj_hdr.f_nscns;
		n_scnum = bin->bigobj_symbols[idx].n_scnum;
		n_value = bin->bigobj_symbols[idx].n_value;
		n_type = bin->bigobj_symbols[idx].n_type;
		n_sclass = bin->bigobj_symbols[idx].n_sclass;
		n_name = bin->bigobj_symbols[idx].n_name;
		s = &bin->bigobj_symbols[idx];
	} else {
		f_nsyms = bin->hdr.f_nsyms;
		f_nscns = bin->hdr.f_nscns;
		n_scnum = bin->symbols[idx].n_scnum;
		n_value = bin->symbols[idx].n_value;
		n_type = bin->symbols[idx].n_type;
		n_sclass = bin->symbols[idx].n_sclass;
		n_name = bin->symbols[idx].n_name;
		s = &bin->symbols[idx];
	}

	if (idx < 0 || idx > f_nsyms) {
		return false;
	}

	char *coffname = r_coff_symbol_name (bin, s);
	if (!coffname) {
		return false;
	}
	ptr->name = r_bin_name_new_from (coffname);
	ptr->forwarder = "NONE";
	ptr->bind = R_BIN_BIND_LOCAL_STR;
	ptr->is_imported = false;
	if (n_scnum < f_nscns + 1 && n_scnum > 0 && bin->scn_hdrs) {
		//first index is 0 that is why -1
		sc_hdr = &bin->scn_hdrs[n_scnum - 1];
		ptr->paddr = sc_hdr->s_scnptr + n_value;
		if (bin->scn_va) {
			ptr->vaddr = bin->scn_va[n_scnum - 1] + n_value;
		}
	}

	switch (n_sclass) {
	case COFF_SYM_CLASS_FUNCTION:
		ptr->type = R_BIN_TYPE_FUNC_STR;
		break;
	case COFF_SYM_CLASS_FILE:
		ptr->type = R_BIN_TYPE_FILE_STR;
		break;
	case COFF_SYM_CLASS_SECTION:
		ptr->type = R_BIN_TYPE_SECTION_STR;
		break;
	case COFF_SYM_CLASS_EXTERNAL:
		if (n_scnum == COFF_SYM_SCNUM_UNDEF) {
			ptr->is_imported = true;
			ptr->paddr = ptr->vaddr = UT64_MAX;
			ptr->bind = "NONE";
		} else {
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
		}
		ptr->type = (DTYPE_IS_FUNCTION (n_type) || !strcmp (coffname, "main"))
			? R_BIN_TYPE_FUNC_STR
			: R_BIN_TYPE_UNKNOWN_STR;
		break;
	case COFF_SYM_CLASS_STATIC:
		if (n_scnum == COFF_SYM_SCNUM_ABS) {
			ptr->type = "ABS";
			ptr->paddr = ptr->vaddr = UT64_MAX;
			ptr->name = r_bin_name_new_from (r_str_newf ("%s-0x%08x", coffname, n_value));
			if (ptr->name) {
				R_FREE (coffname);
			} else {
				ptr->name = r_bin_name_new_from (coffname);
			}
		} else if (sc_hdr && !memcmp (sc_hdr->s_name, n_name, 8)) {
			ptr->type = R_BIN_TYPE_SECTION_STR;
		} else {
			ptr->type = DTYPE_IS_FUNCTION (n_type)
				? R_BIN_TYPE_FUNC_STR
				: R_BIN_TYPE_UNKNOWN_STR;
		}
		break;
	default:
		{
		r_strf_var (ivar, 32, "%i", n_sclass);
		ptr->type = r_str_constpool_get (&rbin->constpool, ivar);
		}
		break;
		}
	ptr->size = 4;
	ptr->ordinal = 0;
	return true;
}

static bool is_imported_symbol(struct r_bin_coff_obj *bin, int idx) {
	ut32 n_scnum = bin->type == COFF_TYPE_BIGOBJ? bin->bigobj_symbols[idx].n_scnum: bin->symbols[idx].n_scnum;
	ut32 n_sclass = bin->type == COFF_TYPE_BIGOBJ? bin->bigobj_symbols[idx].n_sclass: bin->symbols[idx].n_sclass;
	return n_scnum == COFF_SYM_SCNUM_UNDEF && n_sclass == COFF_SYM_CLASS_EXTERNAL;
}

static RBinImport *_fill_bin_import(struct r_bin_coff_obj *bin, int idx) {
	RBinImport *ptr = R_NEW0 (RBinImport);
	void *s = NULL;
	ut16 n_type = 0;
	ut32 f_nsyms = bin->type == COFF_TYPE_BIGOBJ? bin->bigobj_hdr.f_nsyms: bin->hdr.f_nsyms;
	if (!ptr || idx < 0 || idx > f_nsyms) {
		free (ptr);
		return NULL;
	}
	if (bin->type == COFF_TYPE_BIGOBJ) {
		s = &bin->bigobj_symbols[idx];
		n_type = bin->bigobj_symbols[idx].n_type;
	} else {
		s = &bin->symbols[idx];
		n_type = bin->symbols[idx].n_type;
	}
	if (!is_imported_symbol (bin, idx)) {
		free (ptr);
		return NULL;
	}
	char *coffname = r_coff_symbol_name (bin, s);
	if (!coffname) {
		free (ptr);
		return NULL;
	}
	ptr->name = r_bin_name_new_from (coffname);
	ptr->bind = "NONE";
	ptr->type = DTYPE_IS_FUNCTION (n_type)
		? R_BIN_TYPE_FUNC_STR
		: R_BIN_TYPE_UNKNOWN_STR;
	return ptr;
}

static bool xcoff_is_imported_symbol(struct xcoff32_ldsym *s) {
	return XCOFF_LDSYM_FLAGS (s->l_smtype) == XCOFF_LDSYM_FLAG_IMPORT;
}

static RBinImport *_xcoff_fill_bin_import(struct r_bin_coff_obj *bin, int idx) {
	RBinImport *ptr = R_NEW0 (RBinImport);
	if (!ptr || idx < 0 || idx > bin->x_ldhdr.l_nsyms) {
		free (ptr);
		return NULL;
	}
	struct xcoff32_ldsym *s = &bin->x_ldsyms[idx];
	if (!xcoff_is_imported_symbol (s)) {
		free (ptr);
		return NULL;
	}
	char *sn = r_str_ndup (s->l_name, 8);
	if (R_STR_ISNOTEMPTY (sn)) {
		ptr->name = r_bin_name_new (sn);
	}
	free (sn);
	if (!ptr->name) {
		free (ptr);
		return NULL;
	}
	switch (s->l_smclas) {
	case XCOFF_LDSYM_CLASS_FUNCTION:
		ptr->type = R_BIN_TYPE_FUNC_STR;
		break;
	default:
		ptr->type = R_BIN_TYPE_UNKNOWN_STR;
		break;
	}
	return ptr;
}

static RList *entries(RBinFile *bf) {
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->bo->bin_obj;
	RList *ret;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	RBinAddr *ptr = r_coff_get_entry (obj);
	if (ptr) {
		r_list_append (ret, ptr);
	}
	return ret;
}

// XXX the string must be heap allocated because these are bitfields
static const char *coff_section_type_tostring(int i) {
	if (i & COFF_STYP_TEXT) {
		return "TEXT";
	}
	if (i & COFF_STYP_DATA) {
		return "DATA";
	}
	if (i & COFF_STYP_DATA) {
		return "BSS";
	}
	return "MAP";
#if 0
	eprintf ("---> %x\n", i);
	if (i & COFF_FLAGS_TI_F_EXEC) {
		return "EXEC";
	}
	if (i & COFF_FLAGS_TI_F_RELFLG) {
		return "RELFLG";
	}
	if (i & COFF_FLAGS_TI_F_LNNO) {
		return "LNNO";
	}
	if (i & COFF_FLAGS_TI_F_LSYMS) {
		return "LSYMS";
	}
	if (i & COFF_FLAGS_TI_F_BIG) {
		return "BIG";
	}
	if (i & COFF_FLAGS_TI_F_LITTLE) {
		return "LITTLE";
	}
#endif
	return "MAP";
}

static const char *xcoff_section_type_tostring(int i) {
	switch (i & 0xFFFF) {
	case XCOFF_SCN_TYPE_DWARF:
		return "DWARF";
	case XCOFF_SCN_TYPE_TEXT:
		return "TEXT";
	case XCOFF_SCN_TYPE_DATA:
		return "DATA";
	case XCOFF_SCN_TYPE_BSS:
		return "BSS";
	case XCOFF_SCN_TYPE_EXCEPT:
		return "EXCEPT";
	case XCOFF_SCN_TYPE_LOADER:
		return "LOADER";
	}
	return NULL;
}

// XXX: This should probably be generic
static void truncate_section(RBinSection *ptr, const struct r_bin_coff_obj *obj) {
	// The section size might exceed the binary size, which causes
	// DoS problems via unbounded memory allocations.  Thus, truncate
	// section size.
	ut64 file_start = (ut64)ptr->paddr;
	ut64 file_end = file_start + (ut64)ptr->size;
	// file_end in [0,2^33) as both arguments in [0,2^32), thus no overflow.
	if (R_UNLIKELY (file_start > obj->size)) {
		R_LOG_WARN ("File range of section \"%s\" is fully out of bounds (%#" PRIx64 "..%#" PRIx64 "), but file size is %#" PRIx64 ")",
			    ptr->name, file_start, file_end, obj->size);
		ptr->size = 0;
	} else if (R_UNLIKELY (file_end > obj->size)) {
		R_LOG_WARN ("File range of section \"%s\" is partially out of bounds (%#" PRIx64 "..%#" PRIx64 "), but file size is %#" PRIx64 ")",
			    ptr->name, file_start, file_end, obj->size);
		ptr->size = obj->size - file_start;
	}
}

static void coff_section(RBinSection *ptr, const struct r_bin_coff_obj *obj, size_t i) {
	if (strstr (ptr->name, "data")) {
		ptr->is_data = true;
	}
	ptr->size = obj->scn_hdrs[i].s_size;
	ptr->vsize = obj->scn_hdrs[i].s_size;
	ptr->paddr = obj->scn_hdrs[i].s_scnptr;
	ptr->type = coff_section_type_tostring (obj->scn_hdrs[i].s_flags);
	if (obj->scn_va) {
		ptr->vaddr = obj->scn_va[i];
	}
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
}

static void xcoff_section(RBinSection *ptr, const struct r_bin_coff_obj *obj, size_t i) {
	ptr->size = obj->scn_hdrs[i].s_size;
	ptr->vsize = obj->scn_hdrs[i].s_size;
	ptr->paddr = obj->scn_hdrs[i].s_scnptr;
	ptr->vaddr = obj->scn_hdrs[i].s_vaddr;
	ptr->type = xcoff_section_type_tostring (obj->scn_hdrs[i].s_flags & 0xFFFF);
	ptr->add = true;
	switch (obj->scn_hdrs[i].s_flags & 0xFFFF) {
	case XCOFF_SCN_TYPE_TEXT:
		ptr->perm = R_PERM_R | R_PERM_X;
		break;
	case XCOFF_SCN_TYPE_DATA:
	case XCOFF_SCN_TYPE_BSS:
		ptr->perm = R_PERM_R | R_PERM_W;
		break;
	}
}

static RList *sections(RBinFile *bf) {
	char *tmp = NULL;
	size_t i;
	RBinSection *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->bo->bin_obj;

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	if (!ret) {
		return NULL;
	}
	ut32 f_nscns = obj->type == COFF_TYPE_BIGOBJ? obj->bigobj_hdr.f_nscns: obj->hdr.f_nscns;
	if (f_nscns < 1) {
		// return NULL;
		f_nscns &= 0xffff;
	}
	if (obj && obj->scn_hdrs) {
		for (i = 0; i < f_nscns; i++) {
			tmp = r_coff_symbol_name (obj, &obj->scn_hdrs[i]);
			if (!tmp) {
				// causes UAF and losses the whole section list if one is wrong
				// r_list_free (ret);
				continue;
			}
			//IO does not like sections with the same name append idx
			//since it will update it
			ptr = R_NEW0 (RBinSection);
			if (!ptr) {
				free (tmp);
				return ret;
			}
			ptr->name = r_str_newf ("%s-%u", tmp, (unsigned int)i);
			free (tmp);
			if (obj->type == COFF_TYPE_XCOFF) {
				xcoff_section (ptr, obj, i);
			} else {
				coff_section (ptr, obj, i);
			}
			truncate_section (ptr, obj);
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static RList *symbols(RBinFile *bf) {
	int i;
	RBinSymbol *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->bo->bin_obj;
	RList *ret = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	if ((obj->type == COFF_TYPE_BIGOBJ && obj->bigobj_symbols) || obj->symbols) {
		ut32 f_nsyms = 0;
		ut32 symbol_size = 0;
		void *symbols;
		size_t numaux_offset = 0;

		if (obj->type == COFF_TYPE_BIGOBJ) {
			f_nsyms = obj->bigobj_hdr.f_nsyms;
			symbol_size = sizeof (struct coff_bigobj_symbol);
			symbols = obj->bigobj_symbols;
			numaux_offset = offsetof (struct coff_bigobj_symbol, n_numaux);
		} else {
			f_nsyms = obj->hdr.f_nsyms;
			symbol_size = sizeof (struct coff_symbol);
			symbols = obj->symbols;
			numaux_offset = offsetof (struct coff_symbol, n_numaux);
		}

		for (i = 0; i < f_nsyms; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			if (_fill_bin_symbol (bf->rbin, obj, i, &ptr)) {
				r_list_append (ret, ptr);
				ht_up_insert (obj->sym_ht, (ut64)i, ptr);
			} else {
				free (ptr);
			}

			ut8 n_numaux = *((ut8 *)symbols + i * symbol_size + numaux_offset);
			i += n_numaux;
		}
	}
	return ret;
}

static RList *imports(RBinFile *bf) {
	int i;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->bo->bin_obj;
	RList *ret = r_list_newf ((RListFree)r_bin_import_free);
	if (!ret) {
		return NULL;
	}
	int ord = 0;
	if (obj->x_ldsyms) {
		for (i = 0; i < obj->x_ldhdr.l_nsyms; i++) {
			RBinImport *ptr = _xcoff_fill_bin_import (obj, i);
			if (ptr) {
				ptr->ordinal = ord++;
				r_list_append (ret, ptr);
				ht_up_insert (obj->imp_ht, (ut64)i, ptr);
			}
		}
	} else if ((obj->type == COFF_TYPE_BIGOBJ && obj->bigobj_symbols) || obj->symbols) {
		ut32 f_nsyms = 0;
		ut32 symbol_size = 0;
		void *symbols;
		size_t numaux_offset = 0;

		if (obj->type == COFF_TYPE_BIGOBJ) {
			f_nsyms = obj->bigobj_hdr.f_nsyms;
			symbol_size = sizeof (struct coff_bigobj_symbol);
			symbols = obj->bigobj_symbols;
			numaux_offset = offsetof (struct coff_bigobj_symbol, n_numaux);
		} else {
			f_nsyms = obj->hdr.f_nsyms;
			symbol_size = sizeof (struct coff_symbol);
			symbols = obj->symbols;
			numaux_offset = offsetof (struct coff_symbol, n_numaux);
		}
		for (i = 0; i < f_nsyms; i++) {
			RBinImport *ptr = _fill_bin_import (obj, i);
			if (ptr) {
				ptr->ordinal = ord++;
				r_list_append (ret, ptr);
				ht_up_insert (obj->imp_ht, (ut64)i, ptr);
			}
			ut8 n_numaux = *((ut8 *)symbols + i * symbol_size + numaux_offset);
			i += n_numaux;
		}
	}
	return ret;
}

static RList *libs(RBinFile *bf) {
	return NULL;
}

static ut32 _read_le32(RBin *rbin, ut64 addr) {
	ut8 data[4] = {0};
	if (!rbin->iob.read_at (rbin->iob.io, addr, data, sizeof (data))) {
		return UT32_MAX;
	}
	return r_read_le32 (data);
}

static ut16 _read_le16(RBin *rbin, ut64 addr) {
	ut8 data[2] = {0};
	if (!rbin->iob.read_at (rbin->iob.io, addr, data, sizeof (data))) {
		return UT16_MAX;
	}
	return r_read_le16 (data);
}

#define BYTES_PER_IMP_RELOC 8

static RList *_relocs_list(RBin *rbin, struct r_bin_coff_obj *co, bool patch, ut64 imp_map) {
	R_RETURN_VAL_IF_FAIL (rbin && co, NULL);
	if (!co->scn_hdrs) {
		return NULL;
	}
	int j, i = 0;
	ut32 f_nscns = (co->type == COFF_TYPE_BIGOBJ)
		? co->bigobj_hdr.f_nscns: co->hdr.f_nscns;
	const bool patch_imports = patch && (imp_map != UT64_MAX);
	HtUU *imp_vaddr_ht = patch_imports? ht_uu_new0 (): NULL;
	if (patch_imports && !imp_vaddr_ht) {
		return NULL;
	}
	RList *list_rel = r_list_newf (free); // r_bin_reloc_free
	for (i = 0; i < f_nscns; i++) {
		if (!co->scn_hdrs[i].s_nreloc) {
			continue;
		}
		int len = 0, size = co->scn_hdrs[i].s_nreloc * sizeof (struct coff_reloc);
		if (size < 0) {
			break;
		}
		struct coff_reloc *rel = calloc (1, size + sizeof (struct coff_reloc));
		if (!rel) {
			break;
		}
		if (co->scn_hdrs[i].s_relptr > co->size \
			|| co->scn_hdrs[i].s_relptr + size > co->size) {
			free (rel);
			break;
		}
		len = r_buf_read_at (co->b, co->scn_hdrs[i].s_relptr, (ut8*)rel, size);
		if (len != size) {
			free (rel);
			break;
		}
		for (j = 0; j < co->scn_hdrs[i].s_nreloc; j++) {
			RBinSymbol *symbol = (RBinSymbol *)ht_up_find (co->sym_ht, (ut64)rel[j].r_symndx, NULL);
			if (!symbol) {
				continue;
			}
			RBinReloc *reloc = R_NEW0 (RBinReloc);
			reloc->symbol = symbol;
			reloc->paddr = co->scn_hdrs[i].s_scnptr + rel[j].r_vaddr;
			if (co->scn_va) {
				reloc->vaddr = co->scn_va[i] + rel[j].r_vaddr;
			}
			reloc->type = rel[j].r_type;

			ut64 sym_vaddr = symbol->vaddr;
			if (symbol->is_imported) {
				reloc->import = (RBinImport *)ht_up_find (co->imp_ht, (ut64)rel[j].r_symndx, NULL);
				if (patch_imports) {
					bool found;
					sym_vaddr = ht_uu_find (imp_vaddr_ht, (ut64)rel[j].r_symndx, &found);
					if (!found) {
						sym_vaddr = imp_map;
						imp_map += BYTES_PER_IMP_RELOC;
						ht_uu_insert (imp_vaddr_ht, (ut64)rel[j].r_symndx, sym_vaddr);
						symbol->vaddr = sym_vaddr;
					}
				}
			}

			reloc->ntype = rel[j].r_type;
			if (sym_vaddr) {
				int plen = 0;
				ut8 patch_buf[8];
				ut16 magic = co->type == COFF_TYPE_BIGOBJ? co->bigobj_hdr.f_magic: co->hdr.f_magic;
				switch (magic) {
				case COFF_FILE_MACHINE_I386:
					switch (rel[j].r_type) {
					case COFF_REL_I386_DIR32:
						reloc->type = R_BIN_RELOC_32;
						r_write_le32 (patch_buf, (ut32)sym_vaddr);
						plen = 4;
						break;
					case COFF_REL_I386_REL32:
						reloc->type = R_BIN_RELOC_32;
						reloc->additive = 1;
						ut64 data = _read_le32 (rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc->addend = data;
						data += sym_vaddr - reloc->vaddr - 4;
						r_write_le32 (patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_AMD64:
					switch (rel[j].r_type) {
					case COFF_REL_AMD64_REL32:
						reloc->type = R_BIN_RELOC_32;
						reloc->additive = 1;
						ut64 data = _read_le32 (rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc->addend = data;
						data += sym_vaddr - reloc->vaddr - 4;
						r_write_le32 (patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARMNT:
					switch (rel[j].r_type) {
					case COFF_REL_ARM_BRANCH24T:
					case COFF_REL_ARM_BLX23T:
						reloc->type = R_BIN_RELOC_32;
						ut16 hiword = _read_le16 (rbin, reloc->vaddr);
						if (hiword == UT16_MAX) {
							break;
						}
						ut16 loword = _read_le16 (rbin, reloc->vaddr + 2);
						if (loword == UT16_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc->vaddr - 4;
						if (dst & 1) {
							break;
						}
						loword |= (ut16)(dst >> 1) & 0x7ff;
						hiword |= (ut16)(dst >> 12) & 0x7ff;
						r_write_le16 (patch_buf, hiword);
						r_write_le16 (patch_buf + 2, loword);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARM64:
					switch (rel[j].r_type) {
					case COFF_REL_ARM64_BRANCH26:
						reloc->type = R_BIN_RELOC_32;
						ut32 data = _read_le32 (rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc->vaddr;
						data |= (ut32)((dst >> 2) & 0x3ffffffULL);
						r_write_le32 (patch_buf, data);
						plen = 4;
						break;
					}
					break;
				}
				if (patch && plen) {
					rbin->iob.overlay_write_at (rbin->iob.io, reloc->vaddr, patch_buf, plen);
					if (symbol->is_imported) {
						reloc->vaddr = sym_vaddr;
					}
				}
			}
			r_list_append (list_rel, reloc);
		}
		free (rel);
	}
	ht_uu_free (imp_vaddr_ht);
	return list_rel;
}

static RList *relocs(RBinFile *bf) {
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj*)bf->bo->bin_obj;
	return _relocs_list (bf->rbin, bin, false, UT64_MAX);
}

static RList *patch_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && bf->rbin->iob.io && bf->rbin->iob.io->desc, NULL);
	RBin *b = bf->rbin;
	RBinObject *bo = r_bin_cur_object (b);
	RIO *io = bf->rbin->iob.io;
	void *symbols = NULL;
	if (!bo || !bo->bin_obj) {
		return NULL;
	}
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj*)bo->bin_obj;
	if (bin->hdr.f_flags & COFF_FLAGS_TI_F_EXEC) {
		return NULL;
	}

	size_t nimports = 0;
	int i;
	ut32 f_nsyms = 0;
	size_t symbol_size = 0;
	size_t numaux_offset = 0;
	if ((bin->type == COFF_TYPE_BIGOBJ && bin->bigobj_symbols) || bin->symbols) {

		if (bin->type == COFF_TYPE_BIGOBJ) {
			symbols = bin->bigobj_symbols;
			f_nsyms = bin->bigobj_hdr.f_nsyms;
			symbol_size = sizeof (struct coff_bigobj_symbol);
		} else {
			symbols = bin->symbols;
			f_nsyms = bin->hdr.f_nsyms;
			symbol_size = sizeof (struct coff_symbol);
		}

		for (i = 0; i < f_nsyms; i++) {
			if (is_imported_symbol (bin, i)) {
				nimports++;
			}
			ut8 n_numaux = *((ut8 *)symbols + i * symbol_size + numaux_offset);
			i += n_numaux;
		}
	}
	ut64 m_vaddr = UT64_MAX;
	if (nimports) {
		ut64 offset = 0;
		RIOBank *bank = b->iob.bank_get (io, io->bank);
		RListIter *iter;
		RIOMapRef *mapref;
		r_list_foreach (bank->maprefs, iter, mapref) {
			RIOMap *map = b->iob.map_get (io, mapref->id);
			if (r_io_map_end (map) > offset) {
				offset = r_io_map_end (map);
			}
		}
		m_vaddr = R_ROUND (offset, 16);
		ut64 size = nimports * BYTES_PER_IMP_RELOC;
		char *muri = r_str_newf ("malloc://%" PFMT64u, size);
		RIODesc *desc = b->iob.open_at (io, muri, R_PERM_R, 0664, m_vaddr);
		free (muri);
		if (!desc) {
			return NULL;
		}

		RIOMap *map = b->iob.map_get_at (io, m_vaddr);
		if (!map) {
			return NULL;
		}
		map->name = strdup (".imports.r2");
	}

	return _relocs_list (b, bin, true, m_vaddr);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)bf->bo->bin_obj;

	ret->file = bf->file? strdup (bf->file): NULL;
	/* XXX also set bclass or class to xcoff? */
	ret->rclass = strdup ("coff");
	ret->bclass = strdup ("coff");
	ut16 magic = obj->type == COFF_TYPE_BIGOBJ? obj->bigobj_hdr.f_magic: obj->hdr.f_magic;
	ut16 flags = obj->type == COFF_TYPE_BIGOBJ? obj->bigobj_hdr.f_flags: obj->hdr.f_flags;
	switch (magic) {
	case COFF_FILE_MACHINE_ALPHA:
	case COFF_FILE_MACHINE_POWERPC:
	case COFF_FILE_MACHINE_R4000:
		ret->type = strdup ("COFF (Object file)");
		break;
	case XCOFF32_FILE_MACHINE_U800WR:
	case XCOFF32_FILE_MACHINE_U800RO:
	case XCOFF32_FILE_MACHINE_U800TOC:
	case XCOFF32_FILE_MACHINE_U802WR:
	case XCOFF32_FILE_MACHINE_U802RO:
		ret->type = strdup ("XCOFF32");
		break;
	case XCOFF32_FILE_MACHINE_U802TOC:
		ret->type = strdup ("XCOFF32 (Executable file, RO text, TOC)");
		break;
	case XCOFF64_FILE_MACHINE_U803TOC:
	case XCOFF64_FILE_MACHINE_U803XTOC:
	case XCOFF64_FILE_MACHINE_U64:
		ret->type = strdup ("XCOFF64");
		break;
	default:
		ret->type = strdup ("COFF (Executable file)");
		break;
	}
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->big_endian = obj->endian;
	ret->has_va = true;
	ret->dbg_info = 0;
	ret->has_lit = true;

	if (r_coff_is_stripped (obj)) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	} else {
		if (!(flags & COFF_FLAGS_TI_F_RELFLG)) {
			ret->dbg_info |= R_BIN_DBG_RELOCS;
		}
		if (!(flags & COFF_FLAGS_TI_F_LNNO)) {
			ret->dbg_info |= R_BIN_DBG_LINENUMS;
		}
		if (!(flags & COFF_FLAGS_TI_F_EXEC)) {
			ret->dbg_info |= R_BIN_DBG_SYMS;
		}
	}

	switch (magic) {
	case COFF_FILE_MACHINE_R4000:
 	case COFF_FILE_MACHINE_MIPS16:
 	case COFF_FILE_MACHINE_MIPSFPU:
 	case COFF_FILE_MACHINE_MIPSFPU16:
 		ret->machine = strdup ("mips");
 		ret->arch = strdup ("mips");
 		ret->bits = 32;
 		break;
	case COFF_FILE_MACHINE_I386:
		ret->machine = strdup ("i386");
		ret->arch = strdup ("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_ARM64:
		ret->machine = strdup ("aarch64");
		ret->arch = strdup ("arm");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_THUMB:
 		ret->machine = strdup ("arm");
 		ret->arch = strdup ("arm");
 		ret->bits = 16;
 		break;
	case COFF_FILE_MACHINE_ARM:
		ret->machine = strdup ("ARM");
		ret->arch = strdup ("arm");
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
	case COFF_FILE_MACHINE_AMD29K:
		ret->cpu = strdup ("29000");
		ret->machine = strdup ("amd29k");
		ret->arch = strdup ("amd29k");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_ARMNT:
		ret->machine = strdup ("arm");
		ret->arch = strdup ("arm");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_SH3:
 	case COFF_FILE_MACHINE_SH3DSP:
 	case COFF_FILE_MACHINE_SH4:
 	case COFF_FILE_MACHINE_SH5:
 		ret->machine = strdup ("sh");
 		ret->arch = strdup ("sh");
 		ret->bits = 32;
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
	case COFF_FILE_MACHINE_ALPHA:
		ret->machine = strdup ("alpha");
		ret->arch = strdup ("alpha");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_POWERPC:
		ret->machine = strdup ("RS/6000");
		ret->cpu = strdup ("ppc");
		ret->arch = strdup ("ppc");
		ret->bits = 32;
		break;
	case XCOFF32_FILE_MACHINE_U800WR:
	case XCOFF32_FILE_MACHINE_U800RO:
	case XCOFF32_FILE_MACHINE_U800TOC:
	case XCOFF32_FILE_MACHINE_U802WR:
	case XCOFF32_FILE_MACHINE_U802RO:
	case XCOFF32_FILE_MACHINE_U802TOC:
		ret->machine = strdup ("RS/6000");
		ret->cpu = strdup ("ppc");
		ret->arch = strdup ("ppc");
		ret->bits = 32;
		ret->os = strdup ("AIX");
		break;
	default:
		ret->machine = strdup ("unknown");
	}

	return ret;
}

static bool check_coff_bigobj(RBinFile *bf, RBuffer *buf) {
	ut8 tmp[56];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));

	if (r >= 56) {
		ut16 sig1 = r_read_le16 (tmp);

		if (sig1 != COFF_FILE_MACHINE_UNKNOWN) {
			return false;
		}

		ut16 sig2 = r_read_le16 (&tmp[2]);
		if (sig2 != 0xffff) {
			return false;
		}

		ut16 version = r_read_le16 (&tmp[4]);
		if (version != 2) {
			return false;
		}

		if (!r_coff_supported_arch (&tmp[6])) {
			return false;
		}

		// Finally, check the magic number
		if (memcmp (coff_bigobj_magic, &tmp[12], 16) != 0) {
			return false;
		}

		return true;
	}

	return false;
}

static bool check_coff(RBinFile *bf, RBuffer *buf) {
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

	ut8 tmp[20];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	return r >= 20 && r_coff_supported_arch (tmp);
}

static bool check(RBinFile *bf, RBuffer *buf) {
	return check_coff (bf, buf) || check_coff_bigobj (bf, buf);
}

RBinPlugin r_bin_plugin_coff = {
	.meta = {
		.name = "coff",
		.author = "Fedor Sakharov",
		.desc = "Common Object File Format",
		.license = "LGPL-3.0-only",
	},
	.weak_guess = true,
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_coff,
	.version = R2_VERSION
};
#endif
