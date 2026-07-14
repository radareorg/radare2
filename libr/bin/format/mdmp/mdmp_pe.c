/* radare2 - LGPL - Copyright 2016-2018 - Davis, Alex Kornitzer */

#include <r_util.h>
#include <r_list.h>

#include "mdmp_pe.h"

static void PE_(add_tls_callbacks)(struct PE_(r_bin_pe_obj_t) *bin, RList *list) {
	int count = 0;
	PE_DWord haddr, paddr, vaddr;
	RBinAddr *ptr = NULL;

	do {
		paddr = sdb_num_getf (bin->kv, 0, "pe.tls_callback%d_paddr", count);
		if (!paddr) {
			break;
		}

		vaddr = sdb_num_getf (bin->kv, 0, "pe.tls_callback%d_vaddr", count);
		if (!vaddr) {
			break;
		}

		haddr = sdb_num_getf (bin->kv, 0, "pe.tls_callback%d_haddr", count);
		if (!haddr) {
			break;
		}
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->hpaddr = haddr;
			ptr->type = R_BIN_ENTRY_TYPE_TLS;
			r_list_append (list, ptr);
		}
		count++;
	} while (vaddr);
}

RList *PE_(r_bin_mdmp_pe_get_entrypoint) (struct PE_(r_bin_mdmp_pe_bin) * pe_bin) {
	ut64 offset;
	struct r_bin_pe_addr_t *entry = NULL;
	RBinAddr *ptr = NULL;
	RList *ret;

	if (!(entry = PE_(r_bin_pe_get_entrypoint) (pe_bin->bin))) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	if ((ptr = R_NEW0 (RBinAddr))) {
		offset = entry->vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		ptr->paddr = offset + pe_bin->paddr;
		ptr->vaddr = offset + pe_bin->vaddr;
		ptr->hpaddr = pe_bin->paddr + entry->haddr;
		ptr->type = R_BIN_ENTRY_TYPE_PROGRAM;

		r_list_append (ret, ptr);
	}

	PE_(add_tls_callbacks)
	(pe_bin->bin, ret);

	free (entry);

	return ret;
}

static inline void filter_import(ut8 *n) {
	int i;
	for (i = 0; n[i]; i++) {
		if (n[i] < 30 || n[i] >= 0x7f) {
			n[i] = 0;
			break;
		}
	}
}

void PE_(r_bin_mdmp_pe_load_imports) (struct PE_(r_bin_mdmp_pe_bin) * pe_bin, RVecRBinImport *vec) {
	RVecPEImport *imports = PE_(r_bin_pe_get_imports) (pe_bin->bin);
	if (!imports) {
		return;
	}
	RList *relocs = r_list_newf ((RListFree)r_bin_reloc_free);
	if (!relocs) {
		RVecPEImport_free (imports);
		return;
	}
	pe_bin->bin->relocs = relocs;
	struct r_bin_pe_import_t *import;
	R_VEC_FOREACH (imports, import) {
		filter_import (import->name);
		RBinImport *ptr = RVecRBinImport_emplace_back (vec);
		ptr->name = r_bin_name_new ((const char *)import->name);
		ptr->libname = *import->libname ? strdup ((const char *)import->libname) : NULL;
		ptr->bind = "NONE";
		ptr->type = R_BIN_TYPE_FUNC_STR;
		ptr->ordinal = import->ordinal;

		RBinReloc *rel = R_NEW0 (RBinReloc);
		if (!rel) {
			break;
		}
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		ut64 offset = import->vaddr;
		if (offset > pe_bin->vaddr) {
			offset -= pe_bin->vaddr;
		}
		rel->additive = 0;
		rel->import = r_bin_import_clone (ptr);
		rel->addend = 0;
		rel->vaddr = offset + pe_bin->vaddr;
		rel->paddr = import->paddr + pe_bin->paddr;
		r_list_append (relocs, rel);
	}
	RVecPEImport_free (imports);
}

void PE_(r_bin_mdmp_pe_load_sections) (struct PE_(r_bin_mdmp_pe_bin) * pe_bin, RVecRBinSection *vec) {
	/* TODO: Vet code, taken verbatim(ish) from bin_pe.c */
	if (!pe_bin || !vec) {
		return;
	}
	ut64 ba = pe_bin->vaddr; //baddr (arch);
	if (!pe_bin->bin) {
		return;
	}
	PE_(r_bin_pe_check_sections) (pe_bin->bin);
	struct r_bin_pe_section_t *section;
	R_VEC_FOREACH (&pe_bin->bin->sections, section) {
		RBinSection *ptr = RVecRBinSection_emplace_back (vec);
		if (!ptr) {
			break;
		}
		if (section->name[0]) {
			ptr->name = strdup ((char *)section->name);
		} else {
			ptr->name = strdup ("");
		}
		ptr->size = section->size;
		if (ptr->size > pe_bin->bin->size) {
			if (section->vsize < pe_bin->bin->size) {
				ptr->size = section->vsize;
			} else {
				//hack give it page size
				ptr->size = 4096;
			}
		}
		ptr->vsize = section->vsize;
		if (!ptr->vsize && ptr->size) {
			ptr->vsize = ptr->size;
		}
		ptr->paddr = section->paddr + pe_bin->paddr;
		ptr->vaddr = section->vaddr + ba;
		ptr->add = false;
		ptr->perm = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (section->perm)) {
			ptr->perm |= R_PERM_X;
		}
		if (R_BIN_PE_SCN_IS_WRITABLE (section->perm)) {
			ptr->perm |= R_PERM_W;
		}
		if (R_BIN_PE_SCN_IS_READABLE (section->perm)) {
			ptr->perm |= R_PERM_R;
		}
		if (R_BIN_PE_SCN_IS_SHAREABLE (section->perm)) {
			ptr->perm |= R_PERM_SHAR;
		}
		if ((ptr->perm & R_PERM_R) && !(ptr->perm & R_PERM_X) && ptr->size > 0) {
			if (!strncmp (ptr->name, ".rsrc", 5) ||
				!strncmp (ptr->name, ".data", 5) ||
				!strncmp (ptr->name, ".rdata", 6)) {
				ptr->is_data = true;
			}
		}
	}
}

void PE_(r_bin_mdmp_pe_load_symbols) (RBin *rbin, struct PE_(r_bin_mdmp_pe_bin) * pe_bin, RVecRBinSymbol *vec) {
	ut64 offset;
	RVecPEExport *symbols = NULL;
	RVecPEImport *imports = NULL;

	/* TODO: Load symbol table from pdb file */
	if ((symbols = PE_(r_bin_pe_get_exports) (pe_bin->bin))) {
		struct r_bin_pe_export_t *symbol;
		R_VEC_FOREACH (symbols, symbol) {
			RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
			offset = symbol->vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = r_bin_name_new ((const char *)symbol->name);
			ptr->libname = *symbol->libname ? strdup ((char *)symbol->libname) : NULL;
			ptr->forwarder = r_str_constpool_get (&rbin->constpool, (char *)symbol->forwarder);
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = symbol->paddr + pe_bin->paddr;
			ptr->ordinal = symbol->ordinal;
		}
		RVecPEExport_free (symbols);
	}
	/* Calling imports is unstable at the moment, I think this is an issue in pe.c */
	if ((imports = PE_(r_bin_pe_get_imports) (pe_bin->bin))) {
		struct r_bin_pe_import_t *import;
		R_VEC_FOREACH (imports, import) {
			RBinSymbol *ptr = RVecRBinSymbol_emplace_back (vec);
			offset = import->vaddr;
			if (offset > pe_bin->vaddr) {
				offset -= pe_bin->vaddr;
			}
			ptr->name = r_bin_name_new ((const char *)import->name);
			ptr->libname = *import->libname ? strdup ((const char *)import->libname) : NULL;
			ptr->is_imported = true;
			ptr->bind = "NONE";
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = offset + pe_bin->vaddr;
			ptr->paddr = import->paddr + pe_bin->paddr;
			ptr->ordinal = import->ordinal;
		}
		RVecPEImport_free (imports);
	}
}
