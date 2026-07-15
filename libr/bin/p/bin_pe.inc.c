/* radare - LGPL - Copyright 2009-2025 - nibble, pancake, alvarofe */

#include <limits.h>
#include <r_bin.h>
#include "../i/private.h"
#include "pe/pe.h"
#include "../format/pe/dotnet.h"

static Sdb* get_sdb(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	return pe? pe->kv: NULL;
}

static bool load_resources(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !PE_(r_bin_pe_load_resources) (pe, &bf->bo->resources_vec)) {
		return false;
	}
	RBinResource *resource;
	R_VEC_FOREACH (&bf->bo->resources_vec, resource) {
		if (resource->paddr != UT64_MAX) {
			resource->paddr += bf->bo->loadaddr;
		}
	}
	return true;
}

static ut64 pe_file_size_bound(RBinFile *bf, RBinPEObj *pe) {
	ut64 size = pe->size;
	ut64 fbufsize = bf->buf? r_buf_size (bf->buf): 0;
	if (fbufsize && fbufsize != UT64_MAX && fbufsize < size) {
		size = fbufsize;
	}
	if (bf->size && bf->size != UT64_MAX && bf->size < size) {
		size = bf->size;
	}
	return size;
}

static const char *get_cc(RBinFile *bf, ut64 vaddr) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSymbol *m = r_bin_get_symbol_at (bf->rbin, vaddr);
	if (!m || !m->arg_prefix || m->lang != R_BIN_LANG_CIL) {
		return NULL;
	}
	const bool instance = !(m->attr & R_BIN_ATTR_STATIC);
	RStrBuf *sb = r_strbuf_new ("dyncc:");
	if (!sb) {
		return NULL;
	}
	if (m->arg_count > 0) {
		r_strbuf_appendf (sb, "%s%u+%u", m->arg_prefix, m->arg_first, m->arg_count);
	}
	r_strbuf_append (sb, ":");
	if (m->ret_count > 0) {
		r_strbuf_appendf (sb, "r0+%u", m->ret_count);
	}
	if (instance && m->arg_count > 0) {
		r_strbuf_append (sb, "!T0");
	}
	char *s = r_strbuf_drain (sb);
	const char *ret = r_str_constpool_get (&bf->rbin->constpool, s);
	free (s);
	return ret;
}

static RList *get_dotnet_symbols(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->clr_hdr) {
		return NULL;
	}
	if (!pe->dotnet_symbols) {
		const ut8 *data = r_buf_data (bf->buf, NULL);
		st64 size = r_buf_size (bf->buf);
		if (data && size > 0 && size <= INT_MAX) {
			ut64 image_base = PE_(r_bin_pe_get_image_base) (pe);
			pe->dotnet_symbols = dotnet_parse (data, (int)size, image_base);
		}
	}
	return pe->dotnet_symbols;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	RBinPEObj *res = PE_(r_bin_pe_new_buf) (buf, bf->rbin->options.verbose);
	if (res) {
		res->mb = &bf->rbin->mb;
		res->sdbdir = R_STR_ISNOTEMPTY (bf->rbin->sdbdir)? strdup (bf->rbin->sdbdir): NULL;
		sdb_ns_set (bf->sdb, "info", res->kv);
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	PE_(r_bin_pe_free) (pe);
}

static ut64 baddr(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	return PE_(r_bin_pe_get_image_base) (pe);
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	struct r_bin_pe_addr_t *peaddr = NULL;
	RBinAddr *ret = NULL;
	if (bf && bf->bo && bf->bo->bin_obj) {
		switch (type) {
		case R_BIN_SYM_MAIN:
			peaddr = PE_(r_bin_pe_get_main_vaddr) (bf->bo->bin_obj);
			break;
		}
	}
	if (peaddr) {
		ret = R_NEW0 (RBinAddr);
		ret->paddr = peaddr->paddr;
		ret->vaddr = peaddr->vaddr;
	}
	free (peaddr);
	return ret;
}

static void add_tls_callbacks(RBinFile *bf, RList* list, int limit) {
	PE_DWord paddr, vaddr, haddr;
	int count = 0;
	RBinPEObj *pe = PE_(get) (bf);

	do {
		paddr = sdb_num_getf (pe->kv, NULL, "pe.tls_callback%d_paddr", count);
		if (!paddr) {
			break;
		}
		vaddr = sdb_num_getf (pe->kv, NULL, "pe.tls_callback%d_vaddr", count);
		if (!vaddr) {
			break;
		}
		haddr = sdb_num_getf (pe->kv, NULL, "pe.tls_callback%d_haddr", count);
		if (!haddr) {
			break;
		}
		if (limit_reached (list, limit)) {
			break;
		}
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		ptr->paddr = paddr;
		ptr->vaddr = vaddr;
		ptr->hpaddr = haddr;
		ptr->type = R_BIN_ENTRY_TYPE_TLS;
		r_list_append (list, ptr);
		count++;
	} while (vaddr);
}

static RList* entries(RBinFile *bf) {
	struct r_bin_pe_addr_t *entry = NULL;
	RList* ret;
	const int limit = bf->rbin->options.limit;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return ret;
	}
	// For .NET assemblies, find entry point from CLR EntryPointToken
	if (pe->clr_hdr && pe->clr_hdr->EntryPointToken) {
		ut32 token = pe->clr_hdr->EntryPointToken;
		ut32 table = (token >> 24) & 0xFF;
		// Table 0x06 is MethodDef - the main entry point for .NET
		if (table == 0x06) {
			ut64 image_base = PE_(r_bin_pe_get_image_base) (pe);
			RList *dotnet_symbols = get_dotnet_symbols (bf);
			if (dotnet_symbols) {
				RListIter *iter;
				DotNetSymbol *dsym;
				r_list_foreach (dotnet_symbols, iter, dsym) {
					if (dsym->token == token && dsym->vaddr > 0) {
						RBinAddr *ptr = R_NEW0 (RBinAddr);
						ptr->vaddr = dsym->vaddr + image_base;
						ptr->paddr = dsym->vaddr;
						ptr->type = R_BIN_ENTRY_TYPE_PROGRAM;
						r_list_append (ret, ptr);
						break;
					}
				}
			}
		}
		if (!r_list_empty (ret)) {
			return ret;
		}
	}
	// Fall back to native PE entry point
	if (!(entry = PE_(r_bin_pe_get_entrypoint) (pe))) {
		return ret;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr  = entry->paddr;
	ptr->vaddr  = entry->vaddr;
	ptr->hpaddr = entry->haddr;
	ptr->type   = R_BIN_ENTRY_TYPE_PROGRAM;
	r_list_append (ret, ptr);
	free (entry);
	if (limit_reached (ret, limit)) {
		return ret;
	}
	// get TLS callback addresses
	add_tls_callbacks (bf, ret, limit);

	return ret;
}

static bool sections_vec(RBinFile *bf) {
	ut64 ba = baddr (bf);
	int i = 0;
	const int limit = bf->rbin->options.limit;

	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return false;
	}
	RVecRBinSection_clear (&bf->bo->sections_vec);
	const ut64 file_size = pe_file_size_bound (bf, pe);

	PE_(r_bin_pe_check_sections) (pe);
	struct r_bin_pe_section_t *section;
	R_VEC_FOREACH (&pe->sections, section) {
		if (limit > 0 && RVecRBinSection_length (&bf->bo->sections_vec) >= (size_t)limit) {
			break;
		}
		RBinSection *sec = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		if (R_STR_ISNOTEMPTY (section->name)) {
			sec->name = strdup ((const char*)section->name);
		} else {
			R_LOG_WARN ("Missing name for section");
			sec->name = r_str_newf ("noname%d", i);
		}
		sec->size = section->size;
		const bool invalid_raw_range = sec->size > file_size || (sec->size > 0 && section->paddr >= file_size);
		if (sec->size > file_size) {
			if (section->vsize < file_size) {
				sec->size = section->vsize;
			} else {
				//hack give it page size
				sec->size = 4096;
			}
		}
		sec->vsize = section->vsize;
		if (!sec->vsize && sec->size) {
			sec->vsize = sec->size;
		}
		if (invalid_raw_range && sec->vsize > sec->size) {
			sec->vsize = sec->size;
		}
		sec->paddr = section->paddr;
		sec->vaddr = section->vaddr + ba;
		sec->add = true;
		sec->perm = 0;
		sec->flags = section->flags;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (section->perm)) {
			sec->perm |= R_PERM_X;
			sec->perm |= R_PERM_R; // implicit
		}
		if (R_BIN_PE_SCN_IS_WRITABLE (section->perm)) {
			sec->perm |= R_PERM_W;
		}
		if (R_BIN_PE_SCN_IS_READABLE (section->perm)) {
			sec->perm |= R_PERM_R;
		}
		// this is causing may tests to fail because rx != srx
		if (R_BIN_PE_SCN_IS_SHAREABLE (section->perm)) {
			sec->perm |= R_PERM_SHAR;
		}
		if ((sec->perm & R_PERM_RW) && !(sec->perm & R_PERM_X) && sec->size > 0) {
			const char *name = sec->name;
			if (name && (!strcmp (name, ".rsrc") || !strcmp (name, ".data") || !strcmp (name, ".rdata"))) {
				sec->is_data = true;
			}
		}
		i++;
	}
	return true;
}

static void find_pe_overlay(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	ut64 pe_overlay_size;
	ut64 pe_overlay_offset = PE_(bin_pe_get_overlay) (pe, &pe_overlay_size);
	if (pe_overlay_offset) {
		sdb_num_set (bf->sdb, "pe_overlay.offset", pe_overlay_offset, 0);
		sdb_num_set (bf->sdb, "pe_overlay.size", pe_overlay_size, 0);
	}
}

static RList* classes(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->dos_header || !pe->nt_headers) {
		return NULL;
	}
	RList *dotnet_symbols = get_dotnet_symbols (bf);
	if (!dotnet_symbols || r_list_empty (dotnet_symbols)) {
		return NULL;
	}
	const ut64 image_base = PE_(r_bin_pe_get_image_base) (pe);
	const bool names_only = bf->rbin->options.classes_names_only;
	const int limit = bf->rbin->options.limit;

	RListIter *iter_sym;
	DotNetSymbol *dsym;
	// Pass 1: create class entries from typedef symbols (and their fields)
	r_list_foreach (dotnet_symbols, iter_sym, dsym) {
		if (!dsym->name || !dsym->type || strcmp (dsym->type, "typedef")) {
			continue;
		}
		const char *ns = dsym->namespace;
		char *fullname = R_STR_ISNOTEMPTY (ns)
			? r_str_newf ("%s.%s", ns, dsym->name)
			: strdup (dsym->name);
		if (limit > 0 && r_list_length (bf->bo->classes) >= limit) {
			free (fullname);
			break;
		}
		RBinClass *cls = r_bin_file_add_class (bf, fullname, NULL, 0);
		if (cls) {
			cls->lang = R_BIN_LANG_MSVC;
			if (!names_only && dsym->fields) {
				RListIter *iter_field;
				DotNetField *dfield;
				r_list_foreach (dsym->fields, iter_field, dfield) {
					RBinField *field = RVecRBinField_emplace_back (&cls->fields);
					field->name = r_bin_name_new (dfield->name);
					field->kind = R_BIN_FIELD_KIND_FIELD;
					field->offset = dfield->offset;
				}
			}
		}
		free (fullname);
	}
	if (names_only) {
		return NULL;
	}
	// Pass 2: split methoddef symbol names into class.method and append
	r_list_foreach (dotnet_symbols, iter_sym, dsym) {
		if (!dsym->name || !dsym->type || strcmp (dsym->type, "methoddef")) {
			continue;
		}
		// Method names are "Namespace.ClassName.MethodName"; the method has
		// no embedded dots so walk back-to-front and split at the last dot
		// whose tail is dot-free.
		char *tmp = strdup (dsym->name);
		char *split = NULL;
		char *cur = tmp;
		while ((split = strrchr (cur, '.'))) {
			if (!strchr (split + 1, '.')) {
				break;
			}
			cur = split - 1;
			if (cur <= tmp) {
				split = NULL;
				break;
			}
		}
		if (!split) {
			split = strchr (tmp, '.');
		}
		if (!split || split == tmp) {
			free (tmp);
			continue;
		}
		*split = '\0';
		const char *method_name = split + 1;
		if (!bf->rbin->options.load_unnamed
				&& (r_bin_name_is_unnamed (tmp) || r_bin_name_is_unnamed (method_name))) {
			free (tmp);
			continue;
		}
		RBinClass *cls = r_bin_file_add_class (bf, tmp, NULL, 0);
		if (cls) {
			cls->lang = R_BIN_LANG_MSVC;
		}
		RBinSymbol *m = r_bin_class_add_method (bf, tmp, method_name, 0);
		if (m) {
			m->vaddr = dsym->vaddr + image_base;
			m->paddr = dsym->vaddr;
			m->bind = R_BIN_BIND_GLOBAL_STR;
			m->type = R_BIN_TYPE_FUNC_STR;
			m->size = dsym->size;
		}
		free (tmp);
	}
	return NULL;
}

#ifndef R_BIN_PE64
static char* types(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->dos_header || !pe->nt_headers) {
		return NULL;
	}

	RList *dotnet_symbols = get_dotnet_symbols (bf);
	if (!dotnet_symbols || r_list_empty (dotnet_symbols)) {
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}

	RListIter *iter_sym;
	DotNetSymbol *dsym;
	r_list_foreach (dotnet_symbols, iter_sym, dsym) {
		if (!dsym->name) {
			continue;
		}
		if (dsym->type && !strcmp (dsym->type, "typedef")) {
			// Struct/class
			const char *ns = dsym->namespace ? dsym->namespace : "";
			r_strbuf_appendf (sb, "struct %s%s%s {\n", ns, *ns ? "." : "", dsym->name);
			if (dsym->fields) {
				RListIter *iter_field;
				DotNetField *field;
				r_list_foreach (dsym->fields, iter_field, field) {
					if (field->name) {
						r_strbuf_appendf (sb, "  %s;\n", field->name);
					}
				}
			}
			r_strbuf_append (sb, "};\n\n");
		} else if (dsym->type && !strcmp (dsym->type, "methoddef")) {
			// Function signature
			r_strbuf_appendf (sb, "void %s();\n", dsym->name);
		}
	}

	return r_strbuf_drain (sb);
}
#endif

static bool symbols_vec(RBinFile *bf) {
	RBinSymbol *ptr = NULL;
	RVecPEExport *symbols = NULL;
	RVecPEImport *imports = NULL;
	const int limit = bf->rbin->options.limit;

	RVecRBinSymbol *ret = &bf->bo->symbols_vec;
	RBinPEObj *pe = PE_(get) (bf);
	if ((symbols = PE_(r_bin_pe_get_exports)(pe))) {
		struct r_bin_pe_export_t *symbol;
		R_VEC_FOREACH (symbols, symbol) {
			if (limit_reached_vec (ret, limit)) {
				break;
			}
			ptr = RVecRBinSymbol_emplace_back (ret);
			ptr->name = r_bin_name_new ((char *)symbol->name);
			ptr->libname = *symbol->libname ? strdup ((char *)symbol->libname) : NULL;
			ptr->forwarder = r_str_constpool_get (&bf->rbin->constpool, (char *)symbol->forwarder);
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->vaddr = symbol->vaddr;
			ptr->paddr = symbol->paddr;
			ptr->ordinal = symbol->ordinal;
		}
		RVecPEExport_free (symbols);
	}

	if ((imports = PE_(r_bin_pe_get_imports)(pe))) {
		struct r_bin_pe_import_t *import;
		R_VEC_FOREACH (imports, import) {
			if (limit_reached_vec (ret, limit)) {
				break;
			}
			ptr = RVecRBinSymbol_emplace_back (ret);
			ptr->name = r_bin_name_new ((const char *)import->name);
			ptr->libname = strdup ((const char *)import->libname);
			ptr->is_imported = true;
			ptr->bind = "NONE";
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->vaddr = import->vaddr;
			ptr->paddr = import->paddr;
			ptr->ordinal = import->ordinal;
		}
		RVecPEImport_free (imports);
	}
	if (limit_reached_vec (ret, limit)) {
		find_pe_overlay (bf);
		return true;
	}

	// Add .NET symbols if this is a .NET assembly
	if (pe && pe->dos_header && pe->nt_headers) {
		ut64 image_base = PE_(r_bin_pe_get_image_base) (pe);
		RList *dotnet_symbols = get_dotnet_symbols (bf);
		if (dotnet_symbols) {
			if (r_list_length (dotnet_symbols) > 0) {
				RListIter *iter;
				DotNetSymbol *dsym;
				r_list_foreach (dotnet_symbols, iter, dsym) {
					if (limit_reached_vec (ret, limit)) {
						break;
					}
					if (!strcmp (dsym->type, "methoddef")) {
						// Add methoddef at its RVA
						ptr = RVecRBinSymbol_emplace_back (ret);
						if (dsym->namespace && dsym->namespace[0]) {
							char *full_name = r_str_newf ("%s.%s", dsym->namespace, dsym->name);
							ptr->name = r_bin_name_new (full_name);
							free (full_name);
						} else {
							ptr->name = r_bin_name_new (dsym->name);
						}
						ptr->type = R_BIN_TYPE_FUNC_STR;
						ptr->bind = R_BIN_BIND_GLOBAL_STR;
						if (dsym->is_native) {
							ptr->lang = R_BIN_LANG_C;
						} else {
							ptr->lang = R_BIN_LANG_CIL;
							if (dsym->param_count > 0 || dsym->ret_count > 0) {
								ptr->arg_first = 0;
								ptr->arg_count = dsym->param_count;
								ptr->arg_prefix = "a";
								ptr->ret_count = dsym->ret_count;
								if (!dsym->is_instance) {
									ptr->attr |= R_BIN_ATTR_STATIC;
								}
							}
						}
						if (dsym->vaddr > 0) {
							ptr->vaddr = dsym->vaddr + image_base;
							ptr->paddr = dsym->vaddr;
						}
						ptr->size = dsym->size;
					}
				}
			}
		}
	}

	find_pe_overlay (bf);
	return true;
}

static void filter_import(ut8 *n) {
	size_t i;
	for (i = 0; n[i]; i++) {
		if (n[i] < 30 || n[i] >= 0x7f) {
			n[i] = 0;
			break;
		}
	}
}

static bool imports_vec(RBinFile *bf) {
	const int limit = bf->rbin->options.limit;

	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return false;
	}
	RVecRBinImport *ret = &bf->bo->imports_vec;
	r_list_free (pe->relocs);
	RList *relocs = r_list_newf ((RListFree)r_bin_reloc_free);
	if (!relocs) {
		return false;
	}
	pe->relocs = relocs;

	RVecPEImport *imports = PE_(r_bin_pe_get_imports)(pe);
	if (!imports) {
		return true;
	}
	struct r_bin_pe_import_t *imp;
	R_VEC_FOREACH (imports, imp) {
		if (limit_reached_vec_imports (ret, limit)) {
			break;
		}
		filter_import (imp->name);
		RBinImport *ptr = RVecRBinImport_emplace_back (ret);
		ptr->name = r_bin_name_new ((char*)imp->name);
		ptr->libname = strdup ((char*)imp->libname);
		ptr->bind = "NONE";
		ptr->type = "FUNC";
		ptr->ordinal = imp->ordinal;

		RBinReloc *rel = R_NEW0 (RBinReloc);
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = r_bin_import_clone (ptr);
		rel->addend = 0;
		rel->vaddr = r_buf_read_le32_at (bf->buf, imp->paddr);
		rel->paddr = imp->paddr;
		rel->ntype = imp->ntype;
		r_list_append (relocs, rel);
	}
	RVecPEImport_free (imports);
	return true;
}

static RList* relocs(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (pe && pe->relocs) {
		RList *l = r_list_clone (pe->relocs, NULL);
		// ownership transferred
		pe->relocs->free = NULL;
		return l;
	}
	return NULL;
}

static RList* libs(RBinFile *bf) {
	RVecPELib *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	const int limit = bf->rbin->options.limit;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	RBinPEObj *pe = PE_(get) (bf);
	if (!(libs = PE_(r_bin_pe_get_libs)(pe))) {
		return ret;
	}
	struct r_bin_pe_lib_t *lib;
	R_VEC_FOREACH (libs, lib) {
		if (limit_reached (ret, limit)) {
			break;
		}
		ptr = strdup (lib->name);
		r_list_append (ret, ptr);
	}
	RVecPELib_free (libs);
	return ret;
}

static bool has_pe_lib(RBinFile *bf, const char *name) {
	RBinPEObj *pe = PE_(get) (bf);
	RVecPELib *libs = PE_(r_bin_pe_get_libs)(pe);
	if (!libs) {
		return false;
	}

	bool found = false;
	struct r_bin_pe_lib_t *lib;
	R_VEC_FOREACH (libs, lib) {
		if (!strcmp (lib->name, name)) {
			found = true;
			break;
		}
	}
	RVecPELib_free (libs);
	return found;
}

static bool is_dot_net(RBinFile *bf) {
	return has_pe_lib (bf, "mscoree.dll");
}

static bool is_vb6(RBinFile *bf) {
	return has_pe_lib (bf, "msvbvm60.dll");
}

static bool check_inlined_canary(RBinFile *bf) {
	ut8 buf[64];
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return false;
	}
	struct r_bin_pe_addr_t *entry = PE_(r_bin_pe_get_entrypoint) (pe);
	if (!entry) {
		return false;
	}
	// check for 32bit canary
	ut64 addr = entry->paddr;
	if (addr == UT64_MAX || !addr) {
		goto out_fail;
	}
	st64 nread = r_buf_read_at (bf->buf, addr, buf, sizeof (buf));
	if (nread < 1) {
		goto out_fail;
	}
	if (buf[0] == 0x48) {
		if (nread < 9) {
			goto out_fail;
		}
		// x86-64
#if 0
	// X86-64
	;-- entry0, rip:
	0x140001348      4883ec28       sub   rsp,  0x28
	0x14000134c      e85b020000     call  0x1400015ac
	....
	0x1400015ac      48895c2420     mov   qword [rsp + 0x20], rbx
	0x1400015b1      55             push  rbp
	0x1400015b2      488bec         mov   rbp,  rsp
	0x1400015b5      4883ec20       sub   rsp,  0x20
	0x1400015b9      488b0580ba01.  mov   rax,  qword [0x14001d040]
	0x1400015c0      48bb32a2df2d.  movabs rbx,  0x2b992ddfa232
	0x1400015ca      483bc3         cmp   rax,  rbx
#endif
		// follow call
		ut64 calldst = addr + 9 + (st32)r_read_le32 (buf + 5);
		nread = r_buf_read_at (bf->buf, calldst, buf, sizeof (buf));
		if (nread < 2) {
			goto out_fail;
		}
		if (buf[0] != 0x48 && buf[1] != 0x89) {
			goto out_fail;
		}

		ut8 can0[8] = {0};
		const int can1_off = 0x16;
		if (nread < can1_off + (int)sizeof (can0)) {
			goto out_fail;
		}
		ut32 canaddr = r_read_le32 (buf + 16);
		ut32 panaddr = canaddr - 0x40; // PE_(va2pa)(bf->bo->bin_obj, canaddr);

		if (r_buf_read_at (bf->buf, panaddr, can0, sizeof (can0)) != sizeof (can0)) {
			goto out_fail;
		}
		if (!memcmp (can0, buf + can1_off, sizeof (can0))) {
			char *canstr = r_str_newf ("%02x%02x%02x%02x%02x%02x%02x%02x",
				can0[0], can0[1], can0[2], can0[3],
				can0[4], can0[5], can0[6], can0[7]);
			sdb_set (bf->sdb, "canary.value", canstr, 0);
			free (canstr);
			goto out_succeed;
		}
	} else if (buf[0] == 0xe8) {
#if 0
// X86-32
	mov edi, edi
	push ebp
	mov ebp, esp
	sub esp, 0x10
	mov eax, dword [0x8a2b84] // contents of 0x8a2b84 should be 0xbb40e64e
	and dword [ebp - 8], 0
	and dword [ebp - 4], 0
	push ebx
	push edi
	mov edi, 0xbb40e64e
#endif
		// follow call
		if (nread < 5) {
			goto out_fail;
		}
		ut64 calldst = addr + 5 + (st32)r_read_le32 (buf + 1);
		nread = r_buf_read_at (bf->buf, calldst, buf, sizeof (buf));
		if (nread < 3) {
			goto out_fail;
		}
		if (buf[0] == 0x8b && buf[1] == 0xff && buf[2] == 0x55) {
			goto out_succeed;
		}
		ut8 can0[4] = {0};
		const int can1_off = 9;
		if (nread < can1_off + (int)sizeof (can0)) {
			goto out_fail;
		}
		ut32 canaddr = r_read_le32 (buf + 2);
		ut32 panaddr = PE_(va2pa)(pe, canaddr);
		if (r_buf_read_at (bf->buf, panaddr, can0, sizeof (can0)) != sizeof (can0)) {
			goto out_fail;
		}
		if (!memcmp (can0, buf + can1_off, sizeof (can0))) {
			char *canstr = r_str_newf ("%02x%02x%02x%02x", can0[0], can0[1], can0[2], can0[3]);
			sdb_set (bf->sdb, "canary.value", canstr, 0);
			free (canstr);
			goto out_succeed;
		}
	}

	out_succeed:
	free (entry);
	return true;

	out_fail:
	free (entry);
	return false;
}

static bool has_canary(RBinFile *bf) {
	if (check_inlined_canary (bf)) {
		return true;
	}
	RBinPEObj *pe = PE_(get) (bf);
	if (pe) {
		const RList *relocs_list = pe->relocs;
		if (relocs_list) {
			RListIter *iter;
			RBinReloc *rel;
			r_list_foreach (relocs_list, iter, rel) {
				if (rel->import) {
					const char *name = r_bin_name_tostring2 (rel->import->name, 'o');
					if (!strcmp (name, "__security_init_cookie")) {
						return true;
					}
				}
			}
		}
	} else {  // rabin2 needs this as it will not initialise bin
		imports_vec (bf);
		RBinImport *imp;
		R_VEC_FOREACH (&bf->bo->imports_vec, imp) {
			const char *name = r_bin_name_tostring2 (imp->name, 'o');
			if (!strcmp (name, "__security_init_cookie")) {
				return true;
			}
		}
	}
	return false;
}

static bool haschr(const RBinFile* bf, ut16 dllCharacteristic) {
	if (!bf) {
		return false;
	}
	ut64 sz;
	const ut8 *buf = r_buf_data (bf->buf, &sz);
	if (!buf || sz < 0x40) {
		return false;
	}
	ut32 idx = r_read_le32 (buf + 0x3c);
	ut64 off = idx + 0x5e;
	if (off > sz || off + sizeof (ut16) > sz) {
		return false;
	}
	return r_read_le16 (buf + off) & dllCharacteristic;
}

static const char *normalized_visibility_name(const char *name) {
	while (name && *name == '_') {
		name++;
	}
	return name;
}

static bool is_suspicious_library_export(const char *name) {
	name = normalized_visibility_name (name);
	return R_STR_ISNOTEMPTY (name) && (!strcmp (name, "main") ||
		r_str_casestr (name, "hidden") || r_str_casestr (name, "helper"));
}

static bool has_uncaps_exports(RBinPEObj *pe) {
	R_RETURN_VAL_IF_FAIL (pe, false);
	RVecPEExport *exports = PE_(r_bin_pe_get_exports) (pe);
	if (!exports) {
		return false;
	}
	const bool is_dll = PE_(r_bin_pe_is_dll) (pe);
	bool uncaps = false;
	struct r_bin_pe_export_t *exp;
	R_VEC_FOREACH (exports, exp) {
		const char *name = (const char *)exp->name;
		if (!R_STR_ISNOTEMPTY (name)) {
			continue;
		}
		if (!is_dll) {
			uncaps = true;
			break;
		}
		if (is_suspicious_library_export (name)) {
			uncaps = true;
			break;
		}
	}
	RVecPEExport_free (exports);
	return uncaps;
}

static RBinInfo* info(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return NULL;
	}
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = PE_(r_bin_pe_get_class) (pe);
	ret->rclass = strdup ("pe");
	ret->os = PE_(r_bin_pe_get_os) (pe);
	ret->machine = PE_(r_bin_pe_get_machine) (pe);
	ret->default_cc = PE_(r_bin_pe_get_cc) (pe);
	if (pe->clr_hdr) {
		ret->arch = strdup ("cil");
		ret->subsystem = strdup ("dotnet");
		ret->lang = "cil";
	} else {
		ret->arch = strdup (PE_(r_bin_pe_get_arch) (pe));
		ret->subsystem = PE_(r_bin_pe_get_subsystem) (pe);
	}
	if (is_dot_net (bf)) {
		ret->lang = "cil";
	}
	if (is_vb6 (bf)) {
		ret->lang = "vb";
	}
	const char *typestr = PE_(r_bin_pe_is_dll) (pe)? "DLL (Dynamic Link Library)": "EXEC (Executable file)";
	ret->type = strdup (typestr);

	ut32 claimed_checksum = PE_(bin_pe_get_claimed_checksum) (pe);
	if (pe->size < 0x40000000 /* 1 GiB */) {
		ut32 actual_checksum = PE_(bin_pe_get_actual_checksum) (pe);
		ret->actual_checksum = r_str_newf ("0x%08x", actual_checksum);
	} else {
		R_LOG_WARN("Skipping calculating actual checksum because too large file (1+ GiB)");
	}

	ut32 pe_overlay = sdb_num_get (bf->sdb, "pe_overlay.size", 0);
	ret->bits = PE_(r_bin_pe_get_bits) (pe);
	ret->big_endian = PE_(r_bin_pe_is_big_endian) (pe);
	ret->dbg_info = 0;
	ret->has_lit = true;
	ret->has_canary = has_canary (bf);
	ret->has_nx = haschr (bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
	ret->has_pi = haschr (bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
	ret->claimed_checksum = r_str_newf ("0x%08x", claimed_checksum);
	ret->pe_overlay = pe_overlay > 0;
	ret->signature = pe? pe->is_signed: false;
	ret->file_hashes = r_list_newf ((RListFree)r_bin_file_hash_free);
	Sdb *db = sdb_ns (bf->sdb, "pe", true);
	sdb_bool_set (db, "canary", has_canary (bf), 0);
	sdb_bool_set (db, "highva", haschr (bf, IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA), 0);
	sdb_bool_set (db, "aslr", haschr (bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE), 0);
	sdb_bool_set (db, "forceintegrity", haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "nx", haschr (bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT), 0);
	sdb_bool_set (db, "isolation", !haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "seh", !haschr (bf, IMAGE_DLL_CHARACTERISTICS_NO_SEH), 0);
	sdb_bool_set (db, "bind", !haschr (bf, IMAGE_DLL_CHARACTERISTICS_NO_BIND), 0);
	sdb_bool_set (db, "appcontainer", haschr (bf, IMAGE_DLL_CHARACTERISTICS_APPCONTAINER), 0);
	sdb_bool_set (db, "wdmdriver", haschr (bf, IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER), 0);
	sdb_bool_set (db, "guardcf", haschr (bf, IMAGE_DLL_CHARACTERISTICS_GUARD_CF), 0);
	sdb_bool_set (db, "terminalserveraware", haschr (bf, IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE), 0);
	sdb_num_set (db, "bits", ret->bits, 0);
	sdb_set (db, "claimed_checksum", ret->claimed_checksum, 0);
	sdb_set (db, "actual_checksum", ret->actual_checksum, 0);
	sdb_bool_set (db, "is_authhash_valid", PE_(bin_pe_is_authhash_valid) (pe), 0);

	ret->has_va = true;

	if (PE_(r_bin_pe_is_stripped_debug) (pe)) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	if (PE_(r_bin_pe_is_stripped_line_nums) (pe)) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS;
	}
	if (PE_(r_bin_pe_is_stripped_local_syms) (pe)) {
		ret->dbg_info |= R_BIN_DBG_SYMS;
	}
	if (PE_(r_bin_pe_is_stripped_relocs) (pe)) {
		ret->dbg_info |= R_BIN_DBG_RELOCS;
	}
	if (has_uncaps_exports (pe)) {
		ret->dbg_info |= R_BIN_DBG_UNCAPS;
	}

	SDebugInfo di = {{0}};
	if (PE_(r_bin_pe_get_debug_data)(pe, &di)) {
		ret->guid = r_str_ndup (di.guidstr, GUIDSTR_LEN);
		if (ret->guid) {
			ret->debug_file_name = r_str_ndup (di.file_name, DBG_FILE_NAME_LEN);
			if (!ret->debug_file_name) {
				R_FREE (ret->guid);
			}
		}
	}

	return ret;
}

static ut64 get_vaddr(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return baddr + vaddr;
}

static RList *compute_hashes(RBinFile *bf) {
	RList *file_hashes = r_list_newf ((RListFree) r_bin_file_hash_free);
	RBinPEObj *pe = PE_(get) (bf);
	if (pe) {
		const char *authentihash = PE_(bin_pe_compute_authentihash) (pe);
		if (authentihash) {
			RBinFileHash *authhash = R_NEW0 (RBinFileHash);
			authhash->type = strdup ("authentihash");
			authhash->hex = authentihash;
			r_list_push (file_hashes, authhash);
		}
	}
	return file_hashes;
}

#ifndef R_BIN_PE64
static const char *getname(RBinFile *bf, int type, int idx, bool sd) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->clr_hdr) {
		return NULL;
	}
	RList *dotnet_symbols = get_dotnet_symbols (bf);
	if (!dotnet_symbols) {
		return NULL;
	}
	RListIter *iter;
	DotNetSymbol *dsym;
	ut32 token = 0;
	switch (type) {
	case 'm': // methoddef or memberref
		token = (0x06 << 24) | idx; // try methoddef first
		r_list_foreach (dotnet_symbols, iter, dsym) {
			if (dsym->token == token) {
				return dsym->name;
			}
		}
		token = (0x0A << 24) | idx; // try memberref
		r_list_foreach (dotnet_symbols, iter, dsym) {
			if (dsym->token == token) {
				return dsym->name;
			}
		}
		break;
	case 't': // typedef
		token = (0x02 << 24) | idx;
		r_list_foreach (dotnet_symbols, iter, dsym) {
			if (dsym->token == token) {
				return dsym->name;
			}
		}
		break;
	case 'r': // typeref
		token = (0x01 << 24) | idx;
		r_list_foreach (dotnet_symbols, iter, dsym) {
			if (dsym->token == token) {
				return dsym->name;
			}
		}
		break;
	case 'f': // field
		token = (0x04 << 24) | idx;
		r_list_foreach (dotnet_symbols, iter, dsym) {
			if (dsym->token == token) {
				return dsym->name;
			}
		}
		break;
	case 's': // strings
		if (pe->streams) {
			int i;
			for (i = 0; pe->streams[i]; i++) {
				if (pe->streams[i]->Name && !strcmp (pe->streams[i]->Name, "#Strings")) {
					DATA_DIRECTORY *metadata_dir = (DATA_DIRECTORY *)((ut8*)pe->clr_hdr + 8);
					ut64 rva = metadata_dir->VirtualAddress + pe->streams[i]->Offset + idx;
					ut64 offset = PE_(va2pa) (pe, rva);
					const char *str = r_buf_get_string (pe->b, offset);
					if (str) {
						char *escaped = r_str_escape (str);
						char *quoted = r_str_newf ("\"%s\"", escaped);
						free (escaped);
						return quoted;
					}
					return NULL;
				}
			}
		}
		break;
	}
	return NULL;
}
#endif
