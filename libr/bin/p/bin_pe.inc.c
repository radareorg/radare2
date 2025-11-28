/* radare - LGPL - Copyright 2009-2025 - nibble, pancake, alvarofe */

#include <r_bin.h>
#include "../i/private.h"
#include "pe/pe.h"
#include "../format/pe/dotnet.h"

static Sdb* get_sdb(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	return pe? pe->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	RBinPEObj *res = PE_(r_bin_pe_new_buf) (buf, bf->rbin->options.verbose);
	if (res) {
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
	if (peaddr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = peaddr->paddr;
		ret->vaddr = peaddr->vaddr;
	}
	free (peaddr);
	return ret;
}

static void add_tls_callbacks(RBinFile *bf, RList* list) {
	r_strf_buffer (64);
	PE_DWord paddr, vaddr, haddr;
	int count = 0;
	RBinAddr *ptr = NULL;
	RBinPEObj *pe = PE_(get) (bf);
	const char *key;

	do {
		key =  r_strf ("pe.tls_callback%d_paddr", count);
		paddr = sdb_num_get (pe->kv, key, 0);
		if (!paddr) {
			break;
		}
		key =  r_strf ("pe.tls_callback%d_vaddr", count);
		vaddr = sdb_num_get (pe->kv, key, 0);
		if (!vaddr) {
			break;
		}
		key = r_strf ("pe.tls_callback%d_haddr", count);
		haddr = sdb_num_get (pe->kv, key, 0);
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

static RList* entries(RBinFile *bf) {
	struct r_bin_pe_addr_t *entry = NULL;
	RBinAddr *ptr = NULL;
	RList* ret;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	RBinPEObj *pe = PE_(get) (bf);
	if (!(entry = PE_(r_bin_pe_get_entrypoint) (pe))) {
		return ret;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr  = entry->paddr;
		ptr->vaddr  = entry->vaddr;
		ptr->hpaddr = entry->haddr;
		ptr->type   = R_BIN_ENTRY_TYPE_PROGRAM;
		r_list_append (ret, ptr);
	}
	free (entry);
	// get TLS callback addresses
	add_tls_callbacks (bf, ret);

	return ret;
}

static RList* sections(RBinFile *bf) {
	ut64 ba = baddr (bf);
	int i;

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	if (!ret) {
		return NULL;
	}

	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->sections) {
		r_list_free (ret);
		return NULL;
	}
	struct r_bin_pe_section_t *sections = pe->sections;

	PE_(r_bin_pe_check_sections) (pe, &sections);
	for (i = 0; !sections[i].last; i++) {
		RBinSection *sec = R_NEW0 (RBinSection);
		if (!sec) {
			break;
		}
		if (R_STR_ISNOTEMPTY (sections[i].name)) {
			sec->name = strdup ((const char*)sections[i].name);
		} else {
			R_LOG_WARN ("Missing name for section");
			sec->name = r_str_newf ("noname%d", i);
		}
		sec->size = sections[i].size;
		if (sec->size > pe->size) {
			if (sections[i].vsize < pe->size) {
				sec->size = sections[i].vsize;
			} else {
				//hack give it page size
				sec->size = 4096;
			}
		}
		sec->vsize = sections[i].vsize;
		if (!sec->vsize && sec->size) {
			sec->vsize = sec->size;
		}
		sec->paddr = sections[i].paddr;
		sec->vaddr = sections[i].vaddr + ba;
		sec->add = true;
		sec->perm = 0;
		sec->flags = sections[i].flags;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].perm)) {
			sec->perm |= R_PERM_X;
			sec->perm |= R_PERM_R; // implicit
		}
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].perm)) {
			sec->perm |= R_PERM_W;
		}
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].perm)) {
			sec->perm |= R_PERM_R;
		}
		// this is causing may tests to fail because rx != srx
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].perm)) {
			sec->perm |= R_PERM_SHAR;
		}
		if ((sec->perm & R_PERM_RW) && !(sec->perm & R_PERM_X) && sec->size > 0) {
			const char *name = sec->name;
			if (name && (!strcmp (name, ".rsrc") || !strcmp (name, ".data") || !strcmp (name, ".rdata"))) {
				sec->is_data = true;
			}
		}
		r_list_append (ret, sec);
	}
	return ret;
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
	RList *ret = NULL;
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->dos_header || !pe->nt_headers) {
		return NULL;
	}

	RBuffer *buf = bf->buf;
	const ut8 *data = r_buf_data (buf, NULL);
	size_t size = r_buf_size (buf);
	ut64 image_base = PE_(r_bin_pe_get_image_base)(pe);
	RList *dotnet_symbols = dotnet_parse (data, size, image_base);
	if (r_list_empty (dotnet_symbols)) {
		r_list_free (dotnet_symbols);
		return NULL;
	}
	ret = r_list_newf ((RListFree)r_bin_class_free);
	if (!ret) {
		return NULL;
	}

	// Process symbols - first create classes from typedefs, then add methods
	RListIter *iter_sym;
	DotNetSymbol *dsym;
	// First pass: create class entries from typedef symbols
	r_list_foreach (dotnet_symbols, iter_sym, dsym) {
		if (!dsym->name || !dsym->type || strcmp (dsym->type, "typedef")) {
			continue;
		}
		// Create full class name with namespace
		char *class_name_full;
		const char *ns = dsym->namespace;
		if (R_STR_ISNOTEMPTY (ns)) {
			class_name_full = r_str_newf ("%s.%s", ns, dsym->name);
		} else {
			class_name_full = strdup (dsym->name);
		}
		// Check if class already exists
		RBinClass *existing = NULL;
		RListIter *iter_cls;
		RBinClass *cls_iter;
		r_list_foreach (ret, iter_cls, cls_iter) {
			const char *cls_name = r_bin_name_tostring (cls_iter->name);
			if (cls_name && !strcmp (cls_name, class_name_full)) {
				existing = cls_iter;
				break;
			}
		}
		// Create new class if it doesn't exist
		RBinClass *cls = NULL;
		if (!existing) {
			cls = r_bin_class_new (class_name_full, NULL, 0);
			cls->lang = R_BIN_LANG_MSVC;
			r_list_append (ret, cls);
		}
		RBinClass *target_cls = existing ? existing : cls;
		if (target_cls && dsym->fields) {
			RListIter *iter_field;
			DotNetField *dfield;
			r_list_foreach (dsym->fields, iter_field, dfield) {
				RBinField *field = R_NEW0 (RBinField);
				field->name = r_bin_name_new (dfield->name);
				field->kind = R_BIN_FIELD_KIND_FIELD;
				field->vaddr = 0;
				field->paddr = 0;
				field->size = 0;
				field->offset = dfield->offset;
				r_list_append (target_cls->fields, field);
			}
		}
		free (class_name_full);
	}
	// Second pass: add methods to their corresponding classes
	r_list_foreach (dotnet_symbols, iter_sym, dsym) {
		if (!dsym->name || !dsym->type || strcmp (dsym->type, "methoddef")) {
			continue;
		}

		// Method names in .NET are formatted as: Namespace.ClassName.MethodName
		// or Namespace.ClassName+InnerClass.MethodName
		// Try to find the dot that separates the class from the method by looking for the
		// last dot where what follows it is a plausible method name (contains no further dots, + or `)
		char *tmp = r_str_newf ("%s", dsym->name);
		char *split_point = NULL;

		// Start with the last dot and work backwards
		char *current_search_start = tmp;
		while ((split_point = strrchr (current_search_start, '.'))) {
			*split_point = '\0'; // Temporarily null terminate to isolate method name
			char *potential_method = split_point + 1;

			// Check if this looks like a method name (no dots after this point)
			if (strchr (potential_method, '.') == NULL) {
				// This looks good, use this split point
				*split_point = '\0'; // Keep it null terminated
				break;
			}

			// Restore the dot and try the previous one
			*split_point = '.';
			current_search_start = split_point - 1;
			if (current_search_start <= tmp) {
				split_point = NULL;
				break;
			}
		}

		if (!split_point) {
			// Fallback: use first dot if available
			split_point = strchr (tmp, '.');
		}

		if (!split_point || split_point == tmp) {
			free (tmp);
			continue;
		}

		*split_point = '\0';
		char *class_name_full = tmp;
		char *method_name = split_point + 1;
		// Look for existing class in result list or create new one
		RBinClass *cls = NULL;
		RListIter *iter_cls;
		RBinClass *existing_cls;
		r_list_foreach (ret, iter_cls, existing_cls) {
			const char *cls_name = r_bin_name_tostring (existing_cls->name);
			if (cls_name && !strcmp (cls_name, class_name_full)) {
				cls = existing_cls;
				break;
			}
		}
		if (!cls) {
			// Create new class if it doesn't exist
			cls = r_bin_class_new (class_name_full, NULL, 0);
			if (cls) {
				cls->lang = R_BIN_LANG_MSVC;
				r_list_append (ret, cls);
			}
		}
		if (cls && method_name && *method_name) {
			// Add this method to the class
			RBinSymbol *method_sym = R_NEW0 (RBinSymbol);
			if (method_sym) {
				method_sym->name = r_bin_name_new (method_name);
				method_sym->vaddr = dsym->vaddr + image_base;
				method_sym->paddr = dsym->vaddr;
				method_sym->bind = R_BIN_BIND_GLOBAL_STR;
				method_sym->type = R_BIN_TYPE_FUNC_STR;
				method_sym->size = dsym->size;
				r_list_append (cls->methods, method_sym);
			}
		}
		free (tmp);
	}

	r_list_free (dotnet_symbols);
	return ret;
}

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!(ret = r_list_newf (r_bin_symbol_free))) {
		return NULL;
	}
	RBinPEObj *pe = PE_(get) (bf);
	if ((symbols = PE_(r_bin_pe_get_exports)(pe))) {
		for (i = 0; !symbols[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			ptr->name = r_bin_name_new ((char *)symbols[i].name);
			ptr->libname = *symbols[i].libname ? strdup ((char *)symbols[i].libname) : NULL;
			ptr->forwarder = r_str_constpool_get (&bf->rbin->constpool, (char *)symbols[i].forwarder);
			//strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = symbols[i].vaddr;
			ptr->paddr = symbols[i].paddr;
			ptr->ordinal = symbols[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (symbols);
	}

	if ((imports = PE_(r_bin_pe_get_imports)(pe))) {
		for (i = 0; !imports[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			ptr->name = r_bin_name_new ((const char *)imports[i].name);
			ptr->libname = strdup ((const char *)imports[i].libname);
			ptr->is_imported = true;
			//strncpy (ptr->forwarder, (char*)imports[i].forwarder, R_BIN_SIZEOF_STRINGS);
			ptr->bind = "NONE";
			ptr->type = R_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = imports[i].vaddr;
			ptr->paddr = imports[i].paddr;
			ptr->ordinal = imports[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (imports);
	}

	// Add .NET symbols if this is a .NET assembly
	if (pe && pe->dos_header && pe->nt_headers) {
		RBuffer *buf = bf->buf;
		const ut8 *data = r_buf_data (buf, NULL);
		size_t size = r_buf_size (buf);
		ut64 image_base = PE_(r_bin_pe_get_image_base)(pe);
		RList *dotnet_symbols = dotnet_parse (data, size, image_base);
		if (dotnet_symbols) {
			if (r_list_length (dotnet_symbols) > 0) {
				RListIter *iter;
				DotNetSymbol *dsym;
				r_list_foreach (dotnet_symbols, iter, dsym) {
					if (!dsym->type) {
						continue;
					}
					if (!strcmp (dsym->type, "methoddef")) {
						// Add methoddef at its RVA
						ptr = R_NEW0 (RBinSymbol);
						if (dsym->namespace && dsym->namespace[0]) {
							ptr->name = r_bin_name_new (r_str_newf ("%s.%s", dsym->namespace, dsym->name));
						} else {
							ptr->name = r_bin_name_new (dsym->name);
						}
						ptr->type = R_BIN_TYPE_FUNC_STR;
						ptr->bind = R_BIN_BIND_GLOBAL_STR;
						if (dsym->is_native) {
							ptr->lang = R_BIN_LANG_C;
						} else {
							ptr->lang = R_BIN_LANG_CIL;
						}
						if (dsym->vaddr > 0) {
							ptr->vaddr = dsym->vaddr + image_base;
							ptr->paddr = dsym->vaddr;
						}
						ptr->size = dsym->size;
						r_list_append (ret, ptr);
					}
#if 0
					// duplicated symbols for ref data. not necessasry
					if (dsym->token && (!strcmp (dsym->type, "methoddef") || !strcmp (dsym->type, "memberref"))) {
						// Add symbol at token address for disassembly resolution
						ptr = R_NEW0 (RBinSymbol);
						if (dsym->namespace && dsym->namespace[0]) {
							ptr->name = r_bin_name_new (r_str_newf ("%s.%s", dsym->namespace, dsym->name));
						} else {
							ptr->name = r_bin_name_new (dsym->name);
						}
						ptr->type = R_BIN_TYPE_FUNC_STR;
						ptr->bind = R_BIN_BIND_GLOBAL_STR;
						if (!strcmp (dsym->type, "methoddef") && !dsym->is_native) {
							ptr->lang = R_BIN_LANG_CIL;
						}
						ptr->vaddr = dsym->token;
						ptr->paddr = 0;
						ptr->size = 0;
						r_list_append (ret, ptr);
					}
#endif
				}
			}
			r_list_free (dotnet_symbols);
		}
	}

	find_pe_overlay (bf);
	return ret;
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

static RList* imports(RBinFile *bf) {
	RList *ret = NULL;
	RBinImport *ptr = NULL;
	RBinReloc *rel = NULL;
	int i;

	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return NULL;
	}
	if (!(ret = r_list_newf ((RListFree)r_bin_import_free))) {
		return NULL;
	}
	r_list_free (pe->relocs);
	RList *relocs = r_list_newf (free);
	if (!relocs) {
		free (ret);
		return NULL;
	}
	pe->relocs = relocs;

	struct r_bin_pe_import_t *imports = PE_(r_bin_pe_get_imports)(pe);
	if (!imports) {
		return ret;
	}
	for (i = 0; !imports[i].last; i++) {
		struct r_bin_pe_import_t *imp = &imports[i];
		if (!(ptr = R_NEW0 (RBinImport))) {
			break;
		}
		filter_import (imp->name);
		ptr->name = r_bin_name_new ((char*)imp->name);
		ptr->libname = strdup ((char*)imp->libname);
		ptr->bind = "NONE";
		ptr->type = "FUNC";
		ptr->ordinal = imp->ordinal;
		// NOTE(eddyb) a PE hint is just an optional possible DLL export table
		// index for the import. There is no point in exposing it.
		//ptr->hint = imp->hint;
		r_list_append (ret, ptr);

		if (!(rel = R_NEW0 (RBinReloc))) {
			break;
		}
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		{
			ut8 addr[4];
			r_buf_read_at (bf->buf, imp->paddr, addr, 4);
			ut64 newaddr = (ut64) r_read_le32 (&addr);
			rel->vaddr = newaddr;
		}
		rel->paddr = imp->paddr;
		rel->ntype = imp->ntype;
		r_list_append (relocs, rel);
	}
	free (imports);
	return ret;
}

static RList* relocs(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (pe && pe->relocs) {
		return r_list_clone (pe->relocs, NULL);
	}
	return NULL;
}

static RList* libs(RBinFile *bf) {
	struct r_bin_pe_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	RBinPEObj *pe = PE_(get) (bf);
	if (!(libs = PE_(r_bin_pe_get_libs)(pe))) {
		return ret;
	}
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static bool is_dot_net(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	struct r_bin_pe_lib_t *libs = PE_(r_bin_pe_get_libs)(pe);
	if (!libs) {
		return false;
	}

	size_t i;
	for (i = 0; !libs[i].last; i++) {
		if (!strcmp (libs[i].name, "mscoree.dll")) {
			free (libs);
			return true;
		}
	}
	free (libs);
	return false;
}

static bool is_vb6(RBinFile *bf) {
	int i;
	RBinPEObj *pe = PE_(get) (bf);
	struct r_bin_pe_lib_t *libs = PE_(r_bin_pe_get_libs)(pe);
	if (!libs) {
		return false;
	}
	for (i = 0; !libs[i].last; i++) {
		if (!strcmp (libs[i].name, "msvbvm60.dll")) {
			free (libs);
			return true;
		}
	}
	free (libs);
	return false;
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
	if (r_buf_read_at (bf->buf, addr, buf, sizeof (buf)) < 1) {
		goto out_fail;
	}
	if (buf[0] == 0x48) {
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
		ut64 rel_addr = (ut64)((int)(buf[5] + (buf[6] << 8) + (buf[7] << 16) + (buf[8] << 24)));
		ut64 calldst = addr + 5 + 4 + rel_addr;
		if (r_buf_read_at (bf->buf, calldst, buf, sizeof (buf)) < 1) {
			goto out_fail;
		}
		if (buf[0] != 0x48 && buf[1] != 0x89) {
			goto out_fail;
		}
		ut64 canaddr = 0;
		r_buf_read_at (bf->buf, calldst + 16, (ut8*)&canaddr, 4);

		ut32 panaddr = canaddr - 0x40; // PE_(va2pa)(bf->bo->bin_obj, canaddr);

		ut8 can0[8] = {0};
		r_buf_read_at (bf->buf, panaddr, can0, 8);
		ut8 can1[8] = {0};
		r_buf_read_at (bf->buf, calldst + 0x16, can1, 8);
		if (!memcmp (can0, can1, 8)) {
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
		ut64 rel_addr = (ut64)((int)(buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24)));
		ut64 calldst = addr + 5 + rel_addr;
		if (r_buf_read_at (bf->buf, calldst, buf, sizeof (buf)) < 1) {
			goto out_fail;
		}
		if (buf[0] == 0x8b && buf[1] == 0xff && buf[2] == 0x55) {
			goto out_succeed;
		}
		ut32 canaddr = 0;
		r_buf_read_at (bf->buf, calldst + 2, (ut8*)&canaddr, 4);
		ut32 panaddr = PE_(va2pa)(pe, canaddr);
		ut8 can0[4] = {0};
		r_buf_read_at (bf->buf, panaddr, can0, 4);
		ut8 can1[4] = {0};
		r_buf_read_at (bf->buf, calldst + 9, can1, 4);
		if (!memcmp (can0, can1, 4)) {
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
	// XXX: We only need imports here but this causes leaks, we need to wait for the below. This is a horrible solution!
	// TODO: use O(1) when imports sdbized
	RListIter *iter;
	RBinPEObj *pe = PE_(get) (bf);
	if (pe) {
		const RList* relocs_list = pe->relocs;
		RBinReloc *rel;
		if (relocs_list) {
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
		const RList* imports_list = imports (bf);
		RBinImport *imp;
		if (imports_list) {
			r_list_foreach (imports_list, iter, imp) {
				const char *name = r_bin_name_tostring2 (imp->name, 'o');
				if (!strcmp (name, "__security_init_cookie")) {
					return true;
				}
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
	if (!buf) {
		return false;
	}
	size_t idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (idx + 0x5E + 1 >= sz ) {
		return false;
	}
	//it's funny here idx+0x5E can be 158 and sz 159 but with
	//the cast it reads two bytes until 160
	return ((*(ut16*)(buf + idx + 0x5E)) & dllCharacteristic);
}

static RBinInfo* info(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return NULL;
	}
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = PE_(r_bin_pe_get_class) (pe);
	ret->rclass = strdup ("pe");
	ret->os = PE_(r_bin_pe_get_os) (pe);
	ret->arch = PE_(r_bin_pe_get_arch) (pe);
	ret->machine = PE_(r_bin_pe_get_machine) (pe);
	ret->subsystem = PE_(r_bin_pe_get_subsystem) (pe);
	ret->default_cc = PE_(r_bin_pe_get_cc) (pe);
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
	sdb_bool_set (db, "highva", haschr (bf, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA), 0);
	sdb_bool_set (db, "aslr", haschr (bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE), 0);
	sdb_bool_set (db, "forceintegrity", haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "nx", haschr (bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT), 0);
	sdb_bool_set (db, "isolation", !haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "seh", !haschr (bf, IMAGE_DLLCHARACTERISTICS_NO_SEH), 0);
	sdb_bool_set (db, "bind", !haschr (bf, IMAGE_DLLCHARACTERISTICS_NO_BIND), 0);
	sdb_bool_set (db, "appcontainer", haschr (bf, IMAGE_DLLCHARACTERISTICS_APPCONTAINER), 0);
	sdb_bool_set (db, "wdmdriver", haschr (bf, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER), 0);
	sdb_bool_set (db, "guardcf", haschr (bf, IMAGE_DLLCHARACTERISTICS_GUARD_CF), 0);
	sdb_bool_set (db, "terminalserveraware", haschr (bf, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE), 0);
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
			if (authhash) {
				authhash->type = strdup ("authentihash");
				authhash->hex = authentihash;
				r_list_push (file_hashes, authhash);
			}
		}
	}
	return file_hashes;
}
