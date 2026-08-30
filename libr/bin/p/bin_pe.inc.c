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
	if (!m || !m->arg_prefix || m->attr.lang != R_BIN_LANG_CIL) {
		return NULL;
	}
	const bool instance = !(m->attr.flags & R_BIN_ATTR_STATIC);
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

// ECMA-335 II.25.4.4 method body header flags
#define CIL_METHOD_MORE_SECTS 0x8
// ECMA-335 II.25.4.5 method data section kinds
#define CIL_SECT_EHTABLE 0x1
#define CIL_SECT_FATFORMAT 0x40
#define CIL_SECT_MORESECTS 0x80
// ECMA-335 II.25.4.6 exception clause flags
#define CIL_EH_CATCH 0x0
#define CIL_EH_FILTER 0x1
#define CIL_EH_FINALLY 0x2
#define CIL_EH_FAULT 0x4

static void normalize_dotnet_method_bodies(RBinFile *bf, RBinPEObj *pe, RList *symbols) {
	R_RETURN_IF_FAIL (bf && bf->buf && pe && symbols);
	const ut64 file_size = r_buf_size (bf->buf);
	RListIter *iter;
	DotNetSymbol *sym;
	r_list_foreach (symbols, iter, sym) {
		if (!sym->type || strcmp (sym->type, "methoddef") || !sym->vaddr) {
			continue;
		}
		sym->paddr = PE_(va2pa) (pe, sym->vaddr);
		if (sym->is_native || sym->paddr >= file_size) {
			continue;
		}
		ut8 header[12];
		if (r_buf_read_at (bf->buf, sym->paddr, header, 1) != 1) {
			continue;
		}
		ut32 header_size = 0;
		ut32 code_size = 0;
		bool more_sects = false;
		if ((header[0] & 3) == 2) {
			header_size = 1;
			code_size = header[0] >> 2;
		} else if ((header[0] & 3) == 3
				&& r_buf_read_at (bf->buf, sym->paddr, header, sizeof (header)) == sizeof (header)) {
			ut16 flags_size = r_read_le16 (header);
			header_size = ((flags_size >> 12) & 0xf) * 4;
			code_size = r_read_le32 (header + 4);
			// CorILMethod_MoreSects: the exception clauses follow the code
			more_sects = (flags_size & CIL_METHOD_MORE_SECTS) != 0;
			if (header_size < sizeof (header)) {
				header_size = 0;
			}
		}
		if (!header_size || header_size > file_size - sym->paddr
				|| code_size > file_size - sym->paddr - header_size) {
			continue;
		}
		sym->paddr += header_size;
		sym->vaddr += header_size;
		sym->hsize = header_size;
		sym->size = code_size;
		if (more_sects) {
			// the section headers are aligned to a 4 byte boundary
			ut64 at = (sym->paddr + code_size + 3) & ~(ut64)3;
			if (at >= sym->paddr && at + 4 <= file_size) {
				sym->eh_paddr = at;
			}
		}
	}
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
			normalize_dotnet_method_bodies (bf, pe, pe->dotnet_symbols);
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
						ptr->paddr = dsym->paddr;
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
			R_LOG_DEBUG ("Missing name for section %d at 0x%08"PFMT64x, i, (ut64)section->vaddr);
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

static RBinAttribute dotnet_type_attr(ut32 flags) {
	RBinAttribute attr = R_BIN_ATTR_NONE;
	switch (flags & 7) {
	case 1:
	case 2:
		attr |= R_BIN_ATTR_PUBLIC;
		break;
	case 3:
		attr |= R_BIN_ATTR_PRIVATE;
		break;
	case 4:
		attr |= R_BIN_ATTR_PROTECTED;
		break;
	case 5:
		attr |= R_BIN_ATTR_INTERNAL;
		break;
	case 6:
		attr |= R_BIN_ATTR_PROTECTED | R_BIN_ATTR_INTERNAL;
		break;
	default:
		break;
	}
	if (flags & 0x20) {
		attr |= R_BIN_ATTR_INTERFACE;
	}
	if (flags & 0x80) {
		attr |= R_BIN_ATTR_ABSTRACT;
	}
	if (flags & 0x100) {
		attr |= R_BIN_ATTR_SEALED;
	}
	return attr;
}

static RBinAttribute dotnet_method_attr(ut32 flags, const char *name) {
	RBinAttribute attr = R_BIN_ATTR_NONE;
	switch (flags & 7) {
	case 1:
		attr |= R_BIN_ATTR_PRIVATE;
		break;
	case 2:
		attr |= R_BIN_ATTR_PRIVATE | R_BIN_ATTR_PROTECTED;
		break;
	case 3:
		attr |= R_BIN_ATTR_INTERNAL;
		break;
	case 4:
		attr |= R_BIN_ATTR_PROTECTED;
		break;
	case 5:
		attr |= R_BIN_ATTR_PROTECTED | R_BIN_ATTR_INTERNAL;
		break;
	case 6:
		attr |= R_BIN_ATTR_PUBLIC;
		break;
	default:
		break;
	}
	if (flags & 0x10) {
		attr |= R_BIN_ATTR_STATIC;
	}
	if (flags & 0x20) {
		attr |= R_BIN_ATTR_FINAL;
	}
	if (flags & 0x40) {
		attr |= R_BIN_ATTR_VIRTUAL;
	}
	if (flags & 0x400) {
		attr |= R_BIN_ATTR_ABSTRACT;
	}
	if (flags & 0x2000) {
		attr |= R_BIN_ATTR_EXTERN | R_BIN_ATTR_NATIVE;
	}
	if (name && (!strcmp (name, ".ctor") || !strcmp (name, ".cctor"))) {
		attr |= R_BIN_ATTR_CONSTRUCTOR;
	}
	return attr;
}

static RBinAttribute dotnet_field_attr(ut32 flags) {
	RBinAttribute attr = R_BIN_ATTR_NONE;
	switch (flags & 7) {
	case 1:
		attr |= R_BIN_ATTR_PRIVATE;
		break;
	case 2:
		attr |= R_BIN_ATTR_PRIVATE | R_BIN_ATTR_PROTECTED;
		break;
	case 3:
		attr |= R_BIN_ATTR_INTERNAL;
		break;
	case 4:
		attr |= R_BIN_ATTR_PROTECTED;
		break;
	case 5:
		attr |= R_BIN_ATTR_PROTECTED | R_BIN_ATTR_INTERNAL;
		break;
	case 6:
		attr |= R_BIN_ATTR_PUBLIC;
		break;
	default:
		break;
	}
	if (flags & 0x10) {
		attr |= R_BIN_ATTR_STATIC;
	}
	if (flags & 0x20) {
		attr |= R_BIN_ATTR_READONLY;
	}
	if (flags & 0x40) {
		attr |= R_BIN_ATTR_CONST;
	}
	return attr;
}

static char *dotnet_symbol_name_by_token(RList *symbols, ut32 token) {
	RListIter *iter;
	DotNetSymbol *sym;
	r_list_foreach (symbols, iter, sym) {
		if (sym->token != token || !sym->name) {
			continue;
		}
		return R_STR_ISNOTEMPTY (sym->namespace)
			? r_str_newf ("%s.%s", sym->namespace, sym->name): strdup (sym->name);
	}
	return NULL;
}

// the type of a CIL catch clause is a TypeDef, TypeRef or TypeSpec token
static char *clr_class_name(RList *symbols, ut32 token) {
	switch (token >> 24) {
	case 0x01: // TypeRef
	case 0x02: // TypeDef
	case 0x1b: // TypeSpec
		return dotnet_symbol_name_by_token (symbols, token);
	}
	return NULL;
}

// ECMA-335 II.25.4.6 - parse the exception clauses of a single IL method body
static void clr_trycatch_method(RBinFile *bf, RVecRBinTrycatch *trycatch, RList *symbols, DotNetSymbol *sym, ut64 image_base) {
	const ut64 file_size = r_buf_size (bf->buf);
	const ut64 source = sym->vaddr + image_base;
	ut64 at = sym->eh_paddr;
	int section;
	// a method carries a handful of data sections at most, but a crafted
	// binary may chain them forever, so bound the walk
	for (section = 0; section < 8; section++) {
		ut8 shdr[4];
		if (at + sizeof (shdr) > file_size
				|| r_buf_read_at (bf->buf, at, shdr, sizeof (shdr)) != sizeof (shdr)) {
			return;
		}
		const ut8 kind = shdr[0];
		const bool fat = (kind & CIL_SECT_FATFORMAT) != 0;
		const ut32 data_size = fat
			? (ut32)shdr[1] | ((ut32)shdr[2] << 8) | ((ut32)shdr[3] << 16)
			: (ut32)shdr[1];
		const ut32 entry_size = fat? 24: 12;
		if (data_size < 4 + entry_size || at + data_size > file_size) {
			return;
		}
		if (kind & CIL_SECT_EHTABLE) {
			ut32 count = (data_size - 4) / entry_size;
			ut64 clause = at + 4;
			ut32 i;
			for (i = 0; i < count; i++, clause += entry_size) {
				ut8 buf[24];
				if (r_buf_read_at (bf->buf, clause, buf, entry_size) != (int)entry_size) {
					return;
				}
				ut32 flags, try_off, try_len, handler_off, handler_len, extra;
				if (fat) {
					flags = r_read_le32 (buf);
					try_off = r_read_le32 (buf + 4);
					try_len = r_read_le32 (buf + 8);
					handler_off = r_read_le32 (buf + 12);
					handler_len = r_read_le32 (buf + 16);
					extra = r_read_le32 (buf + 20);
				} else {
					flags = r_read_le16 (buf);
					try_off = r_read_le16 (buf + 2);
					try_len = buf[4];
					handler_off = r_read_le16 (buf + 5);
					handler_len = buf[7];
					extra = r_read_le32 (buf + 8);
				}
				// every offset is relative to the start of the method body
				if (try_off > sym->size || try_len > sym->size - try_off
						|| handler_off > sym->size || handler_len > sym->size - handler_off) {
					continue;
				}
				RBinTrycatch *tc = r_bin_trycatch_add (trycatch, source,
					source + try_off, source + try_off + try_len,
					source + handler_off,
					(flags & CIL_EH_FILTER) && extra <= sym->size? source + extra: 0);
				if (!tc) {
					return;
				}
				switch (flags & 7) {
				case CIL_EH_FILTER:
					tc->kind = R_BIN_TRYCATCH_FILTER;
					break;
				case CIL_EH_FINALLY:
				case CIL_EH_FAULT:
					tc->kind = R_BIN_TRYCATCH_CLEANUP;
					break;
				case CIL_EH_CATCH:
					tc->kind = R_BIN_TRYCATCH_CATCH;
					tc->type_filter = extra;
					tc->type = clr_class_name (symbols, extra);
					// catching System.Object catches everything
					tc->catch_all = tc->type && !strcmp (tc->type, "System.Object");
					break;
				default:
					break;
				}
			}
		}
		if (!(kind & CIL_SECT_MORESECTS)) {
			return;
		}
		at = (at + data_size + 3) & ~(ut64)3;
	}
}

// collect the exception clauses of every managed method in the assembly
static void clr_trycatch(RBinFile *bf, RVecRBinTrycatch *trycatch) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->clr_hdr) {
		return;
	}
	RList *symbols = get_dotnet_symbols (bf);
	if (!symbols) {
		return;
	}
	const ut64 image_base = PE_(r_bin_pe_get_image_base) (pe);
	RListIter *iter;
	DotNetSymbol *sym;
	r_list_foreach (symbols, iter, sym) {
		if (sym->eh_paddr && sym->type && !strcmp (sym->type, "methoddef")) {
			clr_trycatch_method (bf, trycatch, symbols, sym, image_base);
		}
	}
}

static RVecRBinTrycatch *pe_trycatch(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe) {
		return NULL;
	}
	if (!pe->trycatch_loaded) {
		pe->trycatch_loaded = true;
		clr_trycatch (bf, &pe->trycatch);
#ifndef R_BIN_PE64
		RVecRBinTrycatch_shrink_to_fit (&pe->trycatch);
#endif
	}
	return &pe->trycatch;
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
	r_bin_file_add_language (bf, R_BIN_LANG_CIL);
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
		char *super = dotnet_symbol_name_by_token (dotnet_symbols, dsym->extends_token);
		RBinClass *cls = r_bin_file_add_class (bf, fullname, super, dotnet_type_attr (dsym->flags));
		if (cls) {
			cls->attr.lang = R_BIN_LANG_CIL;
			if (!names_only && dsym->fields) {
				RListIter *iter_field;
				DotNetField *dfield;
				r_list_foreach (dsym->fields, iter_field, dfield) {
					RBinField *field = RVecRBinField_emplace_back (&cls->fields);
					field->name = r_bin_name_new (dfield->name);
					field->type = r_bin_name_new (r_str_get_fail (dfield->type_name, "unknown"));
					field->attr.kind = R_BIN_FIELD_KIND_FIELD;
					field->attr.lang = R_BIN_LANG_CIL;
					field->attr.flags = dotnet_field_attr (dfield->flags);
					field->attr.offset = dfield->offset;
				}
			}
		}
		free (super);
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
		if (!R_STR_ISNOTEMPTY (dsym->classname) || !R_STR_ISNOTEMPTY (dsym->short_name)) {
			continue;
		}
		if (!bf->rbin->options.load_unnamed
				&& (r_bin_name_is_unnamed (dsym->classname) || r_bin_name_is_unnamed (dsym->short_name))) {
			continue;
		}
		RBinClass *cls = r_bin_file_add_class (bf, dsym->classname, NULL, 0);
		if (cls) {
			cls->attr.lang = R_BIN_LANG_CIL;
		}
		RBinSymbol *m = r_bin_class_add_method (bf, dsym->classname, dsym->short_name, dsym->param_count);
		if (m) {
			m->attr.lang = R_BIN_LANG_CIL;
			m->attr.flags = dotnet_method_attr (dsym->flags, dsym->short_name);
			m->vaddr = dsym->vaddr + image_base;
			m->paddr = dsym->paddr;
			m->bind = R_BIN_BIND_GLOBAL_STR;
			m->type = R_BIN_TYPE_FUNC_STR;
			m->attr.size = dsym->size;
			m->rtype = strdup (r_str_get_fail (dsym->return_type, "unknown"));
			m->arg_first = 0;
			m->arg_count = dsym->param_count;
			m->cc_arg_count = dsym->param_count;
			m->ret_count = dsym->ret_count;
			m->arg_prefix = "a";
			if (dsym->signature) {
				m->name->name = strdup (dsym->short_name);
				r_bin_name_update (m->name, dsym->signature);
			}
		}
	}
	return NULL;
}

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
						r_strbuf_appendf (sb, "  %s %s;\n",
							r_str_get_fail (field->type_name, "unknown"), field->name);
					}
				}
			}
			r_strbuf_append (sb, "};\n\n");
		} else if (dsym->type && !strcmp (dsym->type, "methoddef")) {
			// Function signature
			r_strbuf_appendf (sb, "%s %s();\n",
				r_str_get_fail (dsym->return_type, "unknown"), dsym->name);
		}
	}

	return r_strbuf_drain (sb);
}

static bool symbols_vec(RBinFile *bf) {
	RBinSymbol *ptr = NULL;
	RVecPEExport *symbols = NULL;
	RVecPEImport *imports = NULL;
	bool has_native_dotnet = false;
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
				r_bin_file_add_language (bf, R_BIN_LANG_CIL);
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
						if (ptr->name && dsym->signature) {
							ptr->name->name = strdup (dsym->name);
							r_bin_name_update (ptr->name, dsym->signature);
						}
						ptr->type = R_BIN_TYPE_FUNC_STR;
						ptr->bind = R_BIN_BIND_GLOBAL_STR;
						if (dsym->is_native) {
							ptr->attr.lang = R_BIN_LANG_C;
							if (!has_native_dotnet) {
								r_bin_file_add_language (bf, R_BIN_LANG_C);
								has_native_dotnet = true;
							}
						} else {
							ptr->attr.lang = R_BIN_LANG_CIL;
							ptr->rtype = strdup (r_str_get_fail (dsym->return_type, "unknown"));
							ptr->arg_first = 0;
							ptr->arg_count = dsym->param_count;
							ptr->cc_arg_count = dsym->param_count;
							ptr->arg_prefix = "a";
							ptr->ret_count = dsym->ret_count;
							ptr->attr.flags |= dotnet_method_attr (dsym->flags, dsym->short_name);
							if (!dsym->is_instance) {
								ptr->attr.flags |= R_BIN_ATTR_STATIC;
							}
						}
						if (dsym->vaddr > 0) {
							ptr->vaddr = dsym->vaddr + image_base;
							ptr->paddr = dsym->paddr;
							ptr->hsize = dsym->hsize;
						}
						ptr->attr.size = dsym->size;
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
	RVecRBinReloc *relocs = &pe->relocs;
	RVecRBinReloc_clear (relocs);

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

		RBinReloc *rel = RVecRBinReloc_emplace_back (relocs);
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->import = r_bin_import_clone (ptr);
		rel->vaddr = r_buf_read_le32_at (bf->buf, imp->paddr);
		rel->paddr = imp->paddr;
		rel->ntype = imp->ntype;
	}
	RVecPEImport_free (imports);
	return true;
}

static RVecRBinReloc *relocs(RBinFile *bf) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || RVecRBinReloc_empty (&pe->relocs)) {
		return NULL;
	}
	RVecRBinReloc *ret = RVecRBinReloc_new ();
	if (ret) {
		RVecRBinReloc_swap (ret, &pe->relocs);
	}
	return ret;
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
	// the reloc list is 1:1 with the imports, so check those instead
	RBinImport *imp;
	R_VEC_FOREACH (&bf->bo->imports_vec, imp) {
		const char *name = r_bin_name_tostring2 (imp->name, 'o');
		if (!strcmp (name, "__security_init_cookie")) {
			return true;
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
		// when the pe is read from memory (dbg://) the buffer spans the whole
		// address space, so this is expected rather than a malformed binary
		R_LOG_DEBUG ("Skipping actual checksum of a %"PFMT64d" byte image", (st64)pe->size);
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

static const char *dotnet_token_name(RList *symbols, ut32 token) {
	RListIter *iter;
	DotNetSymbol *sym;
	r_list_foreach (symbols, iter, sym) {
		if (sym->token == token) {
			return sym->signature? sym->signature: sym->name;
		}
	}
	return NULL;
}

static bool dotnet_compressed_length(const ut8 *buf, int available, ut32 *value, int *prefix_size) {
	if (available < 1 || !value || !prefix_size) {
		return false;
	}
	if (!(buf[0] & 0x80)) {
		*value = buf[0];
		*prefix_size = 1;
		return true;
	}
	if ((buf[0] & 0xc0) == 0x80 && available >= 2) {
		*value = ((ut32)(buf[0] & 0x3f) << 8) | buf[1];
		*prefix_size = 2;
		return true;
	}
	if ((buf[0] & 0xe0) == 0xc0 && available >= 4) {
		*value = ((ut32)(buf[0] & 0x1f) << 24) | ((ut32)buf[1] << 16)
			| ((ut32)buf[2] << 8) | buf[3];
		*prefix_size = 4;
		return true;
	}
	return false;
}

typedef struct {
	char *string;
	ut64 paddr;
	ut64 vaddr;
	ut32 size;
	ut32 length;
	ut32 encoded_size;
} DotNetUserString;

static bool dotnet_user_string_at(RBinFile *bf, RBinPEObj *pe, ut32 index, DotNetUserString *result) {
	if (!bf || !bf->buf || !pe || !pe->clr_hdr || !pe->streams || !index || !result) {
		return false;
	}
	int i;
	for (i = 0; pe->streams[i]; i++) {
		PE_(image_metadata_stream) *stream = pe->streams[i];
		if (!stream->Name || strcmp (stream->Name, "#US")) {
			continue;
		}
		ut32 stream_size = stream->Size;
		if (index >= stream_size) {
			return false;
		}
		ut64 stream_rva = (ut64)pe->clr_hdr->MetaDataDirectoryAddress + stream->Offset;
		ut64 offset = PE_(va2pa) (pe, stream_rva) + index;
		ut8 prefix[4];
		int available = R_MIN ((ut32)sizeof (prefix), stream_size - index);
		if (r_buf_read_at (bf->buf, offset, prefix, available) != available) {
			return false;
		}
		ut32 length;
		int prefix_size;
		if (!dotnet_compressed_length (prefix, available, &length, &prefix_size)
				|| !length || length > stream_size - index - prefix_size
				|| length - 1 > (INT_MAX - 1) / 2) {
			return false;
		}
		int utf16_size = length - 1; // Last byte is the ECMA-335 terminal flag.
		ut8 *utf16 = malloc (R_MAX (utf16_size, 1));
		ut8 *utf8 = malloc (utf16_size * 2 + 1);
		if (!utf16 || !utf8
				|| (utf16_size && r_buf_read_at (bf->buf,
					offset + prefix_size, utf16, utf16_size) != utf16_size)) {
			free (utf16);
			free (utf8);
			return false;
		}
		int utf8_size = r_str_utf16_to_utf8 (utf8, utf16_size * 2 + 1,
			utf16, utf16_size, false);
		free (utf16);
		if (utf8_size < 0) {
			free (utf8);
			return false;
		}
		utf8[utf8_size] = 0;
		*result = (DotNetUserString){
			.string = (char *)utf8,
			.paddr = offset + prefix_size,
			.vaddr = PE_(r_bin_pe_get_image_base) (pe) + stream_rva + index + prefix_size,
			.size = utf16_size,
			.length = r_utf8_strlen (utf8),
			.encoded_size = prefix_size + length,
		};
		return true;
	}
	return false;
}

static const char *dotnet_user_string(RBinFile *bf, RBinPEObj *pe, ut32 index) {
	DotNetUserString us = {0};
	if (!dotnet_user_string_at (bf, pe, index, &us)) {
		return NULL;
	}
	char *escaped = r_str_escape (us.string);
	free (us.string);
	char *quoted = escaped? r_str_newf ("\"%s\"", escaped): NULL;
	free (escaped);
	const char *result = r_str_constpool_get (&bf->rbin->constpool, quoted);
	free (quoted);
	return result;
}

static RVecRBinString *strings(RBinFile *bf) {
	RVecRBinString *ret = r_bin_file_get_strings (bf,
		bf->rbin->options.minstrlen, 0, bf->rawstr);
	if (!ret) {
		ret = RVecRBinString_new ();
	}
	RBinPEObj *pe = PE_(get) (bf);
	if (!ret || !pe || !pe->clr_hdr || !pe->streams) {
		return ret;
	}
	int i;
	for (i = 0; pe->streams[i]; i++) {
		PE_(image_metadata_stream) *stream = pe->streams[i];
		if (!stream->Name || strcmp (stream->Name, "#US")) {
			continue;
		}
		ut32 index = 1; // Offset zero is reserved by ECMA-335.
		while (index < stream->Size) {
			DotNetUserString us = {0};
			if (!dotnet_user_string_at (bf, pe, index, &us)) {
				break;
			}
			RBinString *bs = RVecRBinString_emplace_back (ret);
			if (!bs) {
				free (us.string);
				break;
			}
			*bs = (RBinString){
				.string = us.string,
				.vaddr = us.vaddr,
				.paddr = us.paddr,
				.ordinal = index,
				.size = us.size,
				.length = us.length,
				.type = R_STRING_TYPE_WIDE,
			};
			index += us.encoded_size;
		}
		break;
	}
	return ret;
}

static const char *getname(RBinFile *bf, int type, int idx, bool sd) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->clr_hdr) {
		return NULL;
	}
	if (type == 's') {
		return dotnet_user_string (bf, pe, idx);
	}
	RList *dotnet_symbols = get_dotnet_symbols (bf);
	if (!dotnet_symbols) {
		return NULL;
	}
	(void)sd;
	ut32 token = 0;
	switch (type) {
	case 'r': token = 0x01000000 | idx; break;
	case 't': token = 0x02000000 | idx; break;
	case 'f': token = 0x04000000 | idx; break;
	case 'm': token = 0x06000000 | idx; break;
	case 'M': token = 0x0a000000 | idx; break;
	case 'S': token = 0x11000000 | idx; break;
	case 'T': token = 0x1b000000 | idx; break;
	case 'g': token = 0x2b000000 | idx; break;
	default: break;
	}
	return token? dotnet_token_name (dotnet_symbols, token): NULL;
}

static ut64 getoffset(RBinFile *bf, int type, int idx) {
	RBinPEObj *pe = PE_(get) (bf);
	if (!pe || !pe->clr_hdr || idx < 0) {
		return UT64_MAX;
	}
	if (type == 's') {
		DotNetUserString us = {0};
		if (!dotnet_user_string_at (bf, pe, idx, &us)) {
			return UT64_MAX;
		}
		free (us.string);
		return us.vaddr;
	}
	ut32 token = type == 'm'? 0x06000000 | idx: 0;
	RList *dotnet_symbols = token? get_dotnet_symbols (bf): NULL;
	if (dotnet_symbols) {
		RListIter *iter;
		DotNetSymbol *sym;
		r_list_foreach (dotnet_symbols, iter, sym) {
			if (sym->token == token && sym->vaddr) {
				return PE_(r_bin_pe_get_image_base) (pe) + sym->vaddr;
			}
		}
	}
	return UT64_MAX;
}
