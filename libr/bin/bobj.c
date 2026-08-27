/* radare2 - LGPL - Copyright 2009-2026 - pancake, nibble, dso */

#define R_LOG_ORIGIN "bin.obj"

#include <r_bin.h>
#include <sdb/ht_su.h>
#include <r_util.h>
#include "i/private.h"

R_API void r_bin_mem_free(void *data) {
	RBinMem *mem = (RBinMem *)data;
	if (mem) {
		if (mem->mirrors) {
			mem->mirrors->free = r_bin_mem_free;
			r_list_free (mem->mirrors);
		}
		free (mem->name);
		free (mem);
	}
}

// stable sort by vaddr: relocs with the same vaddr keep the plugin order
static void sort_relocs(RVecRBinReloc *relocs) {
	const size_t n = RVecRBinReloc_length (relocs);
	RBinReloc *a = R_VEC_START_ITER (relocs);
	size_t i;
	for (i = 1; i < n && a[i - 1].vaddr <= a[i].vaddr; i++) {
		;
	}
	if (i >= n) {
		return; // already sorted, the common case
	}
	RBinReloc *tmp = R_NEWS (RBinReloc, n);
	if (!tmp) {
		return;
	}
	RBinReloc *src = a, *dst = tmp;
	size_t width;
	for (width = 1; width < n; width *= 2) {
		for (i = 0; i < n; i += 2 * width) {
			size_t l = i, m = R_MIN (i + width, n), k = i;
			const size_t lend = m, r = R_MIN (i + 2 * width, n);
			while (l < lend && m < r) {
				dst[k++] = (src[m].vaddr < src[l].vaddr)? src[m++]: src[l++];
			}
			while (l < lend) {
				dst[k++] = src[l++];
			}
			while (m < r) {
				dst[k++] = src[m++];
			}
		}
		RBinReloc *t = src;
		src = dst;
		dst = t;
	}
	if (src != a) {
		memcpy (a, src, n * sizeof (RBinReloc));
	}
	free (tmp);
}

R_API void r_bin_object_import_cache_cleanup(RBinObject *o) {
	if (o) {
		ht_pp_free (o->import_name_ht);
		ht_up_free (o->import_addr_ht);
		o->import_name_ht = NULL;
		o->import_addr_ht = NULL;
		o->import_symbols = NULL;
	}
}

static void import_cache_cleanup(RBinObject *o) {
	r_bin_object_import_cache_cleanup (o);
}

static void clamp_list(RList *list, int limit) {
	if (!list || limit < 1) {
		return;
	}
	while (r_list_length (list) > (ut32)limit) {
		r_list_delete (list, list->tail);
	}
}

static void rebase_strings_vec(RBinObject *bo) {
	RBinString *string;
	R_VEC_FOREACH (&bo->strings, string) {
		string->paddr += bo->loadaddr;
	}
}

static void clamp_strings_vec(RVecRBinString *vec, int limit) {
	size_t len = RVecRBinString_length (vec);
	if (limit >= 1 && len > (size_t)limit) {
		RVecRBinString_erase_back (vec, RVecRBinString_at (vec, (size_t)limit));
	}
}

// Trim an RVec to at most `limit` elements (no-op when limit < 1). erase_back
// invokes the vec's fini_fn for each dropped element, matching pop_back.
#define CLAMP_VEC(T, vec, limit) do { \
	T *_v = (vec); \
	int _l = (limit); \
	if (_l >= 1 && T##_length (_v) > (size_t)_l) { \
		T##_erase_back (_v, T##_at (_v, (size_t)_l)); \
	} \
} while (0)

// take ownership of the relocs returned by the plugin: clamp, rebase and sort by vaddr
static void set_relocs(RBinObject *bo, RVecRBinReloc *relocs, int limit) {
	RVecRBinReloc_free (bo->relocs);
	CLAMP_VEC (RVecRBinReloc, relocs, limit);
	if (bo->loadaddr) {
		RBinReloc *r;
		R_VEC_FOREACH (relocs, r) {
			r->paddr += bo->loadaddr;
		}
	}
	sort_relocs (relocs);
	RVecRBinReloc_shrink_to_fit (relocs);
	bo->relocs = relocs;
}

static void rebase_sections_vec(RBinObject *bo) {
	RBinSection *section;
	R_VEC_FOREACH (&bo->sections_vec, section) {
		section->paddr += bo->loadaddr;
	}
}

static bool bin_name_has_value(RBinName *name) {
	return name && ((R_STR_ISNOTEMPTY (name->name) && !r_bin_name_is_unnamed (name->name))
		|| (R_STR_ISNOTEMPTY (name->oname) && !r_bin_name_is_unnamed (name->oname))
		|| (R_STR_ISNOTEMPTY (name->fname) && !r_bin_name_is_unnamed (name->fname)));
}

static bool symbol_has_value(RBinSymbol *sym) {
	const char *name = sym && sym->name? sym->name->name: NULL;
	bool entry = name && r_str_startswith (name, "entry") && r_str_isnumber (name + 5);
	return sym && !(sym->attr.flags & R_BIN_ATTR_SYNTHETIC) && (entry || bin_name_has_value (sym->name));
}

static void filter_unnamed_symbols_vec(RBinFile *bf, RVecRBinSymbol *symbols) {
	size_t i = 0;
	while (i < RVecRBinSymbol_length (symbols)) {
		RBinSymbol *sym = RVecRBinSymbol_at (symbols, i);
		r_bin_register_symbol_language (bf, sym);
		if (symbol_has_value (sym)) {
			i++;
		} else {
			RVecRBinSymbol_remove (symbols, i);
		}
	}
}

static void filter_unnamed_imports_vec(RVecRBinImport *imports) {
	size_t i = 0;
	while (i < RVecRBinImport_length (imports)) {
		RBinImport *imp = RVecRBinImport_at (imports, i);
		if (imp && bin_name_has_value (imp->name)) {
			i++;
		} else {
			RVecRBinImport_remove (imports, i);
		}
	}
}

// Promote class methods built by plugins (objc/pe/java/demangler/...) into
// bo->symbols_vec so they show up in `iS` and other symbol consumers. Methods
// whose vaddr is already in symbols_vec (dex/clone-from-symbols paths) are
// skipped to avoid double-listing. Runs before reloc creation so subsequent
// realloc-stability assumptions hold.
static void sync_class_methods_to_symbols_vec(RBinObject *bo) {
	if (!bo || !bo->classes) {
		return;
	}
	HtUP *seen = ht_up_new0 ();
	if (!seen) {
		return;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (&bo->symbols_vec, sym) {
		if (sym->vaddr && sym->vaddr != UT64_MAX) {
			ht_up_insert (seen, sym->vaddr, sym);
		}
	}
	RBinClass *cls;
	RListIter *it;
	r_list_foreach (bo->classes, it, cls) {
		RBinSymbol *m;
		R_VEC_FOREACH (&cls->methods, m) {
			if (!m->name || !m->vaddr || m->vaddr == UT64_MAX) {
				continue;
			}
			if (ht_up_find (seen, m->vaddr, NULL)) {
				continue;
			}
			RBinSymbol *dst = RVecRBinSymbol_emplace_back (&bo->symbols_vec);
			r_bin_symbol_copy (dst, m);
			ht_up_insert (seen, m->vaddr, dst);
		}
	}
	ht_up_free (seen);
}

static void filter_unnamed_classes(RBinFile *bf, RList *classes) {
	RListIter *iter, *tmp;
	RBinClass *klass;
	r_list_foreach_safe (classes, iter, tmp, klass) {
		if (klass && klass->attr.lang != R_BIN_LANG_NONE) {
			r_bin_file_add_language (bf, klass->attr.lang);
		}
		if (!klass || (klass->attr.flags & R_BIN_ATTR_SYNTHETIC) || !bin_name_has_value (klass->name)) {
			r_list_delete (classes, iter);
			continue;
		}
		size_t i = 0;
		while (i < RVecRBinSymbol_length (&klass->methods)) {
			RBinSymbol *method = RVecRBinSymbol_at (&klass->methods, i);
			r_bin_register_symbol_language (bf, method);
			if (!symbol_has_value (method)) {
				RVecRBinSymbol_remove (&klass->methods, i);
			} else {
				i++;
			}
		}
	}
}

static bool classes_names_only(RBinFile *bf) {
	return bf && bf->rbin && bf->rbin->options.classes_names_only;
}

static void class_drop_details(RBinClass *klass) {
	if (klass) {
		RVecRBinSymbol_clear (&klass->methods);
		RVecRBinField_clear (&klass->fields);
	}
}

static void classes_drop_details(RList *classes) {
	RBinClass *klass;
	RListIter *iter;
	r_list_foreach (classes, iter, klass) {
		class_drop_details (klass);
	}
}

static void object_delete_items(RBinObject *o) {
	R_RETURN_IF_FAIL (o);
	ut32 i = 0;
	r_strpool_free (o->pool);
	ht_up_free (o->addr2klassmethod);
	ht_up_free (o->symbol_addr_ht);
	o->symbol_addr_ht = NULL;
	r_list_free (o->entries);
	r_list_free (o->fields);
	r_list_free (o->libs);
	RVecRBinReloc_free (o->relocs);
	RVecRBinString_fini (&o->strings);
	ht_up_free (o->strings_db);

	RVecRBinImport_fini (&o->imports_vec);
	RVecRBinSymbol_fini (&o->symbols_vec);
	RVecRBinSection_fini (&o->sections_vec);
	RVecRBinResource_fini (&o->resources_vec);

	r_list_free (o->classes);
	ht_pp_free (o->classes_ht);
	r_list_free (o->lines);
	sdb_free (o->kv);
	r_list_free (o->mem);
	for (i = 0; i < R_BIN_SYM_LAST; i++) {
		free (o->binsym[i]);
	}
	ht_pp_free (o->import_name_ht);
	ht_up_free (o->import_addr_ht);
	o->import_name_ht = NULL;
	o->import_addr_ht = NULL;
	o->import_symbols = NULL;
	/* free optional filter hashtables if present */
	if (o->filters) {
		/* Attempt to free as HtPP first; if type mismatch, free as HtSU */
		/* These tables are internal and optional; free whichever was used */
		ht_pp_free ((HtPP *)o->filters);
		o->filters = NULL;
	}
}

R_IPI void r_bin_object_free(void /*RBinObject*/ *o_) {
	RBinObject *o = o_;
	if (o) {
		free (o->regstate);
		r_bin_info_free (o->info);
		object_delete_items (o);
		free (o);
	}
}

static char *swiftField(const char *dn, const char *cn) {
	if (!dn || !cn) {
		return NULL;
	}

	char *p = strstr (dn, ".getter_");
	if (!p) {
		p = strstr (dn, ".setter_");
		if (!p) {
			p = strstr (dn, ".method_");
		}
	}
	if (p) {
		char *q = strstr (dn, cn);
		if (q && q[strlen (cn)] == '.') {
			q = strdup (q + strlen (cn) + 1);
			char *r = strchr (q, '.');
			if (r) {
				*r = 0;
			}
			return q;
		}
	}
	return NULL;
}

typedef struct {
	RBinSymbol *sym;
	char *classname;
	char *method;
	RBinLanguage lang;
	RBinAttribute flags;
	bool proves_class;
} CxxMemberInfo;

static void cxx_member_info_free(void *ptr) {
	CxxMemberInfo *info = ptr;
	if (info) {
		free (info->classname);
		free (info->method);
		free (info);
	}
}

static const char *cxx_last_scope(const char *start, const char *end) {
	int angles = 0;
	const char *p = end;
	while (p > start) {
		p--;
		if (*p == '>') {
			angles++;
		} else if (*p == '<' && angles > 0) {
			angles--;
		} else if (!angles && *p == ':' && p > start && p[-1] == ':') {
			return p - 1;
		}
	}
	return NULL;
}

static const char *cxx_call_open(const char *name) {
	const char *p = strrchr (name, ')');
	if (!p) {
		return NULL;
	}
	int depth = 1;
	while (p > name) {
		p--;
		if (*p == ')') {
			depth++;
		} else if (*p == '(' && --depth == 0) {
			return p;
		}
	}
	return NULL;
}

static char *cxx_demangled_symbol(RBinSymbol *sym, RBinLanguage *lang_out) {
	const char *dname = r_bin_name_tostring2 (sym->name, 'd');
	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	RBinLanguage lang = sym->attr.lang;
	if (lang == R_BIN_LANG_NONE && R_STR_ISNOTEMPTY (oname)) {
		lang = r_bin_lang_from_symbol_name (oname);
	}
	if (lang_out) {
		*lang_out = lang == R_BIN_LANG_IBMXL? R_BIN_LANG_IBMXL: R_BIN_LANG_CXX;
	}
	if (R_STR_ISEMPTY (oname)) {
		return NULL;
	}
	const char *mangled = oname;
	const char *prefixes[] = { "sym.imp.", "imp.", "reloc.", NULL };
	int i;
	for (i = 0; prefixes[i]; i++) {
		if (r_str_startswith (mangled, prefixes[i])) {
			mangled += strlen (prefixes[i]);
			break;
		}
	}
	const bool itanium = r_str_startswith (mangled, "_Z") || r_str_startswith (mangled, "__Z");
	if (lang != R_BIN_LANG_CXX && lang != R_BIN_LANG_IBMXL && !itanium) {
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (dname) && R_STR_ISNOTEMPTY (oname) && strcmp (dname, oname)) {
		return strdup (dname);
	}
	if (lang == R_BIN_LANG_RUST) {
		return NULL;
	}
	return r_bin_demangle_cxx (NULL, oname, sym->vaddr);
}

static char *cxx_basename(const char *name) {
	const char *scope = cxx_last_scope (name, name + strlen (name));
	char *base = strdup (scope? scope + 2: name);
	if (!base) {
		return NULL;
	}
	char *template = strchr (base, '<');
	if (template) {
		*template = 0;
	}
	char *tag = strchr (base, '[');
	if (tag) {
		*tag = 0;
	}
	return base;
}

static CxxMemberInfo *cxx_member_info(RBinSymbol *sym) {
	RBinLanguage lang;
	char *demangled = cxx_demangled_symbol (sym, &lang);
	if (!demangled) {
		return NULL;
	}
	CxxMemberInfo *info = R_NEW0 (CxxMemberInfo);
	if (!info) {
		free (demangled);
		return NULL;
	}
	info->sym = sym;
	info->lang = lang;
	const char *name = demangled;
	const char *thunk_prefixes[] = {
		"non-virtual thunk to ",
		"virtual thunk to ",
		"covariant return thunk to ",
		NULL
	};
	int i;
	for (i = 0; thunk_prefixes[i]; i++) {
		if (r_str_startswith (name, thunk_prefixes[i])) {
			name += strlen (thunk_prefixes[i]);
			info->flags |= R_BIN_ATTR_SYNTHETIC;
			info->proves_class = true;
			break;
		}
	}
	const char *class_prefixes[] = {
		"vtable for ",
		"VTT for ",
		"typeinfo for ",
		"typeinfo name for ",
		NULL
	};
	for (i = 0; class_prefixes[i]; i++) {
		if (r_str_startswith (name, class_prefixes[i])) {
			name += strlen (class_prefixes[i]);
			if (R_STR_ISNOTEMPTY (name) && !r_str_startswith (name, "__cxxabiv1::")) {
				info->classname = strdup (name);
				info->proves_class = true;
			}
			free (demangled);
			return info;
		}
	}
	const char *open = cxx_call_open (name);
	if (!open) {
		free (demangled);
		cxx_member_info_free (info);
		return NULL;
	}
	const char *scope = cxx_last_scope (name, open);
	if (!scope) {
		free (demangled);
		cxx_member_info_free (info);
		return NULL;
	}
	const char *owner = scope;
	int angles = 0;
	while (owner > name) {
		const char ch = owner[-1];
		if (ch == '>') {
			angles++;
		} else if (ch == '<' && angles > 0) {
			angles--;
		} else if (!angles && IS_WHITESPACE (ch)) {
			break;
		}
		owner--;
	}
	info->classname = r_str_ndup (owner, scope - owner);
	info->method = strdup (scope + 2);
	if (!info->classname || !info->method) {
		free (demangled);
		cxx_member_info_free (info);
		return NULL;
	}
	char *owner_base = cxx_basename (info->classname);
	char *method_base = r_str_ndup (scope + 2, open - (scope + 2));
	if (!owner_base || !method_base) {
		free (owner_base);
		free (method_base);
		free (demangled);
		cxx_member_info_free (info);
		return NULL;
	}
	char *tag = strchr (method_base, '[');
	if (tag) {
		*tag = 0;
	}
	char *template = strchr (method_base, '<');
	if (template) {
		*template = 0;
	}
	if (!strcmp (owner_base, method_base)) {
		info->flags |= R_BIN_ATTR_CONSTRUCTOR;
		info->proves_class = true;
	} else if (*method_base == '~' && !strcmp (owner_base, method_base + 1)) {
		info->flags |= R_BIN_ATTR_DESTRUCTOR;
		info->proves_class = true;
	}
	free (owner_base);
	free (method_base);
	const char *close = strrchr (open, ')');
	if (close) {
		if (strstr (close + 1, " const")) {
			info->flags |= R_BIN_ATTR_CONST;
			info->proves_class = true;
		}
		if (strstr (close + 1, " volatile")) {
			info->flags |= R_BIN_ATTR_VOLATILE;
			info->proves_class = true;
		}
		if (strstr (close + 1, " &")) {
			info->proves_class = true;
		}
	}
	free (demangled);
	return info;
}

static RBinClass *cxx_add_class(RBinFile *bf, CxxMemberInfo *info) {
	RBinClass *c = r_bin_file_add_class (bf, info->classname, NULL, 0);
	if (c) {
		c->origin = R_BIN_CLASS_ORIGIN_NAME;
		c->attr.lang = info->lang;
		r_bin_file_add_language (bf, info->lang);
	}
	return c;
}

static bool cxx_class_has_method(RBinClass *c, CxxMemberInfo *info) {
	RBinSymbol *method;
	R_VEC_FOREACH (&c->methods, method) {
		const char *name = r_bin_name_tostring2 (method->name, 'd');
		if (method->vaddr == info->sym->vaddr && name && !strcmp (name, info->method)) {
			return true;
		}
	}
	return false;
}

static void cxx_add_method(RBinFile *bf, CxxMemberInfo *info) {
	RBinClass *c = ht_pp_find (bf->bo->classes_ht, info->classname, NULL);
	if (!c) {
		return;
	}
	if (!c->addr) {
		c->addr = info->sym->vaddr;
	}
	free (info->sym->classname);
	info->sym->classname = strdup (info->classname);
	info->sym->attr.lang = info->lang;
	info->sym->attr.flags |= info->flags;
	if (classes_names_only (bf) || cxx_class_has_method (c, info)) {
		return;
	}
	RBinSymbol *copy = r_bin_symbol_clone (info->sym);
	if (!copy) {
		return;
	}
	r_bin_name_demangled (copy->name, info->method);
	RBinSymbol *dst = RVecRBinSymbol_emplace_back (&c->methods);
	if (!dst) {
		r_bin_symbol_free (copy);
		return;
	}
	*dst = *copy;
	free (copy);
}

static void classes_from_symbol_language(RBinFile *bf, RBinSymbol *sym) {
	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	if (!oname || oname[0] != '_') {
		return;
	}
	const char *cn = sym->classname;
	if (!cn) {
		return;
	}
	// swift specific
	char *dn = r_bin_name_tostring2 (sym->name, 'd');
	char *fn = swiftField (dn, cn);
	if (fn) {
		RBinClass *c = r_bin_file_add_class (bf, sym->classname, NULL, 0);
		if (c && !classes_names_only (bf)) {
			RBinField *f = RVecRBinField_emplace_back (&c->fields);
			f->name = r_bin_name_new (fn);
			f->paddr = sym->paddr;
			f->vaddr = sym->vaddr;
			f->value = -1;
			f->attr.size = sym->attr.size;
		}
		free (fn);
	} else {
		char *mn = strstr (dn, "..");
		if (!mn) {
			mn = strstr (dn, cn);
			if (mn && mn[strlen (cn)] == '.') {
				RBinClass *c = r_bin_file_add_class (bf, sym->classname, NULL, 0);
				if (c && !classes_names_only (bf)) {
					RBinSymbol *bs = r_bin_symbol_clone (sym);
					RBinSymbol *dst = RVecRBinSymbol_emplace_back (&c->methods);
					*dst = *bs;
					free (bs);
				}
			}
		}
	}
}

static RList *classes_from_symbols(RBinFile *bf, bool include_language_symbols) {
	RList *cxx_members = r_list_newf (cxx_member_info_free);
	if (!cxx_members) {
		return bf->bo->classes;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (&bf->bo->symbols_vec, sym) {
		CxxMemberInfo *info = cxx_member_info (sym);
		if (info && info->classname) {
			if (info->proves_class) {
				cxx_add_class (bf, info);
			}
			if (info->method) {
				if (r_list_append (cxx_members, info)) {
					continue;
				}
			}
		}
		cxx_member_info_free (info);
	}
	CxxMemberInfo *info;
	RListIter *iter;
	r_list_foreach (cxx_members, iter, info) {
		cxx_add_method (bf, info);
	}
	r_list_free (cxx_members);
	if (include_language_symbols) {
		R_VEC_FOREACH (&bf->bo->symbols_vec, sym) {
			classes_from_symbol_language (bf, sym);
		}
	}
	return bf->bo->classes;
}

// TODO: kill offset and sz, because those should be inferred from binfile->buf
R_IPI RBinObject *r_bin_object_new(RBinFile *bf, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz) {
	R_RETURN_VAL_IF_FAIL (bf && plugin, NULL);
	ut64 bytes_sz = r_buf_size (bf->buf);
	RBinObject *bo = R_NEW0 (RBinObject);
	bo->obj_size = (bytes_sz >= sz + offset)? sz: 0;
	bo->boffset = offset;
	bo->regstate = NULL;
	bo->kv = sdb_new0 (); // XXX bf->sdb bf->bo->sdb wtf
	bo->baddr = baseaddr;
	bo->classes = r_list_newf ((RListFree)r_bin_class_free);
	bo->classes_ht = ht_pp_new0 ();
	bo->import_name_ht = NULL;
	bo->import_addr_ht = NULL;
	bo->import_symbols = NULL;
	bo->baddr_shift = 0;
	bo->plugin = plugin;
	bo->loadaddr = loadaddr != UT64_MAX ? loadaddr : 0;
	RVecRBinSymbol_init (&bo->symbols_vec);
	RVecRBinImport_init (&bo->imports_vec);
	RVecRBinSection_init (&bo->sections_vec);
	RVecRBinResource_init (&bo->resources_vec);
	RVecRBinString_init (&bo->strings);
	bo->pool = r_strpool_new ();
	bf->bo = bo;

	if (plugin && plugin->load) {
		if (!plugin->load (bf, bf->buf, loadaddr)) {
			R_LOG_DEBUG ("load failed for %s plugin", plugin->meta.name);
			goto fail;
		}
	} else {
		R_LOG_WARN ("Plugin %s should implement load method", plugin->meta.name);
		goto fail;
	}

	// XXX - object size can't be set here and needs to be set where where
	// the object is created from. The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is
	// extracted from a set of bytes in the file
	r_bin_file_set_obj (bf->rbin, bf, bo);
	r_bin_set_baddr (bf->rbin, bo->baddr);
	r_bin_object_set_items (bf, bo);

	bf->sdb_info = bo->kv;
	Sdb *root_bin_sdb = bf->rbin->sdb;
	if (root_bin_sdb) {
		Sdb *bdb = bf->sdb; // sdb_new0 ();
		if (!sdb_ns (bdb, "info", 0)) {
			sdb_ns_set (bdb, "info", bo->kv);
		}
		bo->kv = bdb;
		sdb_set (bf->sdb, "archs", "0:0:x86:32", 0); // x86??
		sdb_ns_set (root_bin_sdb, "cur", bdb); // bf->sdb);
		r_strf_var (fdns, 32, "fd.%d", bf->fd);
		sdb_ns_set (root_bin_sdb, fdns, bdb); // bf->sdb);
	}
	return bo;

fail:
	r_strpool_free (bo->pool);
	RVecRBinSymbol_fini (&bo->symbols_vec);
	RVecRBinResource_fini (&bo->resources_vec);
	RVecRBinString_fini (&bo->strings);
	if (bo->import_name_ht || bo->import_addr_ht) {
		import_cache_cleanup (bo);
	}
	ht_pp_free (bo->classes_ht);
	r_list_free (bo->classes);
	sdb_free (bo->kv);
	ht_up_free (bo->strings_db);
	free (bo);
	bf->bo = NULL;
	return NULL;
}

static bool filter_classes(RBinFile *bf, RList *list) {
	bool rc = true;
	HtSU *db = ht_su_new0 ();
	HtPP *ht = ht_pp_new0 ();
	RListIter *iter;
	RBinClass *cls;
	RBinSymbol *sym;
	const bool names_only = classes_names_only (bf);
	r_list_foreach (list, iter, cls) {
		if (cls->attr.lang != R_BIN_LANG_NONE) {
			r_bin_file_add_language (bf, cls->attr.lang);
		}
		const char *kname = r_bin_name_tostring (cls->name);
		char *fname = r_bin_filter_name (bf, db, cls->index, kname);
		if (R_STR_ISEMPTY (fname)) {
			R_LOG_INFO ("Corrupted class storage with nameless classes");
			rc = false;
			free (fname);
			break;
		}
		r_bin_name_update (cls->name, fname);
		free (fname);
		if (names_only) {
			continue;
		}
		R_VEC_FOREACH (&cls->methods, sym) {
			if (R_LIKELY (sym->name)) {
				r_bin_filter_sym (bf, ht, sym->vaddr, sym);
			} else {
				R_LOG_INFO ("Unnamed method. Assuming corrupted storage");
				break;
			}
		}
	}
	ht_su_free (db);
	ht_pp_free (ht);
	return rc;
}

static void r_bin_object_rebuild_classes_ht(RBinObject *bo) {
	ht_pp_free (bo->classes_ht);
	bo->classes_ht = ht_pp_new0 ();

	RListIter *it;
	RBinClass *klass;
	r_list_foreach (bo->classes, it, klass) {
		if (klass->name) {
			ht_pp_insert (bo->classes_ht, klass->name, klass);
		}
	}
}

R_API int r_bin_object_set_items(RBinFile *bf, RBinObject *bo) {
	R_RETURN_VAL_IF_FAIL (bf && bo && bo->plugin, false);

	int i;
	bool isSwift = false;
	RBin *bin = bf->rbin;
	RBinPlugin *p = bo->plugin;
	const int limit = bin->options.limit;
	int minlen = (bf->rbin->options.minstrlen > 0) ? bf->rbin->options.minstrlen : p->minstrlen;
	bf->bo = bo;

	if (p->info) {
		r_bin_info_free (bo->info);
		bo->info = p->info (bf);
	} else {
		bo->info = NULL;
	}
	if (bo->info && bo->info->type) {
		if (strstr (bo->info->type, "CORE")) {
			if (p->regstate) {
				bo->regstate = p->regstate (bf);
			}
			if (p->maps) {
				bo->maps = p->maps (bf);
			}
		}
	}
	// XXX: no way to get info from xtr pluginz?
	// Note, object size can not be set from here due to potential
	// inconsistencies
	if (p->size) {
		bo->size = p->size (bf);
	}
	if (p->binsym) {
		for (i = 0; i < R_BIN_SYM_LAST; i++) {
			bo->binsym[i] = p->binsym (bf, i);
			if (bo->binsym[i]) {
				bo->binsym[i]->paddr += bo->loadaddr;
			}
		}
	}
	if (p->entries) {
		bo->entries = p->entries (bf);
		clamp_list (bo->entries, limit);
		REBASE_PADDR (bo, bo->entries, RBinAddr);
	}
	if (p->fields) {
		bo->fields = p->fields (bf);
		if (bo->fields) {
			bo->fields->free = r_bin_field_free;
			REBASE_PADDR (bo, bo->fields, RBinField);
		}
	}
	if (p->imports_vec) {
		p->imports_vec (bf);
		if (!bin->options.load_unnamed) {
			filter_unnamed_imports_vec (&bo->imports_vec);
		}
		CLAMP_VEC (RVecRBinImport, &bo->imports_vec, limit);
		import_cache_cleanup (bo);
	}
	if (p->symbols_vec) {
		p->symbols_vec (bf);
		import_cache_cleanup (bo);
		if (!bin->options.load_unnamed) {
			filter_unnamed_symbols_vec (bf, &bo->symbols_vec);
		}
		if (bin->filter && bin->options.load_unnamed) {
			RBinSymbol *sym;
			HtPP *ht = ht_pp_new0 ();
			if (ht) {
				R_VEC_FOREACH (&bo->symbols_vec, sym) {
					r_bin_filter_sym (bf, ht, sym->vaddr, sym);
				}
				ht_pp_free (ht);
			}
		}
		CLAMP_VEC (RVecRBinSymbol, &bo->symbols_vec, limit);
	}
	if (p->info) {
		r_bin_info_free (bo->info);
		bo->info = p->info (bf);
	} else {
		bo->info = NULL;
	}
	if (p->libs) {
		bo->libs = p->libs (bf);
		clamp_list (bo->libs, limit);
	}
	if (p->sections_vec) {
		RVecRBinSection_clear (&bo->sections_vec);
		if (p->sections_vec (bf)) {
			rebase_sections_vec (bo);
			CLAMP_VEC (RVecRBinSection, &bo->sections_vec, limit);
			if (bin->filter) {
				r_bin_filter_sections_vec (bf, &bo->sections_vec);
			}
		}
	}
	// Load classes before reloc creation. Class-method-creating plugins
	// (objc/pe/java/demangler/...) push into bo->symbols_vec via
	// sync_class_methods_to_symbols_vec, which must happen before reloc
	// plugins capture their symbol pointers (see Stabilize commit).
	if (bin->filter_rules & R_BIN_REQ_CLASSES) {
		if (p->classes) {
			RList *classes = p->classes (bf);
			if (classes) {
				// XXX we should probably merge them instead
				r_list_free (bo->classes);
				bo->classes = classes;
				r_bin_object_rebuild_classes_ht (bo);
			}
			isSwift = r_bin_lang_swift (bf);
			classes_from_symbols (bf, isSwift);
			r_bin_object_rebuild_classes_ht (bo);
		} else {
			RList *classes = classes_from_symbols (bf, true);
			if (classes) {
				bo->classes = classes;
			}
		}
		if (bin->options.classes_names_only) {
			classes_drop_details (bo->classes);
		}
		if (!bin->options.load_unnamed) {
			filter_unnamed_classes (bf, bo->classes);
			r_bin_object_rebuild_classes_ht (bo);
		}
		if (bin->filter && bin->options.load_unnamed) {
			filter_classes (bf, bo->classes);
		}
		if (bin->options.classes_names_only) {
			r_bin_object_rebuild_classes_ht (bo);
		}
		sync_class_methods_to_symbols_vec (bo);
	}
	// Some reloc plugins keep pointers into these vectors, so compact them
	// before reloc creation and do not move them afterwards.
	RVecRBinSymbol_shrink_to_fit (&bo->symbols_vec);
	RVecRBinImport_shrink_to_fit (&bo->imports_vec);
	if (bin->filter_rules & (R_BIN_REQ_RELOCS | R_BIN_REQ_IMPORTS)) {
		if (p->relocs) {
			RVecRBinReloc *relocs = p->relocs (bf);
			if (relocs) {
				set_relocs (bo, relocs, limit);
			}
		}
	}
	if (bin->filter_rules & R_BIN_REQ_STRINGS) {
		RVecRBinString *strings = p->strings
			? p->strings (bf)
			: r_bin_file_get_strings (bf, minlen, 0, bf->rawstr);
		r_bin_take_strings (&bo->strings, strings);
		if (bin->options.debase64) {
			r_bin_object_filter_strings (bo);
		}
		clamp_strings_vec (&bo->strings, limit);
		RVecRBinString_shrink_to_fit (&bo->strings);
		rebase_strings_vec (bo);
		r_bin_object_drop_strings_db (bo);
	}
	if (p->lines) {
		bo->lines = p->lines (bf);
	}
	if (p->get_sdb) {
		Sdb* new_kv = p->get_sdb (bf);
		if (new_kv != bo->kv) {
			sdb_free (bo->kv);
		}
		bo->kv = new_kv;
	}
	if (bin->filter_rules & R_BIN_REQ_RESOURCES) {
		r_bin_file_get_resources (bf);
	}
	if (p->mem)  {
		bo->mem = p->mem (bf);
	}
#if 0
	r_bin_info_free (bo->info);
	// call it twice, otherwise the info is not propagated
	bo->info = p->info? p->info (bf): NULL;
#endif
	// bo->info = p->info? p->info (bf): NULL;
	if (bo->info && bo->info->type) {
		if (strstr (bo->info->type, "CORE")) {
			if (p->regstate) {
				bo->regstate = p->regstate (bf);
			}
			if (p->maps) {
				bo->maps = p->maps (bf);
			}
		}
	}
	if (bo->info && bin->filter_rules & (R_BIN_REQ_INFO | R_BIN_REQ_SYMBOLS | R_BIN_REQ_IMPORTS)) {
		if (isSwift) {
			r_bin_file_add_language (bf, R_BIN_LANG_SWIFT);
		}
		bo->langs = r_bin_load_languages (bf);
	}
	// trim doubling-growth slack from per-class vecs
	if (bo->classes) {
		RListIter *it;
		RBinClass *cls;
		r_list_foreach (bo->classes, it, cls) {
			RVecRBinSymbol_shrink_to_fit (&cls->methods);
			RVecRBinField_shrink_to_fit (&cls->fields);
		}
	}
	return true;
}

R_IPI RVecRBinReloc *r_bin_object_patch_relocs(RBinFile *bf, RBinObject *bo) {
	R_RETURN_VAL_IF_FAIL (bf && bo, NULL);

	if (!bo->is_reloc_patched && bo->plugin && bo->plugin->patch_relocs) {
		RVecRBinReloc *relocs = bo->plugin->patch_relocs (bf);
		if (R_LIKELY (relocs)) {
			set_relocs (bo, relocs, bf->rbin->options.limit);
			bo->is_reloc_patched = true;
		}
	}
	return bo->relocs;
}

R_IPI RBinObject *r_bin_object_get_cur(RBin *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur, NULL);
	return bin->cur->bo;
}

R_IPI RBinObject *r_bin_object_find_by_arch_bits(RBinFile *bf, const char *arch, int bits, const char *name) {
	R_RETURN_VAL_IF_FAIL (bf && arch && name, NULL);
	if (bf->bo) {
		RBinInfo *info = bf->bo->info;
		if (info && info->arch && info->file &&
				(bits == info->bits) &&
				!strcmp (info->arch, arch) &&
				!strcmp (info->file, name)) {
			return bf->bo;
		}
	}
	return NULL;
}

R_API bool r_bin_object_delete(RBin *bin, ut32 bf_id) {
	R_RETURN_VAL_IF_FAIL (bin, false);

	bool res = false;
	RBinFile *bf = r_bin_file_find_by_id (bin, bf_id);
	if (bf) {
		if (bin->cur == bf) {
			bin->cur = NULL;
		}
		// wtf
		if (!bf->bo) {
			r_list_delete_data (bin->binfiles, bf);
		}
	}
	return res;
}

R_IPI void r_bin_object_filter_strings(RBinObject *bo) {
	R_RETURN_IF_FAIL (bo);

	RBinString *ptr;
	R_VEC_FOREACH (&bo->strings, ptr) {
		// strict decoding: a string is only treated as base64 if it fully is,
		// and every nested decode must shrink, otherwise this loops forever
		char *dec = (char *)r_base64_decode_dyn ((const char *)ptr->string, -1, NULL, true);
		if (R_STR_ISEMPTY (dec)) {
			free (dec);
			dec = NULL;
		}
		if (dec) {
			char *s = ptr->string;
			for (;;) {
				char *dec2 = (char *)r_base64_decode_dyn ((const char *)s, -1, NULL, true);
				if (R_STR_ISEMPTY (dec2)) {
					free (dec2);
					break;
				}
				if (!r_str_is_printable (dec2)) {
					free (dec2);
					break;
				}
				free (dec);
				s = dec = dec2;
			}
			if (r_str_is_printable (dec) && strlen (dec) > 3) {
				free (ptr->string);
				ptr->string = dec;
				ptr->type = R_STRING_TYPE_BASE64;
			} else {
				free (dec);
			}
		}
	}
}
