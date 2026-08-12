// Swift5 type metadata. Layouts come from swift/include/swift/ABI/Metadata.h
// and docs/ABI/TypeMetadata.rst in the swift sources

enum {
	SWIFT_CDK_MODULE = 0,
	SWIFT_CDK_EXTENSION = 1,
	SWIFT_CDK_ANONYMOUS = 2,
	SWIFT_CDK_PROTOCOL = 3,
	SWIFT_CDK_CLASS = 16,
	SWIFT_CDK_STRUCT = 17,
	SWIFT_CDK_ENUM = 18
};

// TypeContextDescriptorFlags (upper 16 bits of the flags word)
#define SWIFT_TCD_METAINIT(x) ((x) & 3)
#define SWIFT_TCD_CLASS_HAS_RESILIENT_SUPER (1 << 13)
#define SWIFT_TCD_CLASS_HAS_OVERRIDE_TABLE (1 << 14)
#define SWIFT_TCD_CLASS_HAS_VTABLE (1 << 15)

// MethodDescriptorFlags
#define SWIFT_MDF_KIND(x) ((x) & 0x0f) // 0 method, 1 init, 2 getter, 3 setter, 4 modify, 5 read
#define SWIFT_MDF_INSTANCE 0x10
#define SWIFT_MDF_DYNAMIC 0x20
#define SWIFT_MDF_ASYNC 0x40

typedef struct {
	RBinFile *bf;
	const RSkipList *relocs;
	HtUP *symbols_ht;
	HtPP *mangled_ht; // mangled context prefix -> RBinClass
	int depth;
} SwiftCtx;

typedef struct {
	bool valid;
	int kind; // SWIFT_CDK_*
	ut32 flags;
	ut64 addr; // vaddr of the type context descriptor
	ut64 name_addr;
	ut64 super_addr; // mangled superclass typename (classes only)
	ut64 fields; // FieldDescriptor vaddr
	ut64 vtable; // vaddr of the vtable header (classes only)
} SwiftType;

static st32 swift_s32(RBinFile *bf, ut64 va) {
	ut32 offset, left;
	ut8 b[4] = {0};
	const mach0_ut pa = va2pa (bf, va, &offset, &left);
	if (pa && left >= sizeof (b)) {
		r_buf_read_at (bf->buf, pa, b, sizeof (b));
	}
	return (st32)r_read_le32 (b);
}

static ut64 swift_ptr(RBinFile *bf, ut64 va) {
	ut32 offset, left;
	ut8 b[sizeof (mach0_ut)] = {0};
	const mach0_ut pa = va2pa (bf, va, &offset, &left);
	if (!pa || left < sizeof (b)) {
		return 0;
	}
	r_buf_read_at (bf->buf, pa, b, sizeof (b));
	ut64 v = r_read_ble (b, false, 8 * sizeof (mach0_ut));
	if (v >> 48) {
		// strip chained-fixup/PAC bits, keeping the 36bit target offset
		v &= 0xFFFFFFFFFULL;
	}
	return v & ~1ULL;
}

static char *swift_str(RBinFile *bf, ut64 va) {
	ut32 offset, left;
	return readstr (bf, va, &offset, &left);
}

// fully qualified dotted name of a context descriptor ("CryptoKit.P256.Signing")
static char *swift_context_qualname(SwiftCtx *ctx, ut64 va) {
	if (ctx->depth > 12) {
		return NULL;
	}
	const ut32 flags = (ut32)swift_s32 (ctx->bf, va);
	const int kind = flags & 0x1f;
	char *name = NULL;
	if (kind == SWIFT_CDK_MODULE || kind == SWIFT_CDK_PROTOCOL || kind >= SWIFT_CDK_CLASS) {
		const st32 nrel = swift_s32 (ctx->bf, va + 8);
		if (nrel) {
			name = swift_str (ctx->bf, va + 8 + nrel);
		}
	}
	if (kind == SWIFT_CDK_MODULE) {
		return name;
	}
	const st32 prel = swift_s32 (ctx->bf, va + 4);
	if (prel) {
		ut64 pva = va + 4 + (prel & ~1);
		if (prel & 1) {
			pva = swift_ptr (ctx->bf, pva);
		}
		if (pva) {
			ctx->depth++;
			char *pn = swift_context_qualname (ctx, pva);
			ctx->depth--;
			if (pn && name) {
				char *res = r_str_newf ("%s.%s", pn, name);
				free (pn);
				free (name);
				return res;
			}
			if (pn) {
				return pn; // anonymous/extension context in between
			}
		}
	}
	return name;
}

// resolve an indirect symbolic reference: va holds a pointer (or bind) to a descriptor
static char *swift_indirect_qualname(SwiftCtx *ctx, ut64 va) {
	if (ctx->relocs) {
		struct reloc_t rr = { .addr = va };
		RSkipListNode *node = r_skiplist_find ((RSkipList *)ctx->relocs, &rr);
		if (node) {
			struct reloc_t *rel = node->data;
			if (rel->name[0]) {
				const char *rn = rel->name;
				while (*rn == '_') {
					rn++;
				}
				if (r_str_startswith (rn, "$s")) {
					size_t l = strlen (rn + 2);
					if (l > 2 && !strcmp (rn + l, "Mn")) {
						l -= 2; // drop the "nominal type descriptor" suffix
					}
					char *res = r_bin_demangle_swift_typeref ((const ut8 *)rn + 2, l, 0, NULL, NULL);
					if (res) {
						return res;
					}
				}
				return strdup (rn);
			}
			if (rel->addend > 0) {
				return swift_context_qualname (ctx, rel->addend);
			}
		}
	}
	const ut64 target = swift_ptr (ctx->bf, va);
	return target? swift_context_qualname (ctx, target): NULL;
}

static char *swift_symref_resolve(void *user, ut64 addr, bool indirect) {
	SwiftCtx *ctx = user;
	return indirect? swift_indirect_qualname (ctx, addr): swift_context_qualname (ctx, addr);
}

// mangled context chain ("9CryptoKit4P256O7SigningO9PublicKeyV") used to
// attribute symbols to types; returns NULL for non-nominal contexts
static char *swift_context_mangled(SwiftCtx *ctx, ut64 va) {
	if (ctx->depth > 12) {
		return NULL;
	}
	const ut32 flags = (ut32)swift_s32 (ctx->bf, va);
	const int kind = flags & 0x1f;
	char kindchar = 0;
	switch (kind) {
	case SWIFT_CDK_CLASS: kindchar = 'C'; break;
	case SWIFT_CDK_STRUCT: kindchar = 'V'; break;
	case SWIFT_CDK_ENUM: kindchar = 'O'; break;
	case SWIFT_CDK_MODULE: break;
	default:
		return NULL;
	}
	const st32 nrel = swift_s32 (ctx->bf, va + 8);
	char *name = nrel? swift_str (ctx->bf, va + 8 + nrel): NULL;
	if (R_STR_ISEMPTY (name)) {
		free (name);
		return NULL;
	}
	char *res = NULL;
	if (kind == SWIFT_CDK_MODULE) {
		res = r_str_newf ("%d%s", (int)strlen (name), name);
	} else {
		const st32 prel = swift_s32 (ctx->bf, va + 4);
		ut64 pva = prel? va + 4 + (prel & ~1): 0;
		if (prel & 1) {
			pva = swift_ptr (ctx->bf, pva);
		}
		if (pva) {
			ctx->depth++;
			char *pn = swift_context_mangled (ctx, pva);
			ctx->depth--;
			if (pn) {
				res = r_str_newf ("%s%d%s%c", pn, (int)strlen (name), name, kindchar);
				free (pn);
			}
		}
	}
	free (name);
	return res;
}

// read a (possibly symbolic) mangled type name at va and return its demangled form
static char *swift_read_typeref(SwiftCtx *ctx, ut64 va) {
	ut8 buf[256] = {0};
	ut32 offset, left;
	const mach0_ut pa = va2pa (ctx->bf, va, &offset, &left);
	if (!pa || left < 2) {
		return NULL;
	}
	const int n = R_MIN (left, sizeof (buf) - 1);
	r_buf_read_at (ctx->bf->buf, pa, buf, n);
	int i = 0;
	while (i < n && buf[i]) {
		if (buf[i] <= 0x17) {
			i += 5;
		} else if (buf[i] <= 0x1f) {
			i += 9;
		} else {
			i++;
		}
	}
	return (i > 0)? r_bin_demangle_swift_typeref (buf, R_MIN (i, n), va, swift_symref_resolve, ctx): NULL;
}

static SwiftType swift_parse_type_entry(RBinFile *bf, ut64 typeaddr) {
	SwiftType st = {0};
	const ut32 flags = (ut32)swift_s32 (bf, typeaddr);
	const int kind = flags & 0x1f;
	if (kind != SWIFT_CDK_CLASS && kind != SWIFT_CDK_STRUCT && kind != SWIFT_CDK_ENUM) {
		return st;
	}
#define NCD(x) (typeaddr + ((x) * 4) + swift_s32 (bf, typeaddr + ((x) * 4)))
	st.valid = true;
	st.kind = kind;
	st.flags = flags;
	st.addr = typeaddr;
	st.name_addr = NCD (2);
	st.fields = swift_s32 (bf, typeaddr + 16)? NCD (4): UT64_MAX;
	if (kind == SWIFT_CDK_CLASS) {
		if (swift_s32 (bf, typeaddr + 20)) {
			st.super_addr = NCD (5);
		}
		const ut32 tcd = flags >> 16;
		if ((tcd & SWIFT_TCD_CLASS_HAS_VTABLE) && !(tcd & (1 << 3))) {
			ut64 p = typeaddr + 11 * 4;
			if (flags & (1 << 7)) { // generic: skip the generic context header
				const ut32 nparams = (ut32)swift_s32 (bf, p + 8) & 0xffff;
				const ut32 nreqs = ((ut32)swift_s32 (bf, p + 8)) >> 16;
				p += 16 + ((nparams + 3) & ~3) + nreqs * 12;
			}
			if (tcd & SWIFT_TCD_CLASS_HAS_RESILIENT_SUPER) {
				p += 4;
			}
			switch (SWIFT_TCD_METAINIT (tcd)) {
			case 1: p += 12; break; // singleton metadata initialization
			case 2: p += 4; break; // foreign metadata initialization
			}
			st.vtable = p;
		}
	}
	return st;
}

static inline HtUP *_load_symbol_by_vaddr_hashtable(RBinFile *bf) {
	if (!MACH0_(load_symbols) (bf->bo->bin_obj)) {
		return NULL;
	}
	HtUP *ht = ht_up_new0 ();
	if (R_LIKELY (ht)) {
		RVecRBinSymbol *symbols = &bf->bo->symbols_vec;
		RBinSymbol *sym;
		R_VEC_FOREACH (symbols, sym) {
			ht_up_insert (ht, sym->vaddr, sym);
		}
	}
	return ht;
}

static void swift_parse_fields(SwiftCtx *ctx, RBinClass *klass, ut64 fd, bool is_enum) {
	const ut32 nfields = (ut32)swift_s32 (ctx->bf, fd + 12);
	const ut32 recsize = ((ut32)swift_s32 (ctx->bf, fd + 8)) >> 16;
	if (recsize != 12 || nfields > 2048) {
		R_LOG_DEBUG ("Unexpected swift field descriptor at 0x%08"PFMT64x, fd);
		return;
	}
	ut32 i;
	for (i = 0; i < nfields; i++) {
		const ut64 rec = fd + 16 + (i * 12);
		const ut32 rflags = (ut32)swift_s32 (ctx->bf, rec);
		const st32 trel = swift_s32 (ctx->bf, rec + 4);
		const st32 nrel = swift_s32 (ctx->bf, rec + 8);
		char *field_name = nrel? swift_str (ctx->bf, rec + 8 + nrel): NULL;
		if (R_STR_ISEMPTY (field_name)) {
			free (field_name);
			break;
		}
		RBinField *field = RVecRBinField_emplace_back (&klass->fields);
		if (!field) {
			free (field_name);
			break;
		}
		memset (field, 0, sizeof (RBinField));
		if (trel) {
			char *ftype = swift_read_typeref (ctx, rec + 4 + trel);
			if (ftype) {
				field->type = r_bin_name_new (ftype);
				free (ftype);
			}
		}
		field->name = r_bin_name_new (field_name);
		char *fname = r_name_filter_dup (field_name);
		r_bin_name_filtered (field->name, fname);
		free (fname);
		free (field_name);
		field->vaddr = rec;
		field->paddr = va2pa (ctx->bf, rec, NULL, NULL);
		field->kind = R_BIN_FIELD_KIND_PROPERTY;
		if (is_enum) {
			field->attr = R_BIN_ATTR_ENUM;
		} else if (!(rflags & 2)) {
			field->attr = R_BIN_ATTR_CONST; // let, not var
		}
	}
}

static void swift_parse_vtable(SwiftCtx *ctx, RBinClass *klass, ut64 vt, const char *prefix) {
	RBinFile *bf = ctx->bf;
	const ut32 vtsize = (ut32)swift_s32 (bf, vt + 4);
	if (vtsize > MAX_SWIFT_MEMBERS) {
		R_LOG_DEBUG ("Truncated insane swift vtable at 0x%08"PFMT64x, vt);
		return;
	}
	ut32 i;
	for (i = 0; i < vtsize; i++) {
		const ut64 mdesc = vt + 8 + (i * 8);
		const ut32 mflags = (ut32)swift_s32 (bf, mdesc);
		const st32 irel = swift_s32 (bf, mdesc + 4);
		if (!irel || SWIFT_MDF_KIND (mflags) > 5) {
			continue;
		}
		const ut64 method_addr = mdesc + 4 + irel;
		RBinSymbol *bs = ctx->symbols_ht? ht_up_find (ctx->symbols_ht, method_addr, NULL): NULL;
		RBinSymbol *sym;
		if (bs) {
			const char *rawname = r_bin_name_tostring2 (bs->name, 'o');
			sym = r_bin_symbol_new (rawname, method_addr, method_addr);
			const char *rn = rawname;
			while (*rn == '_') {
				rn++;
			}
			char *dname = NULL;
			ut64 mattr = 0;
			if (prefix && r_str_startswith (rn, "$s") && r_str_startswith (rn + 2, prefix)) {
				dname = r_bin_demangle_swift_member (prefix, rn + 2 + strlen (prefix), &mattr);
				sym->attr |= mattr;
			}
			if (!dname) {
				dname = demangle_swift (bf, rawname);
			}
			if (dname) {
				r_bin_name_demangled (sym->name, dname);
				free (dname);
			}
		} else {
			static const char *kindnames[] = { "method", "init", "getter", "setter", "modify", "read" };
			char *mname = r_str_newf ("%s.%d", kindnames[SWIFT_MDF_KIND (mflags)], i);
			sym = r_bin_symbol_new (mname, method_addr, method_addr);
			free (mname);
		}
		switch (SWIFT_MDF_KIND (mflags)) {
		case 1: sym->attr |= R_BIN_ATTR_CONSTRUCTOR; break;
		case 2: sym->attr |= R_BIN_ATTR_GETTER; break;
		case 3: sym->attr |= R_BIN_ATTR_SETTER; break;
		}
		if (!(mflags & SWIFT_MDF_INSTANCE)) {
			sym->attr |= R_BIN_ATTR_STATIC;
		}
		if (mflags & SWIFT_MDF_ASYNC) {
			sym->attr |= R_BIN_ATTR_ASYNC;
		}
		sym->lang = R_BIN_LANG_SWIFT;
		RVecRBinSymbol_push_back (&klass->methods, sym);
		free (sym);
	}
}

static void swift_parse_type(SwiftCtx *ctx, RList *list, SwiftType st) {
	RBinFile *bf = ctx->bf;
	char *qname = swift_context_qualname (ctx, st.addr);
	char *otypename = qname? qname: swift_str (bf, st.name_addr);
	if (R_STR_ISEMPTY (otypename)) {
		R_LOG_DEBUG ("swift-type-parse missing name");
		free (otypename);
		return;
	}
	RBinClass *klass = r_bin_class_new (otypename, NULL, false);
	char *typename = r_name_filter_dup (otypename);
	r_bin_name_filtered (klass->name, typename);
	free (typename);
	klass->origin = R_BIN_CLASS_ORIGIN_BIN;
	switch (st.kind) {
	case SWIFT_CDK_ENUM:
		klass->attr |= R_BIN_ATTR_ENUM;
		break;
	case SWIFT_CDK_STRUCT:
		klass->attr |= R_BIN_ATTR_STRUCT;
		break;
	}
	if (st.super_addr) {
		char *sname = swift_read_typeref (ctx, st.super_addr);
		if (R_STR_ISNOTEMPTY (sname)) {
			klass->super = r_list_newf ((void *)r_bin_name_free);
			r_list_append (klass->super, r_bin_name_new (sname));
		}
		free (sname);
	}
	klass->addr = st.addr;
	klass->lang = R_BIN_LANG_SWIFT;
	klass->index = r_list_length (bf->bo->classes) + r_list_length (list);
	r_list_append (list, klass);
	char *mangled = swift_context_mangled (ctx, st.addr);
	if (mangled && ctx->mangled_ht) {
		ht_pp_insert (ctx->mangled_ht, mangled, klass);
	}
	if (!class_names_only (bf)) {
		if (st.fields != UT64_MAX) {
			swift_parse_fields (ctx, klass, st.fields, st.kind == SWIFT_CDK_ENUM);
		}
		if (st.vtable) {
			swift_parse_vtable (ctx, klass, st.vtable, mangled);
		}
	}
	free (mangled);
	free (otypename);
}

static void swift_parse_protocols(SwiftCtx *ctx, RList *list, MetaSection *ms) {
	RBinFile *bf = ctx->bf;
	ut32 i;
	for (i = 0; i < ms->size / 4; i++) {
		const ut64 entry = ms->vaddr + (i * 4);
		const st32 rel = swift_s32 (bf, entry);
		if (!rel) {
			continue;
		}
		const ut64 pd = entry + rel;
		if ((swift_s32 (bf, pd) & 0x1f) != SWIFT_CDK_PROTOCOL) {
			continue;
		}
		char *qname = swift_context_qualname (ctx, pd);
		if (R_STR_ISEMPTY (qname)) {
			free (qname);
			continue;
		}
		RBinClass *klass = r_bin_class_new (qname, NULL, false);
		klass->attr |= R_BIN_ATTR_INTERFACE;
		klass->lang = R_BIN_LANG_SWIFT;
		klass->origin = R_BIN_CLASS_ORIGIN_BIN;
		klass->addr = pd;
		const st32 atrel = swift_s32 (bf, pd + 20);
		char *assoc = atrel? swift_str (bf, pd + 20 + atrel): NULL;
		if (R_STR_ISNOTEMPTY (assoc)) {
			RList *names = r_str_split_list (assoc, " ", 0);
			RListIter *iter;
			const char *an;
			r_list_foreach (names, iter, an) {
				RBinField *field = RVecRBinField_emplace_back (&klass->fields);
				if (field) {
					memset (field, 0, sizeof (RBinField));
					field->name = r_bin_name_new (an);
					field->kind = R_BIN_FIELD_KIND_PROPERTY;
					field->attr = R_BIN_ATTR_ABSTRACT;
					field->vaddr = pd;
				}
			}
			r_list_free (names);
		}
		free (assoc);
		klass->index = r_list_length (bf->bo->classes) + r_list_length (list);
		r_list_append (list, klass);
		free (qname);
	}
}

// attribute exported swift symbols ($s<context><member>...) to their types
static void swift_attach_symbols(SwiftCtx *ctx) {
	RVecRBinSymbol *symbols = &ctx->bf->bo->symbols_vec;
	RBinSymbol *bs;
	R_VEC_FOREACH (symbols, bs) {
		const char *rn = r_bin_name_tostring2 (bs->name, 'o');
		while (*rn == '_') {
			rn++;
		}
		if (!r_str_startswith (rn, "$s")) {
			continue;
		}
		const char *p = rn + 2;
		RBinClass *klass = NULL;
		const char *rest = NULL;
		const char *q = p;
		bool in_module = true;
		while (isdigit (*q) && *q != '0') {
			const int n = atoi (q);
			q = r_str_trim_head_digits (q);
			if (n < 1 || n > (int)strlen (q)) {
				break;
			}
			q += n;
			if (strchr ("CVO", *q)) {
				q++;
				char *prefix = r_str_ndup (p, q - p);
				RBinClass *k = ht_pp_find (ctx->mangled_ht, prefix, NULL);
				free (prefix);
				if (k) {
					klass = k;
					rest = q;
				}
			} else if (!in_module) {
				break; // only the module segment comes without a kind marker
			}
			in_module = false;
		}
		if (!klass || !rest || !*rest) {
			continue;
		}
		ut64 attr = 0;
		char *prefix = r_str_ndup (p, rest - p);
		char *mname = r_bin_demangle_swift_member (prefix, rest, &attr);
		free (prefix);
		if (!mname) {
			continue;
		}
		// skip if this address is already covered by a vtable method
		bool dupe = false;
		RBinSymbol *ms;
		R_VEC_FOREACH (&klass->methods, ms) {
			if (ms->vaddr == bs->vaddr) {
				dupe = true;
				break;
			}
		}
		if (dupe) {
			free (mname);
			continue;
		}
		RBinSymbol *sym = r_bin_symbol_new (rn, bs->paddr, bs->vaddr);
		r_bin_name_demangled (sym->name, mname);
		sym->attr = attr;
		sym->lang = R_BIN_LANG_SWIFT;
		RVecRBinSymbol_push_back (&klass->methods, sym);
		free (sym);
		free (mname);
	}
}

