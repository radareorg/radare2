/* radare - LGPL - Copyright 2026 - pancake */

// Swift5 type metadata walker, shared between bin plugins (mach-o, elf).
// Layouts come from swift/include/swift/ABI/Metadata.h and
// docs/ABI/TypeMetadata.rst in the swift sources

#define R_LOG_ORIGIN "bin.swift"

#include "swift.h"

#define MAX_SWIFT_MEMBERS 256

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
	bool valid;
	int kind; // SWIFT_CDK_*
	ut32 flags;
	ut64 addr; // vaddr of the type context descriptor
	ut64 name_addr;
	ut64 super_addr; // mangled superclass typename (classes only)
	ut64 fields; // FieldDescriptor vaddr
	ut64 vtable; // vaddr of the vtable header (classes only)
} SwiftType;

static bool swift_names_only(RBinFile *bf) {
	return bf && bf->rbin && bf->rbin->options.classes_names_only;
}

static st32 swift_s32(RBinSwiftLoader *ld, ut64 va) {
	ut8 b[4] = {0};
	ld->read_at (ld->user, va, b, sizeof (b));
	return (st32)r_read_le32 (b);
}

static char *swift_str(RBinSwiftLoader *ld, ut64 va) {
	char buf[256];
	const int n = ld->read_at (ld->user, va, (ut8 *)buf, sizeof (buf) - 1);
	if (n < 1) {
		return NULL;
	}
	buf[n] = 0;
	return (*buf && (ut8)*buf != 0xff)? strdup (buf): NULL;
}

// fully qualified dotted name of a context descriptor ("CryptoKit.P256.Signing")
static char *swift_context_qualname(RBinSwiftLoader *ld, ut64 va);

// resolve an indirect symbolic reference: va holds a pointer (or bind) to a descriptor
static char *swift_indirect_qualname(RBinSwiftLoader *ld, ut64 va) {
	ut64 target = 0;
	char *name = ld->slot (ld->user, va, &target);
	if (name) {
		const char *rn = name;
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
				free (name);
				return res;
			}
		}
		if (rn != name) {
			char *res = strdup (rn);
			free (name);
			return res;
		}
		return name;
	}
	return target? swift_context_qualname (ld, target): NULL;
}

static char *swift_symref_resolve(void *user, ut64 addr, bool indirect) {
	RBinSwiftLoader *ld = user;
	return indirect? swift_indirect_qualname (ld, addr): swift_context_qualname (ld, addr);
}

static char *swift_context_qualname(RBinSwiftLoader *ld, ut64 va) {
	if (ld->depth > 12) {
		return NULL;
	}
	const ut32 flags = (ut32)swift_s32 (ld, va);
	const int kind = flags & 0x1f;
	char *name = NULL;
	if (kind == SWIFT_CDK_MODULE || kind == SWIFT_CDK_PROTOCOL || kind >= SWIFT_CDK_CLASS) {
		const st32 nrel = swift_s32 (ld, va + 8);
		if (nrel) {
			name = swift_str (ld, va + 8 + nrel);
		}
	}
	if (kind == SWIFT_CDK_MODULE) {
		return name;
	}
	const st32 prel = swift_s32 (ld, va + 4);
	if (prel) {
		const ut64 pva = va + 4 + (prel & ~1);
		char *pn;
		ld->depth++;
		if (prel & 1) {
			pn = swift_indirect_qualname (ld, pva);
		} else {
			pn = swift_context_qualname (ld, pva);
		}
		ld->depth--;
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
	return name;
}

// mangled context chain ("9CryptoKit4P256O7SigningO9PublicKeyV") used to
// attribute symbols to types; returns NULL for non-nominal contexts
static char *swift_context_mangled(RBinSwiftLoader *ld, ut64 va) {
	if (ld->depth > 12) {
		return NULL;
	}
	const ut32 flags = (ut32)swift_s32 (ld, va);
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
	const st32 nrel = swift_s32 (ld, va + 8);
	char *name = nrel? swift_str (ld, va + 8 + nrel): NULL;
	if (R_STR_ISEMPTY (name)) {
		free (name);
		return NULL;
	}
	char *res = NULL;
	if (kind == SWIFT_CDK_MODULE) {
		res = r_str_newf ("%d%s", (int)strlen (name), name);
	} else {
		const st32 prel = swift_s32 (ld, va + 4);
		ut64 pva = prel? va + 4 + (prel & ~1): 0;
		if (pva && (prel & 1)) {
			ut64 target = 0;
			free (ld->slot (ld->user, pva, &target));
			pva = target;
		}
		if (pva) {
			ld->depth++;
			char *pn = swift_context_mangled (ld, pva);
			ld->depth--;
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
static char *swift_read_typeref(RBinSwiftLoader *ld, ut64 va) {
	ut8 buf[256] = {0};
	const int n = ld->read_at (ld->user, va, buf, sizeof (buf) - 1);
	if (n < 2) {
		return NULL;
	}
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
	return (i > 0)? r_bin_demangle_swift_typeref (buf, R_MIN (i, n), va, swift_symref_resolve, ld): NULL;
}

static SwiftType swift_parse_type_entry(RBinSwiftLoader *ld, ut64 typeaddr) {
	SwiftType st = {0};
	const ut32 flags = (ut32)swift_s32 (ld, typeaddr);
	const int kind = flags & 0x1f;
	if (kind != SWIFT_CDK_CLASS && kind != SWIFT_CDK_STRUCT && kind != SWIFT_CDK_ENUM) {
		return st;
	}
#define NCD(x) (typeaddr + ((x) * 4) + swift_s32 (ld, typeaddr + ((x) * 4)))
	st.valid = true;
	st.kind = kind;
	st.flags = flags;
	st.addr = typeaddr;
	st.name_addr = NCD (2);
	st.fields = swift_s32 (ld, typeaddr + 16)? NCD (4): UT64_MAX;
	if (kind == SWIFT_CDK_CLASS) {
		if (swift_s32 (ld, typeaddr + 20)) {
			st.super_addr = NCD (5);
		}
		const ut32 tcd = flags >> 16;
		if ((tcd & SWIFT_TCD_CLASS_HAS_VTABLE) && !(tcd & (1 << 3))) {
			ut64 p = typeaddr + 11 * 4;
			if (flags & (1 << 7)) { // generic: skip the generic context header
				const ut32 nparams = (ut32)swift_s32 (ld, p + 8) & 0xffff;
				const ut32 nreqs = ((ut32)swift_s32 (ld, p + 8)) >> 16;
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

// Map each type context descriptor to its type metadata via the `...N`
// metadata symbols: a struct/class metadata's second word points back to its
// descriptor. Lets swift_parse_fields read the static field-offset vector.
static void swift_build_metadata_map(RBinSwiftLoader *ld) {
	if (!ld->symbols || !ld->slot) {
		return;
	}
	ld->meta_by_desc = ht_up_new0 ();
	RBinSymbol *sym;
	R_VEC_FOREACH (ld->symbols, sym) {
		const char *sn = r_bin_name_tostring2 (sym->name, 'o');
		while (*sn == '_') {
			sn++;
		}
		if (!r_str_startswith (sn, "$s")) {
			continue;
		}
		// type metadata symbols end in "N" (nominal type metadata), but not
		// "Mn" (descriptor), "Ma" (access fn) or the "M*"/"W*" helpers.
		const size_t l = strlen (sn);
		if (l < 3 || sn[l - 1] != 'N' || sn[l - 2] == 'M') {
			continue;
		}
		// second word of the metadata points to its context descriptor
		ut64 desc = 0;
		char *nm = ld->slot (ld->user, sym->vaddr + 8, &desc);
		free (nm);
		if (desc) {
			ht_up_update (ld->meta_by_desc, desc, (void *)(size_t)sym->vaddr);
		}
	}
}

// Byte offset of struct field `i` from the static field-offset vector in the
// type metadata, or UT64_MAX when it cannot be resolved (generic/resilient
// layout, missing metadata). `desc` is the type context descriptor vaddr.
static ut64 swift_struct_field_offset(RBinSwiftLoader *ld, ut64 desc, ut32 i) {
	if (!ld->meta_by_desc) {
		return UT64_MAX;
	}
	bool found = false;
	ut64 meta = (ut64)(size_t)ht_up_find (ld->meta_by_desc, desc, &found);
	if (!found || !meta) {
		return UT64_MAX;
	}
	// StructDescriptor: numFields @ +20, fieldOffsetVectorOffset (words) @ +24
	const ut32 nfields = (ut32)swift_s32 (ld, desc + 20);
	const ut32 fovo = (ut32)swift_s32 (ld, desc + 24);
	if (!fovo || i >= nfields || nfields > 2048) {
		return UT64_MAX;
	}
	return (ut64)(ut32)swift_s32 (ld, meta + (fovo * 8) + (i * 4));
}

static void swift_parse_fields(RBinSwiftLoader *ld, RBinClass *klass, ut64 fd, ut64 desc, bool is_struct, bool is_enum) {
	const ut32 nfields = (ut32)swift_s32 (ld, fd + 12);
	const ut32 recsize = ((ut32)swift_s32 (ld, fd + 8)) >> 16;
	if (recsize != 12 || nfields > 2048) {
		R_LOG_DEBUG ("Unexpected swift field descriptor at 0x%08"PFMT64x, fd);
		return;
	}
	ut32 i;
	for (i = 0; i < nfields; i++) {
		const ut64 rec = fd + 16 + (i * 12);
		const ut32 rflags = (ut32)swift_s32 (ld, rec);
		const st32 trel = swift_s32 (ld, rec + 4);
		const st32 nrel = swift_s32 (ld, rec + 8);
		char *field_name = nrel? swift_str (ld, rec + 8 + nrel): NULL;
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
			char *ftype = swift_read_typeref (ld, rec + 4 + trel);
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
		field->attr.kind = R_BIN_FIELD_KIND_PROPERTY;
		// Byte offset within the instance, read from the metadata's static
		// field-offset vector (structs with fixed layout only).
		if (is_struct) {
			const ut64 off = swift_struct_field_offset (ld, desc, i);
			if (off != UT64_MAX) {
				field->attr.offset = (int)off;
			}
		}
		if (is_enum) {
			field->attr.flags = R_BIN_ATTR_ENUM;
		} else if (!(rflags & 2)) {
			field->attr.flags = R_BIN_ATTR_CONST; // let, not var
		}
	}
}

static void swift_parse_vtable(RBinSwiftLoader *ld, RBinClass *klass, ut64 vt, const char *prefix) {
	const ut32 vtsize = (ut32)swift_s32 (ld, vt + 4);
	if (vtsize > MAX_SWIFT_MEMBERS) {
		R_LOG_DEBUG ("Truncated insane swift vtable at 0x%08"PFMT64x, vt);
		return;
	}
	ut32 i;
	for (i = 0; i < vtsize; i++) {
		const ut64 mdesc = vt + 8 + (i * 8);
		const ut32 mflags = (ut32)swift_s32 (ld, mdesc);
		const st32 irel = swift_s32 (ld, mdesc + 4);
		if (!irel || SWIFT_MDF_KIND (mflags) > 5) {
			continue;
		}
		const ut64 method_addr = mdesc + 4 + irel;
		RBinSymbol *bs = ld->symbols_ht? ht_up_find (ld->symbols_ht, method_addr, NULL): NULL;
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
				sym->attr.flags |= mattr;
			}
			if (!dname) {
				dname = r_bin_demangle (ld->bf, "swift", rawname, 0, false);
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
		case 1: sym->attr.flags |= R_BIN_ATTR_CONSTRUCTOR; break;
		case 2: sym->attr.flags |= R_BIN_ATTR_GETTER; break;
		case 3: sym->attr.flags |= R_BIN_ATTR_SETTER; break;
		}
		if (!(mflags & SWIFT_MDF_INSTANCE)) {
			sym->attr.flags |= R_BIN_ATTR_STATIC;
		}
		if (mflags & SWIFT_MDF_ASYNC) {
			sym->attr.flags |= R_BIN_ATTR_ASYNC;
		}
		sym->attr.lang = R_BIN_LANG_SWIFT;
		RVecRBinSymbol_push_back (&klass->methods, sym);
		free (sym);
	}
}

static void swift_parse_type(RBinSwiftLoader *ld, RList *list, SwiftType st) {
	RBinFile *bf = ld->bf;
	char *qname = swift_context_qualname (ld, st.addr);
	char *otypename = qname? qname: swift_str (ld, st.name_addr);
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
		klass->attr.flags |= R_BIN_ATTR_ENUM;
		break;
	case SWIFT_CDK_STRUCT:
		klass->attr.flags |= R_BIN_ATTR_STRUCT;
		break;
	}
	if (st.super_addr) {
		char *sname = swift_read_typeref (ld, st.super_addr);
		if (R_STR_ISNOTEMPTY (sname)) {
			klass->super = r_list_newf ((void *)r_bin_name_free);
			r_list_append (klass->super, r_bin_name_new (sname));
		}
		free (sname);
	}
	klass->addr = st.addr;
	klass->attr.lang = R_BIN_LANG_SWIFT;
	klass->index = r_list_length (bf->bo->classes) + r_list_length (list);
	r_list_append (list, klass);
	char *mangled = swift_context_mangled (ld, st.addr);
	if (mangled && ld->mangled_ht) {
		ht_pp_insert (ld->mangled_ht, mangled, klass);
	}
	if (!swift_names_only (bf)) {
		if (st.fields != UT64_MAX) {
			swift_parse_fields (ld, klass, st.fields, st.addr,
				st.kind == SWIFT_CDK_STRUCT, st.kind == SWIFT_CDK_ENUM);
		}
		if (st.vtable) {
			swift_parse_vtable (ld, klass, st.vtable, mangled);
		}
	}
	free (mangled);
	free (otypename);
}

static void swift_parse_protocols(RBinSwiftLoader *ld, RList *list, ut64 va, ut64 size) {
	RBinFile *bf = ld->bf;
	ut32 i;
	for (i = 0; i < size / 4; i++) {
		const ut64 entry = va + (i * 4);
		const st32 rel = swift_s32 (ld, entry);
		if (!rel) {
			continue;
		}
		const ut64 pd = entry + rel;
		if ((swift_s32 (ld, pd) & 0x1f) != SWIFT_CDK_PROTOCOL) {
			continue;
		}
		char *qname = swift_context_qualname (ld, pd);
		if (R_STR_ISEMPTY (qname)) {
			free (qname);
			continue;
		}
		RBinClass *klass = r_bin_class_new (qname, NULL, false);
		klass->attr.flags |= R_BIN_ATTR_INTERFACE;
		klass->attr.lang = R_BIN_LANG_SWIFT;
		klass->origin = R_BIN_CLASS_ORIGIN_BIN;
		klass->addr = pd;
		const st32 atrel = swift_s32 (ld, pd + 20);
		char *assoc = atrel? swift_str (ld, pd + 20 + atrel): NULL;
		if (R_STR_ISNOTEMPTY (assoc)) {
			RList *names = r_str_split_list (assoc, " ", 0);
			RListIter *iter;
			const char *an;
			r_list_foreach (names, iter, an) {
				RBinField *field = RVecRBinField_emplace_back (&klass->fields);
				if (field) {
					memset (field, 0, sizeof (RBinField));
					field->name = r_bin_name_new (an);
					field->attr.kind = R_BIN_FIELD_KIND_PROPERTY;
					field->attr.flags = R_BIN_ATTR_ABSTRACT;
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
static void swift_attach_symbols(RBinSwiftLoader *ld) {
	RBinSymbol *bs;
	R_VEC_FOREACH (ld->symbols, bs) {
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
				RBinClass *k = ht_pp_find (ld->mangled_ht, prefix, NULL);
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
		sym->attr.flags = attr;
		sym->attr.lang = R_BIN_LANG_SWIFT;
		RVecRBinSymbol_push_back (&klass->methods, sym);
		free (sym);
		free (mname);
	}
}

R_IPI void r_bin_swift_load_classes(RBinSwiftLoader *ld, RList *out, ut64 types_va, ut64 types_size, ut64 protos_va, ut64 protos_size, int limit) {
	R_RETURN_IF_FAIL (ld && ld->bf && ld->read_at && ld->slot && out);
	r_bin_file_add_language (ld->bf, R_BIN_LANG_SWIFT);
	if (ld->symbols && !swift_names_only (ld->bf)) {
		ld->symbols_ht = ht_up_new0 ();
		RBinSymbol *sym;
		R_VEC_FOREACH (ld->symbols, sym) {
			const char *sn = r_bin_name_tostring2 (sym->name, 'o');
			while (*sn == '_') {
				sn++;
			}
			if (*sn == '$' && !r_str_startswith (sn, "$s")) {
				continue; // aarch64 mapping symbols ($x/$d)
			}
			RBinSymbol *prev = ht_up_find (ld->symbols_ht, sym->vaddr, NULL);
			if (prev) {
				// prefer mangled swift symbols over aliases at the same address
				const char *pn = r_bin_name_tostring2 (prev->name, 'o');
				while (*pn == '_') {
					pn++;
				}
				if (r_str_startswith (pn, "$s") || !r_str_startswith (sn, "$s")) {
					continue;
				}
			}
			ht_up_update (ld->symbols_ht, sym->vaddr, sym);
		}
	}
	ld->mangled_ht = ht_pp_new0 ();
	swift_build_metadata_map (ld);
	ut32 i;
	for (i = 0; i < types_size / 4; i++) {
		if (limit > 0 && r_list_length (out) >= limit) {
			R_LOG_WARN ("swift class limit reached");
			break;
		}
		const ut64 entry = types_va + (i * 4);
		const st32 word = swift_s32 (ld, entry);
		if (!word) {
			continue;
		}
		SwiftType st = swift_parse_type_entry (ld, entry + word);
		if (st.valid) {
			swift_parse_type (ld, out, st);
		}
	}
	if (protos_size > 0) {
		swift_parse_protocols (ld, out, protos_va, protos_size);
	}
	if (ld->symbols_ht) {
		swift_attach_symbols (ld);
	}
	ht_up_free (ld->symbols_ht);
	ht_pp_free (ld->mangled_ht);
	ht_up_free (ld->meta_by_desc);
	ld->symbols_ht = NULL;
	ld->mangled_ht = NULL;
	ld->meta_by_desc = NULL;
}
