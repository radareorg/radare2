/* radare - LGPL - Copyright 2015-2025 - inisider, pancake */

#define R_LOG_ORIGIN "bin"

#include "../../i/private.h"
#include "mach0_classes.h"

#define RO_META (1 << 0)
#define MAX_CLASS_NAME_LEN 512
#define MAX_SWIFT_MEMBERS 256

#ifdef R_BIN_MACH064
#define FAST_DATA_MASK 0x00007ffffffffff8UL
#else
#define FAST_DATA_MASK 0xfffffffcUL
#endif

#define METHOD_LIST_FLAG_IS_SMALL 0x80000000
#define METHOD_LIST_FLAG_IS_PREOPT 0x3
#define METHOD_LIST_ENTSIZE_FLAG_MASK 0xffff0003

#define RO_DATA_PTR(x) ((x) & FAST_DATA_MASK)

typedef struct {
	bool have;
	ut64 addr;
	ut64 vaddr;
	ut64 size;
	ut8 *data;
} MetaSection;

typedef struct {
	// swift
	MetaSection types;
	MetaSection fieldmd;
	MetaSection protos;
	// objc
	MetaSection clslist;
	MetaSection catlist;
} MetaSections;

typedef struct {
	RBinFile *bf;
	RBinClass *klass;
} PropertyListOfListsCtx;

typedef struct {
	RBinFile *bf;
	const char *class_name;
	RBinClass *klass;
	bool is_static;
	objc_cache_opt_info *oi;
} MethodListOfListsCtx;

typedef struct {
	RBinFile *bf;
	RBinClass *klass;
	objc_cache_opt_info *oi;
} ProtocolListOfListsCtx;

typedef struct {
	ut64 image_index: 16;
	st64 list_offset: 48;
} ListOfListsEntry;

typedef void (* OnList)(mach0_ut p, void * ctx);

static bool load_unnamed(RBinFile *bf) {
	return !bf || !bf->rbin || bf->rbin->options.load_unnamed;
}

static bool class_names_only(RBinFile *bf) {
	return bf && bf->rbin && bf->rbin->options.classes_names_only;
}

static bool adjust_bounds(RBinFile *bf, MetaSection *ms, const char *sname) {
	if (ms->addr >= bf->size || ms->size >= bf->size) {
		R_LOG_DEBUG ("Dropping swift5.%s section because oob", sname);
		return false;
	}
	if (ms->addr + ms->size >= bf->size) {
		R_LOG_DEBUG ("Truncating swift5.fieldmd section", sname);
		ms->size = bf->size - ms->addr;
	}
	return true;
}

static bool parse_section(RBinFile *bf, MetaSection *ms, struct section_t *section, const char *sname) {
	if (ms->have) {
		return true;
	}
	if (strstr (section->name, sname)) {
		ms->addr = section->paddr;
		ms->vaddr = section->vaddr;
		ms->size = section->size;
		ms->have = adjust_bounds (bf, ms, sname);
		return true;
	}
	return false;
}

static void metadata_sections_fini(MetaSections *ms) {
	R_FREE (ms->types.data);
	R_FREE (ms->fieldmd.data);
	R_FREE (ms->clslist.data);
	R_FREE (ms->catlist.data);
}

#define PARSECTION(x,y) parse_section (bf, x, section, y)
static MetaSections metadata_sections_init(RBinFile *bf) {
	MetaSections ms = {{0}};
	const RVecSection *sections = MACH0_(load_sections) (bf->bo->bin_obj);
	if (sections) {
		struct section_t *section;
		R_VEC_FOREACH (sections, section) {
			PARSECTION (&ms.clslist, "__objc_classlist");
			PARSECTION (&ms.catlist, "__objc_catlist");
			PARSECTION (&ms.types, "swift5_types");
			PARSECTION (&ms.fieldmd, "swift5_fieldmd");
			PARSECTION (&ms.protos, "swift5_protos");
		}
	}
	return ms;
}

struct MACH0_(SMethodList) {
	ut32 entsize;
	ut32 count;
	/* SMethod first;  These structures follow inline */
};

struct MACH0_(SMethod) {
	mach0_ut name;  /* SEL (32/64-bit pointer) */
	mach0_ut types; /* const char * (32/64-bit pointer) */
	mach0_ut imp;   /* IMP (32/64-bit pointer) */
};

struct MACH0_(SClass) {
	mach0_ut isa;	/* SClass* (32/64-bit pointer) */
	mach0_ut superclass; /* SClass* (32/64-bit pointer) */
	mach0_ut cache;      /* Cache (32/64-bit pointer) */
	mach0_ut vtable;     /* IMP * (32/64-bit pointer) */
	mach0_ut data;       /* SClassRoT * (32/64-bit pointer) */
};

struct MACH0_(SClassRoT) {
	ut32 flags;
	ut32 instanceStart;
	ut32 instanceSize;
#ifdef R_BIN_MACH064
	ut32 reserved;
#endif
	mach0_ut ivarLayout;     /* const uint8_t* (32/64-bit pointer) */
	mach0_ut name;		/* const char* (32/64-bit pointer) */
	mach0_ut baseMethods;    /* const SMEthodList* (32/64-bit pointer) */
	mach0_ut baseProtocols;  /* const SProtocolList* (32/64-bit pointer) */
	mach0_ut ivars;		/* const SIVarList* (32/64-bit pointer) */
	mach0_ut weakIvarLayout; /* const uint8_t * (32/64-bit pointer) */
	mach0_ut baseProperties; /* const SObjcPropertyList* (32/64-bit pointer) */
};

struct MACH0_(SProtocolList) {
	mach0_ut count; /* uintptr_t (a 32/64-bit value) */
			/* SProtocol* list[0];  These pointers follow inline */
};

struct MACH0_(SProtocol) {
	mach0_ut isa;			/* id* (32/64-bit pointer) */
	mach0_ut name;			/* const char * (32/64-bit pointer) */
	mach0_ut protocols;		/* SProtocolList* (32/64-bit pointer) */
	mach0_ut instanceMethods;	/* SMethodList* (32/64-bit pointer) */
	mach0_ut classMethods;		/* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalInstanceMethods; /* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalClassMethods;    /* SMethodList* (32/64-bit pointer) */
	mach0_ut instanceProperties;      /* struct SObjcPropertyList* (32/64-bit pointer) */
};

struct MACH0_(SIVarList) {
	ut32 entsize;
	ut32 count;
	/* SIVar first;  These structures follow inline */
};

struct MACH0_(SIVar) {
	mach0_ut offset; /* uintptr_t * (32/64-bit pointer) */
	mach0_ut name;   /* const char * (32/64-bit pointer) */
	mach0_ut type;   /* const char * (32/64-bit pointer) */
	ut32 alignment;
	ut32 size;
};

struct MACH0_(SObjcProperty) {
	mach0_ut name;       /* const char * (32/64-bit pointer) */
	mach0_ut attributes; /* const char * (32/64-bit pointer) */
};

struct MACH0_(SObjcPropertyList) {
	ut32 entsize;
	ut32 count;
	/* struct SObjcProperty first;  These structures follow inline */
};

struct MACH0_(SCategory) {
	mach0_ut name;
	mach0_ut targetClass;
	mach0_ut instanceMethods;
	mach0_ut classMethods;
	mach0_ut protocols;
	mach0_ut properties;
};

static mach0_ut va2pa(RBinFile *bf, mach0_ut p, ut32 *offset, ut32 *left);
static void get_ivar_list(RBinFile *bf, RBinClass *klass, mach0_ut p);
static void get_objc_property_list(RBinFile *bf, RBinClass *klass, mach0_ut p);
static void get_method_list(RBinFile *bf, RBinClass *klass, const char *class_name, bool is_static, objc_cache_opt_info *oi, mach0_ut p);
static void get_objc_property_list_of_lists(RBinFile *bf, RBinClass *klass, mach0_ut p);
static void get_method_list_of_lists(RBinFile *bf, RBinClass *klass, const char *class_name, bool is_static, objc_cache_opt_info *oi, mach0_ut p);
static void get_protocol_list_of_lists(RBinFile *bf, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p);
static void get_class_ro_t(RBinFile *bf, bool *is_meta_class, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p);
static RList *MACH0_(parse_categories)(RBinFile *bf, MetaSections *ms, const RSkipList *relocs, objc_cache_opt_info *oi);
static bool read_ptr_pa(RBinFile *bf, ut64 paddr, mach0_ut *out);
static bool read_ptr_va(RBinFile *bf, ut64 vaddr, mach0_ut *out);
static char *readstr(RBinFile *bf, mach0_ut p, ut32 *offset, ut32 *left);

static inline bool is_thumb(RBinFile *bf) {
	const struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
	return (bin->hdr.cputype == 12 && bin->hdr.cpusubtype == 9);
}

static mach0_ut va2pa(RBinFile *bf, mach0_ut p, ut32 *offset, ut32 *left) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, 0);

	mach0_ut r = 0;
	RBinObject *obj = bf->bo;

	if (offset) {
		*offset = 0;
	}
	if (left) {
		*left = 0;
	}
	// rename bin to 'mo'
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t)*) obj->bin_obj;
	if (bin->va2pa) {
		// TODO: bf must be first
		return bin->va2pa (p, offset, left, bf);
	}
	mach0_ut addr = p;
	if (bin->lastrange.addr) {
		// memoizatiooon
		RInterval itv = bin->lastrange;
		if (addr >= itv.addr && addr < itv.addr + itv.size) {
			if (offset) {
				*offset = addr - itv.addr;
			}
			if (left) {
				*left = itv.size - (addr - itv.addr);
			}
			return bin->lastrange_pa - obj->boffset + (addr - itv.addr);
		}
	}
	RBinSection *s;
	RVecSegment *sections = MACH0_(get_segments_vec) (bf, bin);  // don't free, cached by bin
	R_VEC_FOREACH (sections, s) {
		if (addr >= s->vaddr && addr < s->vaddr + s->vsize) {
			// XXX range should be with psize, otherwise the bound can be wrong on pa
			bin->lastrange.addr = s->vaddr;
			bin->lastrange.size = s->vsize;
			bin->lastrange_pa = s->paddr;
			if (offset) {
				*offset = addr - s->vaddr;
			}
			if (left) {
				*left = s->vsize - (addr - s->vaddr);
			}
			r = s->paddr - obj->boffset + (addr - s->vaddr);
			break;
		}
	}
	return r;
}

static int sort_by_offset(const RBinField *a, const RBinField *b) {
	if (a->offset > b->offset) {
		return 1;
	}
	if (a->offset < b->offset) {
		return -1;
	}
	return 0;
}

static void get_ivar_list(RBinFile *bf, RBinClass *klass, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && klass);
	if (class_names_only (bf)) {
		return;
	}
	struct MACH0_(SIVarList) il = {0};
	struct MACH0_(SIVar) i;
	ut32 offset, left, j;

	int len;
	mach0_ut ivar_offset;
	RBinField *field = NULL;
	ut8 sivarlist[sizeof (struct MACH0_(SIVarList))] = {0};
	ut8 sivar[sizeof (struct MACH0_(SIVar))] = {0};
	ut8 offs[sizeof (mach0_ut)] = {0};

	if (!bf->bo || !bf->bo->bin_obj || !bf->bo->info) {
		R_LOG_WARN ("Incorrect RBinFile pointer");
		return;
	}
	const bool bigendian = bf->bo->info->big_endian;
	mach0_ut r = va2pa (bf, p, &offset, &left);
	if (!r || r + left < r || r + sizeof (struct MACH0_(SIVarList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof (struct MACH0_(SIVarList)) > bf->size) {
		return;
	}
	if (left < sizeof (struct MACH0_(SIVarList))) {
		if (r_buf_read_at (bf->buf, r, sivarlist, left) != left) {
			return;
		}
	} else {
		len = r_buf_read_at (bf->buf, r, sivarlist, sizeof (struct MACH0_(SIVarList)));
		if (len != sizeof (struct MACH0_(SIVarList))) {
			return;
		}
	}
	il.entsize = r_read_ble (&sivarlist[0], bigendian, 32);
	il.count = r_read_ble (&sivarlist[4], bigendian, 32);
	p += sizeof (struct MACH0_(SIVarList));
	offset += sizeof (struct MACH0_(SIVarList));

	struct MACH0_(obj_t) *mo = (struct MACH0_(obj_t) *) bf->bo->bin_obj;
	for (j = 0; j < il.count; j++) {
		r = va2pa (bf, p, &offset, &left);
		if (!r) {
			return;
		}
		field = RVecRBinField_emplace_back (&klass->fields);
		if (!field) {
			return;
		}
		memset (&i, '\0', sizeof (struct MACH0_(SIVar)));
		if (r + left < r || r + sizeof (struct MACH0_(SIVar)) < r) {
			goto error;
		}
		if (r > bf->size || r + left > bf->size) {
			goto error;
		}
		if (r + sizeof (struct MACH0_(SIVar)) > bf->size) {
			goto error;
		}
		if (left < sizeof (struct MACH0_(SIVar))) {
			if (r_buf_read_at (bf->buf, r, sivar, left) != left) {
				goto error;
			}
		} else {
			len = r_buf_read_at (bf->buf, r, sivar, sizeof (struct MACH0_(SIVar)));
			if (len != sizeof (struct MACH0_(SIVar))) {
				goto error;
			}
		}
#if R_BIN_MACH064
		i.offset = r_read_ble (&sivar[0], bigendian, 64);
		i.name = r_read_ble (&sivar[8], bigendian, 64);
		i.type = r_read_ble (&sivar[16], bigendian, 64);
		i.alignment = r_read_ble (&sivar[24], bigendian, 32);
		i.size = r_read_ble (&sivar[28], bigendian, 32);
#else
		i.offset = r_read_ble (&sivar[0], bigendian, 32);
		i.name = r_read_ble (&sivar[4], bigendian, 32);
		i.type = r_read_ble (&sivar[8], bigendian, 32);
		i.alignment = r_read_ble (&sivar[12], bigendian, 32);
		i.size = r_read_ble (&sivar[16], bigendian, 32);
#endif
		field->vaddr = i.offset;
		mach0_ut offset_at = va2pa (bf, i.offset, NULL, &left);

		if (offset_at > bf->size) {
			goto error;
		}
		if (offset_at + sizeof (ivar_offset) > bf->size) {
			goto error;
		}
		if (offset_at != 0 && left >= sizeof (mach0_ut)) {
			len = r_buf_read_at (bf->buf, offset_at, offs, sizeof (mach0_ut));
			if (len != sizeof (mach0_ut)) {
				R_LOG_ERROR ("reading");
				goto error;
			}
			ivar_offset = r_read_ble (offs, bigendian, 8 * sizeof (mach0_ut));
			field->offset = ivar_offset;
		}
		r = va2pa (bf, i.name, NULL, &left);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
			if (r + left < r) {
				goto error;
			}
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			char *name;
			if (bin->has_crypto) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				const int name_len = R_MIN (MAX_CLASS_NAME_LEN, left);
				name = malloc (name_len + 1);
				len = r_buf_read_at (bf->buf, r, (ut8 *)name, name_len);
				if (len < 1) {
					R_LOG_ERROR ("reading2");
					R_FREE (name);
					goto error;
				}
				name[name_len] = 0;
			}
			field->name = r_bin_name_new (name);
			free (name);
		} else {
			R_LOG_WARN ("not parsing ivars, wrong va2pa");
		}

		r = va2pa (bf, i.type, NULL, &left);
		if (!r) {
			R_LOG_DEBUG ("va2pa error");
			goto error;
		}
		if (r + left < r || r > bf->size || r + left > bf->size) {
			goto error;
		}
		char *type = NULL;
		if (mo->has_crypto) {
			type = strdup ("some_encrypted_data");
		} else {
			int type_len = R_MIN (MAX_CLASS_NAME_LEN, left);
			type = calloc (1, type_len + 1);
			if (type) {
				r_buf_read_at (bf->buf, r, (ut8 *)type, type_len);
				type[type_len] = 0;
			}
		}
		if (type) {
			field->type = r_bin_name_new (type);
			R_FREE (type);
		}
		if (!field->name) {
			R_LOG_WARN ("field name is empty");
			RVecRBinField_pop_back (&klass->fields);
		} else {
			field->kind = R_BIN_FIELD_KIND_VARIABLE;
		}
		p += sizeof (struct MACH0_(SIVar));
		offset += sizeof (struct MACH0_(SIVar));
	}
	RVecRBinField_sort (&klass->fields, sort_by_offset);
	RBinField *isa = RVecRBinField_emplace_front (&klass->fields);
	if (isa) {
		isa->name = r_bin_name_new ("isa");
		isa->size = sizeof (mach0_ut);
		isa->type = r_bin_name_new ("struct objc_class *");
		isa->kind = R_BIN_FIELD_KIND_VARIABLE;
		isa->vaddr = 0;
		isa->offset = 0;
	}
	return;
error:
	if (field) {
		RVecRBinField_pop_back (&klass->fields);
	}
}

static void get_objc_property_list(RBinFile *bf, RBinClass *klass, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info && klass);
	if (class_names_only (bf)) {
		return;
	}
	struct MACH0_(SObjcPropertyList) opl;
	struct MACH0_(SObjcProperty) op;
	mach0_ut r;
	ut32 offset, left, j;
	int len;
	RBinField *property = NULL;
	ut8 sopl[sizeof (struct MACH0_(SObjcPropertyList))] = {0};
	ut8 sop[sizeof (struct MACH0_(SObjcProperty))] = {0};

	if (!bf->bo->bin_obj) {
		R_LOG_WARN ("Incorrect RBinFile pointer");
		return;
	}
	const bool bigendian = bf->bo->info->big_endian;
	r = va2pa (bf, p, &offset, &left);
	if (!r) {
		return;
	}
	memset (&opl, '\0', sizeof (struct MACH0_(SObjcPropertyList)));
	if (r + left < r || r + sizeof (struct MACH0_(SObjcPropertyList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof (struct MACH0_(SObjcPropertyList)) > bf->size) {
		return;
	}
	if (left < sizeof (struct MACH0_(SObjcPropertyList))) {
		if (r_buf_read_at (bf->buf, r, sopl, left) != left) {
			return;
		}
	} else {
		len = r_buf_read_at (bf->buf, r, sopl, sizeof (struct MACH0_(SObjcPropertyList)));
		if (len != sizeof (struct MACH0_(SObjcPropertyList))) {
			return;
		}
	}

	opl.entsize = r_read_ble (&sopl[0], bigendian, 32);
	opl.count = r_read_ble (&sopl[4], bigendian, 32);

	p += sizeof (struct MACH0_(SObjcPropertyList));
	offset += sizeof (struct MACH0_(SObjcPropertyList));
	for (j = 0; j < opl.count; j++) {
		r = va2pa (bf, p, &offset, &left);
		if (!r) {
			return;
		}
		property = RVecRBinField_emplace_back (&klass->fields);
		if (!property) {
			return;
		}
		memset (&op, '\0', sizeof (struct MACH0_(SObjcProperty)));

		if (r + left < r || r + sizeof (struct MACH0_(SObjcProperty)) < r) {
			goto error;
		}
		if (r > bf->size || r + left > bf->size) {
			goto error;
		}
		if (r + sizeof (struct MACH0_(SObjcProperty)) > bf->size) {
			goto error;
		}

		if (left < sizeof (struct MACH0_(SObjcProperty))) {
			if (r_buf_read_at (bf->buf, r, sop, left) != left) {
				goto error;
			}
		} else {
			len = r_buf_read_at (bf->buf, r, sop, sizeof (struct MACH0_(SObjcProperty)));
			if (len != sizeof (struct MACH0_(SObjcProperty))) {
				goto error;
			}
		}
		op.name = r_read_ble (&sop[0], bigendian, 8 * sizeof (mach0_ut));
		op.attributes = r_read_ble (&sop[sizeof (mach0_ut)], bigendian, 8 * sizeof (mach0_ut));
		r = va2pa (bf, op.name, NULL, &left);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
			if (r > bf->size || r + left > bf->size || r + left < r) {
				goto error;
			}
			if (bin->has_crypto) {
				const char k[] = "some_encrypted_data";
				property->name = r_bin_name_new (k);
			} else {
				char lname[MAX_CLASS_NAME_LEN] = {0};
				size_t name_len = R_MIN (MAX_CLASS_NAME_LEN - 1, left);
				if (r_buf_read_at (bf->buf, r, (ut8 *)lname, name_len) != name_len) {
					goto error;
				}
				if (*lname) {
					property->name = r_bin_name_new (lname);
				}
			}
			property->kind = R_BIN_FIELD_KIND_PROPERTY;
			property->offset = j;
			property->paddr = r;
		}
		if (!property->name) {
			RVecRBinField_pop_back (&klass->fields);
		}
		p += sizeof (struct MACH0_(SObjcProperty));
		offset += sizeof (struct MACH0_(SObjcProperty));
	}
	return;
error:
	if (property) {
		RVecRBinField_pop_back (&klass->fields);
	}
}

///////////////////////////////////////////////////////////////////////////////
static void iterate_list_of_lists(RBinFile *bf, OnList cb, void * ctx, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info && bf->bo->bin_obj);

	bool bigendian = bf->bo->info->big_endian;
	ut32 offset, left;
	mach0_ut r = va2pa (bf, p, &offset, &left);
	if (!r) {
		return;
	}

	ut32 count;
	ut8 tmp[sizeof (ut32) * 2];

	if (r + left < r || r + sizeof (tmp) < r) {
		return;
	}
	if (r > bf->size) {
		return;
	}
	if (r + sizeof (tmp) > bf->size) {
		return;
	}
	if (left < sizeof (tmp)) {
		return;
	}

	if (r_buf_read_at (bf->buf, r, tmp, sizeof (tmp)) != sizeof (tmp)) {
		return;
	}

	ut32 entsize = r_read_ble (&tmp[0], bigendian, 32);
	count = r_read_ble (&tmp[4], bigendian, 32);
	if (count < 1 || count > ST32_MAX) {
		return;
	}
	if (r + count * entsize > bf->size) {
		return;
	}

	p += sizeof (tmp);

	int i;
	for (i = 0; i < count; i++) {
		r = va2pa (bf, p, &offset, &left);
		if (!r || r == -1) {
			return;
		}

		ListOfListsEntry entry = {0};
		if (r + left < r || r + entsize < r) {
			break;
		}
		if (r > bf->size) {
			break;
		}
		if (r + entsize > bf->size) {
			break;
		}
		if (left < entsize) {
			break;
		}
		size_t mines = R_MIN (entsize, sizeof (entry));
		if (entsize < sizeof (entry)) {
			R_LOG_WARN ("wrong lole size, breaking, not enough to read");
			break;
		} else if (entsize != sizeof (entry)) {
			R_LOG_WARN ("wrong lole size. fuzzed blob?");
		}
		if (r_buf_read_at (bf->buf, r, (ut8*)&entry, mines) != mines) {
			break;
		}

		mach0_ut list_address = p + entry.list_offset;
		cb (list_address, ctx);

		p += entsize;
	}
}

// TODO: remove class_name, because it's already in klass->name
static void get_method_list(RBinFile *bf, RBinClass *klass, const char *class_name, bool is_static, objc_cache_opt_info *oi, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info && bf->bo->bin_obj && klass);
	if (class_names_only (bf)) {
		return;
	}
	ut32 offset, left, i;
	char *name = NULL;
	char *rtype = NULL;
	int len;
	struct MACH0_(SMethodList) ml = {0};
	ut8 sml[sizeof (struct MACH0_(SMethodList))] = {0};
	ut8 sm[sizeof (struct MACH0_(SMethod))] = {0};

	const bool bigendian = bf->bo->info->big_endian;
	const bool want_unnamed = load_unnamed (bf);
	mach0_ut r = va2pa (bf, p, &offset, &left);
	if (r == 0 || r == (mach0_ut)-1) {
		return;
	}
	if (r + left < r || r + sizeof (struct MACH0_(SMethodList)) < r) {
		return;
	}
	if (r > bf->size) {
		return;
	}
	if (r + sizeof (struct MACH0_(SMethodList)) > bf->size) {
		return;
	}
	if (left < sizeof (struct MACH0_(SMethodList))) {
		if (r_buf_read_at (bf->buf, r, sml, left) != left) {
			return;
		}
	} else {
		len = r_buf_read_at (bf->buf, r, sml, sizeof (struct MACH0_(SMethodList)));
		if (len != sizeof (struct MACH0_(SMethodList))) {
			return;
		}
	}
	ml.entsize = r_read_ble (&sml[0], bigendian, 32);
	ml.count = r_read_ble (&sml[4], bigendian, 32);
	if (ml.count < 1 || ml.count > ST32_MAX) {
		return;
	}
	if (r + (ml.count * (ml.entsize & ~METHOD_LIST_ENTSIZE_FLAG_MASK)) > bf->size) {
		return;
	}

	bool is_small = (ml.entsize & METHOD_LIST_FLAG_IS_SMALL) != 0;
	ut8 mlflags = ml.entsize & 0x3;

	p += sizeof (struct MACH0_(SMethodList));
	offset += sizeof (struct MACH0_(SMethodList));

	size_t read_size = is_small ? 3 * sizeof (ut32): sizeof (struct MACH0_(SMethod));

	RBinSymbol *method = NULL;
	for (i = 0; i < ml.count; i++) {
		r = va2pa (bf, p, &offset, &left);
		if (!r || r == -1) {
			return;
		}

		method = R_NEW0 (RBinSymbol);
		struct MACH0_(SMethod) m = {0};
		if (r + left < r || r + read_size < r) {
			goto error;
		}
		if (r > bf->size) {
			goto error;
		}
		if (r + read_size > bf->size) {
			goto error;
		}
		if (left < read_size) {
			if (r_buf_read_at (bf->buf, r, sm, left) != left) {
				goto error;
			}
		} else {
			len = r_buf_read_at (bf->buf, r, sm, read_size);
			if (len != read_size) {
				goto error;
			}
		}
		if (!is_small) {
			m.name = r_read_ble (&sm[0], bigendian, 8 * sizeof (mach0_ut));
			m.types = r_read_ble (&sm[sizeof (mach0_ut)], bigendian, 8 * sizeof (mach0_ut));
			m.imp = r_read_ble (&sm[2 * sizeof (mach0_ut)], bigendian, 8 * sizeof (mach0_ut));
		} else {
			st64 name_offset = (st32) r_read_ble (&sm[0], bigendian, 8 * sizeof (ut32));
			mach0_ut name;
			if (oi && oi->sel_string_base) {
				name = oi->sel_string_base + name_offset;
			} else {
				name = p + name_offset;
			}
			if (mlflags != METHOD_LIST_FLAG_IS_PREOPT) {
				r = va2pa (bf, name, &offset, &left);
				if (!r) {
					goto error;
				}
				ut8 tmp[8];
				if (r_buf_read_at (bf->buf, r, tmp, sizeof (mach0_ut)) != sizeof (mach0_ut)) {
					goto error;
				}
				m.name = r_read_ble (tmp, bigendian, 8 * sizeof (mach0_ut));
			} else {
				m.name = name;
			}
			st64 types_offset = (st32) r_read_ble (&sm[sizeof (ut32)], bigendian, 8 * sizeof (ut32));
			m.types = p + types_offset + 4;
			st64 imp_offset = (st32) r_read_ble (&sm[2 * sizeof (ut32)], bigendian, 8 * sizeof (ut32));
			m.imp = p + imp_offset + 8;
		}

		r = va2pa (bf, m.name, NULL, &left);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
			if (left < 0 || r > bf->size || r + MAX_CLASS_NAME_LEN > bf->size) {
				goto error;
			}
			if (bin->has_crypto) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				int name_len = R_MIN (MAX_CLASS_NAME_LEN, left);
				name = malloc (name_len + 1);
				len = r_buf_read_at (bf->buf, r, (ut8 *)name, name_len);
				name[name_len] = 0;
				// eprintf ("%d %d\n", name_len, strlen (name));
				if (len < 1) {
					goto error;
				}
			}
			if (!want_unnamed && R_STR_ISEMPTY (name)) {
				R_FREE (name);
				r_bin_symbol_free (method);
				goto next;
			}
			if (class_name) { // XXX to save memory we can just ref the RBinName instance from the class
				method->classname = strdup (class_name);
			} else {
				R_LOG_ERROR ("Invalid class name for method. Avoid parsing invalid data");
				goto error;
			}
			method->name = r_bin_name_new (name);
			R_FREE (name);
		}
		if (!method->name) {
			r_bin_symbol_free (method);
			goto next;
		}

		r = va2pa (bf, m.types, NULL, &left);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
			if (r + left > bf->size) {
				left = bf->size - r;
			}
			if (r + left < r || r > bf->size || r + left > bf->size) {
				goto error;
			}
			if (bin->has_crypto) {
				rtype = strdup ("some_encrypted_data");
				left = strlen (rtype) + 1;
			} else {
				left = 1;
				rtype = malloc (left + 1);
				if (!rtype) {
					goto error;
				}
				if (r_buf_read_at (bf->buf, r, (ut8 *)rtype, left) != left) {
					R_FREE (rtype);
					goto error;
				}
				rtype[left] = 0;
			}
			method->rtype = rtype;
			rtype = NULL;
		}
		method->lang = R_BIN_LANG_OBJC;
		method->vaddr = m.imp;
		if (!method->vaddr) {
			r_bin_symbol_free (method);
			goto next;
		}
		method->type = is_static? R_BIN_TYPE_FUNC_STR: R_BIN_TYPE_METH_STR;
		if (is_static) {
			// it's a clas method, aka does not require an instance
			method->attr |= R_BIN_ATTR_CLASS;
		}
		if (is_thumb (bf)) {
			if (method->vaddr & 1) {
				method->vaddr >>= 1;
				method->vaddr <<= 1;
				//eprintf ("0x%08llx METHOD %s\n", method->vaddr, method->name);
			}
		}
		RVecRBinSymbol_push_back (&klass->methods, method);
		free (method);
next:
		p += read_size;
		offset += read_size;
	}
	return;
error:
	r_bin_symbol_free (method);
	R_FREE (name);
	R_FREE (rtype);
	return;
}

static void get_protocol_list(RBinFile *bf, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && klass && bf->bo && bf->bo->info && bf->bo->bin_obj);
	if (class_names_only (bf)) {
		return;
	}
	struct MACH0_(SProtocolList) pl = {0};
	struct MACH0_(SProtocol) pc;
	ut32 offset, left, i;
	mach0_ut q;
	int len;
	char *class_name = NULL;
	ut8 spl[sizeof (struct MACH0_(SProtocolList))] = {0};
	ut8 spc[sizeof (struct MACH0_(SProtocol))] = {0};
	ut8 sptr[sizeof (mach0_ut)] = {0};

	const bool bigendian = bf->bo->info->big_endian;
	const size_t ptr_size = sizeof (mach0_ut);
	mach0_ut r = va2pa (bf, p, &offset, &left);
	if (!r || r + left < r || r + sizeof (struct MACH0_(SProtocolList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof (struct MACH0_(SProtocolList)) > bf->size) {
		return;
	}
	if (left < sizeof (struct MACH0_(SProtocolList))) {
		if (r_buf_read_at (bf->buf, r, spl, left) != left) {
			return;
		}
	} else {
		len = r_buf_read_at (bf->buf, r, spl, sizeof (struct MACH0_(SProtocolList)));
		if (len != sizeof (struct MACH0_(SProtocolList))) {
			return;
		}
	}
	pl.count = r_read_ble (&spl[0], bigendian, 8 * sizeof (mach0_ut));
	if (pl.count < 1 || pl.count > ST32_MAX) {
		return;
	}

	p += sizeof (struct MACH0_(SProtocolList));
	offset += sizeof (struct MACH0_(SProtocolList));
	for (i = 0; i < pl.count; i++) {
		if (!(r = va2pa (bf, p, &offset, &left))) {
			return;
		}
		if (r + left < r || r + sizeof (mach0_ut) < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (r + sizeof (mach0_ut) > bf->size) {
			return;
		}
		if (left < ptr_size) {
			return;
		}
		len = r_buf_read_at (bf->buf, r, sptr, ptr_size);
		if (len != ptr_size) {
			return;
		}
		q = r_read_ble (&sptr[0], bigendian, 8 * sizeof (mach0_ut));
		if (!(r = va2pa (bf, q, &offset, &left))) {
			return;
		}
		memset (&pc, '\0', sizeof (struct MACH0_(SProtocol)));
		if (r + left < r || r + sizeof (struct MACH0_(SProtocol)) < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (r + sizeof (struct MACH0_(SProtocol)) > bf->size) {
			return;
		}
		if (left < sizeof (struct MACH0_(SProtocol))) {
			if (r_buf_read_at (bf->buf, r, spc, left) != left) {
				return;
			}
		} else {
			len = r_buf_read_at (bf->buf, r, spc, sizeof (struct MACH0_(SProtocol)));
			if (len != sizeof (struct MACH0_(SProtocol))) {
				return;
			}
		}
		const size_t sz = 8 * sizeof (mach0_ut);
		const ut8 *scp = (const ut8*)&spc;
		pc.isa = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.name = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.protocols = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.instanceMethods = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.classMethods = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.optionalInstanceMethods = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.optionalClassMethods = r_read_ble (scp, bigendian, sz);
		scp += sizeof (mach0_ut);
		pc.instanceProperties = r_read_ble (scp, bigendian, sz);
		r = va2pa (bf, pc.name, NULL, &left);
		if (r != 0) {
			char *name = NULL;
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
			if (r + left < r) {
				return;
			}
			if (r > bf->size || r + left > bf->size) {
				return;
			}
			if (bin->has_crypto) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				int name_len = R_MIN (MAX_CLASS_NAME_LEN, left);
				name = malloc (name_len + 1);
				if (!name) {
					return;
				}
				if (r_buf_read_at (bf->buf, r, (ut8 *)name, name_len) != name_len) {
					R_FREE (name);
					return;
				}
				name[name_len] = 0;
			}
			const char *cname = r_bin_name_tostring2 (klass->name, 'd');
			class_name = r_str_newf ("%s::(protocol)%s", cname, name);
			R_FREE (name);
		}

		if (pc.instanceMethods > 0) {
			get_method_list (bf, klass, class_name, false, oi, pc.instanceMethods);
		}
		if (pc.classMethods > 0) {
			get_method_list (bf, klass, class_name, true, oi, pc.classMethods);
		}
		R_FREE (class_name);
		p += ptr_size;
		offset += ptr_size;
	}
}

static void on_property_list(mach0_ut p, void * _ctx) {
	PropertyListOfListsCtx * ctx = _ctx;

	get_objc_property_list (ctx->bf, ctx->klass, p);
}

static void get_objc_property_list_of_lists(RBinFile *bf, RBinClass *klass, mach0_ut p) {
	PropertyListOfListsCtx ctx = {
		.bf = bf,
		.klass = klass,
	};
	iterate_list_of_lists (bf, on_property_list, &ctx, p);
}

static void on_method_list(mach0_ut p, void * _ctx) {
	MethodListOfListsCtx * ctx = _ctx;
	get_method_list (ctx->bf, ctx->klass, ctx->class_name, ctx->is_static, ctx->oi, p);
}

static void get_method_list_of_lists(RBinFile *bf, RBinClass *klass, const char *class_name, bool is_static, objc_cache_opt_info *oi, mach0_ut p) {
	MethodListOfListsCtx ctx = {
		.bf = bf,
		.class_name = class_name,
		.klass = klass,
		.is_static = is_static,
		.oi = oi,
	};
	iterate_list_of_lists (bf, on_method_list, &ctx, p);
}

static void on_protocol_list(mach0_ut p, void * _ctx) {
	ProtocolListOfListsCtx * ctx = _ctx;
	get_protocol_list (ctx->bf, ctx->klass, ctx->oi, p);
}

static void get_protocol_list_of_lists(RBinFile *bf, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p) {
	ProtocolListOfListsCtx ctx = {
		.bf = bf,
		.klass = klass,
		.oi = oi,
	};
	iterate_list_of_lists (bf, on_protocol_list, &ctx, p);
}

static char *demangle_swift(RBinFile *bf, const char *s) {
	return r_bin_demangle (bf, "swift", s, 0, false);
}

static char *demangle_classname(RBinFile *bf, const char *s) {
	char *ret;
	if (r_str_startswith (s, "_TtC")) {
		ret = demangle_swift (bf, s);
	} else {
		ret = strdup (s);
	}
	return ret;
}

static char *get_class_name(RBinFile *bf, mach0_ut p) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->info && bf->bo->bin_obj, NULL);
	RBinObject *bo = bf->bo;
	ut32 offset, left;
	int len;
	ut8 sc[sizeof (mach0_ut)] = {0};
	const ut32 ptr_size = sizeof (mach0_ut);

	if (!p) {
		return NULL;
	}
	bool bigendian = bo->info->big_endian;
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bo->bin_obj;

	ut64 r = va2pa (bf, p, &offset, &left);
	if (!r || (r + left) < r || (r + sizeof (sc)) < r || r > bf->size) {
		return NULL;
	}
	if (r + sizeof (sc) > bf->size) {
		return NULL;
	}
	if (left < sizeof (sc)) {
		return NULL;
	}
	len = r_buf_read_at (bf->buf, r + 4 * ptr_size, sc, sizeof (sc));
	if (len != sizeof (sc)) {
		return NULL;
	}

	ut64 rodata = r_read_ble (sc, bigendian, 8 * ptr_size);
	if (!(r = va2pa (bf, rodata, &offset, &left))) {
		return NULL;
	}
	if (r + left < r || r + sizeof (sc) < r) {
		return NULL;
	}
	if (r > bf->size) {
		return NULL;
	}
	if (r + sizeof (sc) > bf->size) {
		return NULL;
	}
	if (left < sizeof (sc)) {
		return NULL;
	}

#ifdef R_BIN_MACH064
	len = r_buf_read_at (bf->buf, r + 4 * sizeof (ut32) + ptr_size, sc, sizeof (sc));
#else
	len = r_buf_read_at (bf->buf, r + 3 * sizeof (ut32) + ptr_size, sc, sizeof (sc));
#endif
	if (len != sizeof (sc)) {
		return NULL;
	}
	ut64 name = r_read_ble (sc, bigendian, 8 * ptr_size);

	if ((r = va2pa (bf, name, NULL, &left))) {
		if (left < 1 || r + left < r) {
			return NULL;
		}
		if (r > bf->size || r + MAX_CLASS_NAME_LEN > bf->size) {
			return NULL;
		}
		if (bin->has_crypto) {
			return strdup ("some_encrypted_data");
		}
#if 0
		char name[MAX_CLASS_NAME_LEN];
		int name_len = R_MIN (sizeof (name), left);
		int rc = r_buf_read_at (bf->buf, r, (ut8 *)name, name_len);
		if (rc != name_len) {
			rc = 0;
		}
		name[sizeof (name) - 1] = 0;
		return strdup (name);
#else
		ut32 off = r;
		return readstr (bf, name, &off, &left);
#endif
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_ro_t(RBinFile *bf, bool *is_meta_class, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p) {
	struct MACH0_(obj_t) *bin;
	struct MACH0_(SClassRoT) cro = {0};
	ut32 offset, left, i;
	ut64 r, s;
	int len;
	bool bigendian;
	ut8 scro[sizeof (struct MACH0_(SClassRoT))] = {0};

	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->bo->info) {
		R_LOG_WARN ("Invalid RBinFile pointer");
		return;
	}
	bigendian = bf->bo->info->big_endian;
	const bool want_unnamed = load_unnamed (bf);
	bin = (struct MACH0_(obj_t) *)bf->bo->bin_obj;
	if (!(r = va2pa (bf, p, &offset, &left))) {
		// eprintf ("No pointer\n");
		return;
	}

	if (r + left < r || r + sizeof (cro) < r) {
		return;
	}
	if (r > bf->size || r + sizeof (cro) >= bf->size) {
		return;
	}
	if (r + sizeof (cro) > bf->size) {
		return;
	}

	// TODO: use r_buf_fread to avoid endianness issues
	if (left < sizeof (cro)) {
		R_LOG_ERROR ("Not enough data for SClassRoT");
		return;
	}
	len = r_buf_read_at (bf->buf, r, scro, sizeof (cro));
	if (len < 1) {
		return;
	}
	i = 0;
	cro.flags = r_read_ble (&scro[i], bigendian, 8 * sizeof (ut32));
	i += sizeof (ut32);
	cro.instanceStart = r_read_ble (&scro[i], bigendian, 8 * sizeof (ut32));
	i += sizeof (ut32);
	cro.instanceSize = r_read_ble (&scro[i], bigendian, 8 * sizeof (ut32));
	i += sizeof (ut32);
#ifdef R_BIN_MACH064
	cro.reserved = r_read_ble (&scro[i], bigendian, 8 * sizeof (ut32));
	i += sizeof (ut32);
#endif
	cro.ivarLayout = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.name = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.baseMethods = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.baseProtocols = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.ivars = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.weakIvarLayout = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));
	i += sizeof (mach0_ut);
	cro.baseProperties = r_read_ble (&scro[i], bigendian, 8 * sizeof (mach0_ut));

	s = r;
	if ((r = va2pa (bf, cro.name, NULL, &left))) {
		if (left < 1 || r + left < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (bin->has_crypto) {
			R_LOG_ERROR ("Not parsing encrypted data");
			return;
#if 0
			const char kn[] = "some_encrypted_data";
			klass->name = r_bin_name_new (kn);
			// klass->name = strdup ("some_encrypted_data");
			left = strlen (kn) + 1;
#endif
		} else {
			char name[MAX_CLASS_NAME_LEN];
			int name_len = R_MIN (MAX_CLASS_NAME_LEN - 1, left);
			int rc = r_buf_read_at (bf->buf, r, (ut8 *)name, name_len);
			if (rc != name_len) {
				rc = 0;
			}
			name[rc] = 0;
			if (!want_unnamed && !name[0]) {
				return;
			}
			r_bin_name_free (klass->name);
			klass->name = r_bin_name_new (name);
			char *dn = demangle_classname (bf, name);
			if (dn) {
				r_bin_name_demangled (klass->name, dn);
				free (dn);
			}
		}
		//eprintf ("0x%x  %s\n", s, klass->name);
		const char *klass_name = r_bin_name_tostring2 (klass->name, 'o');
		sdb_num_setf (bin->kv, s, 0, "objc_class_%s.offset", klass_name);
	}
	if (!klass->name && !want_unnamed) {
		return;
	}
#ifdef R_BIN_MACH064
	sdb_set (bin->kv, "objc_class.format", "lllll isa super cache vtable data", 0);
#else
	sdb_set (bin->kv, "objc_class.format", "xxxxx isa super cache vtable data", 0);
#endif

	if (is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) != 0;
	}
	if (class_names_only (bf)) {
		return;
	}

	if (cro.baseMethods > 0) {
		const char *klass_name = r_bin_name_tostring2 (klass->name, 'd');
		if (cro.baseMethods & 1) {
			get_method_list_of_lists (bf, klass, klass_name, (cro.flags & RO_META) ? true : false, oi, cro.baseMethods & ~1);
		} else {
			get_method_list (bf, klass, klass_name, (cro.flags & RO_META) ? true : false, oi, cro.baseMethods);
		}
	}
	if (cro.baseProtocols > 0) {
		if (cro.baseProtocols & 1) {
			get_protocol_list_of_lists (bf, klass, oi, cro.baseProtocols & ~1);
		} else {
			get_protocol_list (bf, klass, oi, cro.baseProtocols);
		}
	}
	if (cro.ivars > 0) {
		get_ivar_list (bf, klass, cro.ivars);
	}
	if (cro.baseProperties > 0) {
		if (cro.baseProperties & 1) {
			get_objc_property_list_of_lists (bf, klass, cro.baseProperties & ~1);
		} else {
			get_objc_property_list (bf, klass, cro.baseProperties);
		}
	}
	if (is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) != 0;
	}
}

static mach0_ut get_isa_value(void) {
	// TODO: according to otool sources this is taken from relocs
	return 0;
}

void MACH0_(get_class_t)(RBinFile *bf, RBinClass *klass, mach0_ut p, bool dupe, const RSkipList *relocs, objc_cache_opt_info *oi) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info);
	struct MACH0_(SClass) c = {0};
	const int size = sizeof (struct MACH0_(SClass));
	ut32 offset = 0, left = 0;
	bool is_meta_class = false;
	ut8 sc[sizeof (struct MACH0_(SClass))] = {0};

	const bool bigendian = bf->bo->info->big_endian;
	mach0_ut r = va2pa (bf, p, &offset, &left);
	if (!r || (r + left) < r || (r + size) < r || r > bf->size) {
		return;
	}
	if (r + size > bf->size) {
		return;
	}
	if (left < size) {
		R_LOG_ERROR ("Cannot parse obj class info out of bounds");
		return;
	}
	int len = r_buf_read_at (bf->buf, r, sc, size);
	if (len != size) {
		return;
	}

	const size_t sz = 8 * sizeof (mach0_ut);
	const ut8 *scp = (const ut8*)&sc;
	c.isa = r_read_ble (scp, bigendian, sz);
	scp += sizeof (mach0_ut);
	c.superclass = r_read_ble (scp, bigendian, sz);
	scp += sizeof (mach0_ut);
	c.cache = r_read_ble (scp, bigendian, sz);
	scp += sizeof (mach0_ut);
	c.vtable = r_read_ble (scp, bigendian, sz);
	scp += sizeof (mach0_ut);
	c.data = r_read_ble (scp, bigendian, sz);

	klass->addr = c.isa;
	if (c.superclass) {
		char *klass_name = get_class_name (bf, c.superclass);
		if (klass_name) {
#if 0
			// avoid registering when baseklass == superklass
			const char *base_klass_name = r_bin_name_tostring2 (klass->name, 'o');
			eprintf ("%s \n", base_klass_name, klass_name);
			if (base_klass_name && !strcmp (klass_name, base_klass_name)) {
				free (klass_name);
				return;
			}
#endif
			if (!klass->super) {
				klass->super = r_list_newf ((void *)r_bin_name_free);
			}
			RBinName *bn = r_bin_name_new (klass_name);
			char *dn = demangle_classname (bf, klass_name);
#if 0
			// avoid registering when demangled baseklass == demangled superklass
			const char *base_klass_name = r_bin_name_tostring2 (klass->name, 'd');
			if (base_klass_name && !strcmp (dn, base_klass_name)) {
				free (klass_name);
				return;
			}
#endif
			if (dn) {
				r_bin_name_demangled (bn, dn);
				free (dn);
			}
			r_list_append (klass->super, (void *)bn);
			free (klass_name);
		}
	} else if (relocs) {
		struct reloc_t reloc_at_class_addr = {
			.addr = p + sizeof (mach0_ut)
		};
		RSkipListNode *found = r_skiplist_find (relocs, &reloc_at_class_addr);
		if (found) {
			const char _objc_class[] = "_OBJC_CLASS_$_";
			const size_t _objc_class_len = strlen (_objc_class);
			const char *target_class_name = (char*) ((struct reloc_t*) found->data)->name;
			if (r_str_startswith (target_class_name, _objc_class)) {
				RBinName *sup = r_bin_name_new (target_class_name);
				target_class_name += _objc_class_len;
				r_bin_name_demangled (sup, target_class_name);
				if (r_str_startswith (target_class_name, "_T")) {
					char *dsuper = demangle_swift (bf, target_class_name);
					if (dsuper && strcmp (dsuper, target_class_name)) {
						r_bin_name_demangled (sup, dsuper);
					}
					free (dsuper);
				}
				if (klass->super == NULL) {
					klass->super = r_list_newf ((void *)r_bin_name_free);
				}
				r_list_append (klass->super, sup);
			}
		}
	}
	get_class_ro_t (bf, &is_meta_class, klass, oi, RO_DATA_PTR (c.data));

#if SWIFT_SUPPORT
	if (q (c.data + n_value) & 7) {
		klass->lang = R_BIN_LANG_SWIFT;
		R_LOG_DEBUG ("This is a Swift class");
	}
#endif
	if (!class_names_only (bf) && !is_meta_class && !dupe) {
		mach0_ut isa_n_value = get_isa_value ();
		ut64 tmp = klass->addr;
		MACH0_(get_class_t) (bf, klass, c.isa + isa_n_value, true, relocs, oi);
		klass->addr = tmp;
	}
}

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

static char *swift_typeref_str(SwiftCtx *ctx, const ut8 *p, int len, ut64 va);

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
					char *res = swift_typeref_str (ctx, (const ut8 *)rn + 2, l, 0);
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

// -- minimal demangler for swift type manglings found in field descriptors --

#define TSTK 24
#define TS_LIST 1
#define TS_FIRST 2

typedef struct {
	char *s[TSTK];
	ut8 mark[TSTK];
	ut16 rep[TSTK];
	int n;
} TypeStack;

static void tpush(TypeStack *ts, char *s, ut8 mark) {
	if (s && ts->n < TSTK) {
		ts->s[ts->n] = s;
		ts->mark[ts->n] = mark;
		ts->rep[ts->n] = 0;
		ts->n++;
	} else {
		free (s);
	}
}

static char *tpop(TypeStack *ts) {
	if (ts->n < 1) {
		return NULL;
	}
	ts->n--;
	char *s = ts->s[ts->n];
	if (ts->mark[ts->n] & TS_LIST) {
		free (s);
		return strdup ("()");
	}
	return s;
}

static const char *swift_stdtype(char c) {
	switch (c) {
	case 'a': return "Swift.Array";
	case 'b': return "Swift.Bool";
	case 'c': return "Swift.UnicodeScalar";
	case 'D': return "Swift.Dictionary";
	case 'd': return "Swift.Double";
	case 'f': return "Swift.Float";
	case 'h': return "Swift.Set";
	case 'i': return "Swift.Int";
	case 'J': return "Swift.Character";
	case 'N': return "Swift.ClosedRange";
	case 'n': return "Swift.Range";
	case 'P': return "Swift.UnsafePointer";
	case 'p': return "Swift.UnsafeMutablePointer";
	case 'q': return "Swift.Optional";
	case 'R': return "Swift.UnsafeBufferPointer";
	case 'r': return "Swift.UnsafeMutableBufferPointer";
	case 'S': case 's': return "Swift.String";
	case 'u': return "Swift.UInt";
	case 'V': return "Swift.UnsafeRawPointer";
	case 'v': return "Swift.UnsafeMutableRawPointer";
	case 'w': return "Swift.UnsafeRawBufferPointer";
	case 'W': return "Swift.UnsafeMutableRawBufferPointer";
	}
	return NULL;
}

// build a tuple from the stack: pops until (and including) the TS_FIRST item,
// or until a TS_LIST marker (exclusive)
static char *swift_build_tuple(TypeStack *ts) {
	char *elem[TSTK];
	ut16 reps[TSTK];
	int i, n = 0;
	while (ts->n > 0 && n < TSTK) {
		if (ts->mark[ts->n - 1] & TS_LIST) {
			if (n == 0) {
				ts->n--;
				free (ts->s[ts->n]);
			}
			break;
		}
		const bool first = ts->mark[ts->n - 1] & TS_FIRST;
		ts->n--;
		elem[n] = ts->s[ts->n];
		reps[n] = ts->rep[ts->n];
		n++;
		if (first) {
			break;
		}
	}
	if (n == 0) {
		return strdup ("()");
	}
	if (n == 1 && reps[0] > 0) {
		char *res = r_str_newf ("(%d x %s)", reps[0] + 1, elem[0]);
		free (elem[0]);
		return res;
	}
	RStrBuf *sb = r_strbuf_new ("(");
	for (i = n - 1; i >= 0; i--) {
		r_strbuf_append (sb, elem[i]);
		if (i > 0) {
			r_strbuf_append (sb, ", ");
		}
		free (elem[i]);
	}
	r_strbuf_append (sb, ")");
	return r_strbuf_drain (sb);
}

static void swift_build_generic(TypeStack *ts) {
	char *args[TSTK];
	int i, n = 0;
	while (ts->n > 0 && n < TSTK && !(ts->mark[ts->n - 1] & TS_LIST)) {
		ts->n--;
		args[n++] = ts->s[ts->n];
	}
	if (ts->n > 0 && (ts->mark[ts->n - 1] & TS_LIST)) {
		ts->n--;
		free (ts->s[ts->n]);
	}
	char *base = tpop (ts);
	if (!base) {
		// no base: restore args joined as-is
		for (i = n - 1; i >= 0; i--) {
			tpush (ts, args[i], 0);
		}
		return;
	}
	char *res = NULL;
	if (n == 1 && !strcmp (base, "Swift.Optional")) {
		res = r_str_newf ("%s?", args[0]);
	} else if (n == 1 && !strcmp (base, "Swift.Array")) {
		res = r_str_newf ("[%s]", args[0]);
	} else if (n == 2 && !strcmp (base, "Swift.Dictionary")) {
		res = r_str_newf ("[%s: %s]", args[1], args[0]);
	} else {
		RStrBuf *sb = r_strbuf_new (base);
		r_strbuf_append (sb, "<");
		for (i = n - 1; i >= 0; i--) {
			r_strbuf_append (sb, args[i]);
			if (i > 0) {
				r_strbuf_append (sb, ", ");
			}
		}
		r_strbuf_append (sb, ">");
		res = r_strbuf_drain (sb);
	}
	for (i = 0; i < n; i++) {
		free (args[i]);
	}
	free (base);
	tpush (ts, res, 0);
}

static void swift_build_function(TypeStack *ts, const char *conv, bool athrows, bool aasync) {
	char *params = tpop (ts);
	char *result = tpop (ts);
	if (!params) {
		free (result);
		return;
	}
	const char *fmt = (*params == '(')? "%s%s%s%s -> %s": "%s(%s)%s%s -> %s";
	char *res = r_str_newf (fmt, conv, params,
		aasync? " async": "", athrows? " throws": "", result? result: "()");
	free (params);
	free (result);
	tpush (ts, res, 0);
}

static char *swift_typeref_str(SwiftCtx *ctx, const ut8 *p, int len, ut64 va) {
	TypeStack ts = { {0} };
	bool athrows = false, aasync = false;
	int i = 0;
	while (i < len) {
		const ut8 b = p[i];
		if (b < 0x20) {
			char *name = NULL;
			if (b >= 1 && b <= 0x17) {
				if (i + 5 > len) {
					break;
				}
				if (va && (b == 1 || b == 2)) {
					const st32 rel = (st32)r_read_le32 (p + i + 1);
					const ut64 tgt = va + i + 1 + rel;
					name = (b == 1)
						? swift_context_qualname (ctx, tgt)
						: swift_indirect_qualname (ctx, tgt);
				}
				i += 5;
			} else {
				i += 9; // 8-byte absolute references
			}
			tpush (&ts, name? name: strdup ("?"), 0);
			continue;
		}
		if (isdigit (b) || (b == 's' && i + 1 < len && isdigit (p[i + 1]))
				|| (b == 'S' && i + 2 < len && p[i + 1] == 'o' && isdigit (p[i + 2]))) {
			RStrBuf *nb = r_strbuf_new (NULL);
			if (b == 's') {
				r_strbuf_append (nb, "Swift");
				i++;
			} else if (b == 'S') {
				r_strbuf_append (nb, "__C");
				i += 2;
			}
			bool kindchar = !isdigit (b); // only bare identifiers can be tuple labels
			int segments = 0;
			while (i < len && isdigit (p[i])) {
				int n = atoi ((const char *)p + i);
				while (i < len && isdigit (p[i])) {
					i++;
				}
				if (n < 1 || i + n > len) {
					break;
				}
				if (r_strbuf_length (nb) > 0) {
					r_strbuf_append (nb, ".");
				}
				r_strbuf_append_n (nb, (const char *)p + i, n);
				i += n;
				segments++;
				if (i < len && strchr ("CVOP", p[i])) {
					i++; // nominal kind marker
					kindchar = true;
				}
			}
			if (!kindchar && segments == 1 && ts.n > 0 && !(ts.mark[ts.n - 1] & TS_LIST)
					&& i < len && (p[i] == '_' || p[i] == 't')) {
				// tuple element label: follows its element type
				char *t = tpop (&ts);
				char *label = r_strbuf_drain (nb);
				tpush (&ts, r_str_newf ("%s: %s", label, t), 0);
				free (label);
				free (t);
			} else {
				tpush (&ts, r_strbuf_drain (nb), 0);
			}
			continue;
		}
		switch (b) {
		case '$':
			i += (i + 1 < len && p[i + 1] == 's')? 2: 1;
			break;
		case 'S':
			if (i + 1 >= len) {
				i = len;
				break;
			}
			if (p[i + 1] == 'g') {
				char *t = tpop (&ts);
				// optional function types need wrapping parens
				tpush (&ts, t? r_str_newf (strstr (t, " -> ")? "(%s)?": "%s?", t): NULL, 0);
				free (t);
			} else {
				const char *st = swift_stdtype (p[i + 1]);
				tpush (&ts, strdup (st? st: "?"), 0);
			}
			i += 2;
			break;
		case 'y':
			tpush (&ts, strdup ("y"), TS_LIST);
			i++;
			break;
		case '_':
			if (ts.n > 0) {
				ts.mark[ts.n - 1] |= TS_FIRST;
			}
			i++;
			break;
		case 't':
			tpush (&ts, swift_build_tuple (&ts), 0);
			i++;
			break;
		case 'A':
			i++;
			if (i < len && isdigit (p[i]) && ts.n > 0) {
				ts.rep[ts.n - 1] = atoi ((const char *)p + i);
				while (i < len && isdigit (p[i])) {
					i++;
				}
			}
			break;
		case 'G':
			swift_build_generic (&ts);
			i++;
			break;
		case 'X':
			if (i + 1 < len && p[i + 1] == 'C') {
				swift_build_function (&ts, "@convention(c) ", athrows, aasync);
				athrows = aasync = false;
			}
			i += 2;
			break;
		case 'c':
			swift_build_function (&ts, "", athrows, aasync);
			athrows = aasync = false;
			i++;
			break;
		case 'K':
			athrows = true;
			i++;
			break;
		case 'Y':
			if (i + 1 < len && p[i + 1] == 'a') {
				aasync = true;
			}
			i += 2;
			break;
		case 'z':
			// inout marker applies to the following type; approximate by prefixing the next push
			i++;
			break;
		case 'm':
			{
				char *t = tpop (&ts);
				tpush (&ts, t? r_str_newf ("%s.Type", t): NULL, 0);
				free (t);
				i++;
			}
			break;
		case 'x':
			tpush (&ts, strdup ("A"), 0);
			i++;
			break;
		case 'q':
			if (i + 1 < len && p[i + 1] == '_') {
				tpush (&ts, strdup ("B"), 0);
				i += 2;
			} else if (i + 2 < len && isdigit (p[i + 1]) && p[i + 2] == '_') {
				char gp[2] = { (char)('C' + (p[i + 1] - '0')), 0 };
				tpush (&ts, strdup (gp), 0);
				i += 3;
			} else {
				i++;
			}
			break;
		default:
			// unknown mangling op: stop here and use what we have
			i = len;
			break;
		}
	}
	char *res = NULL;
	while (ts.n > 0) {
		char *t = tpop (&ts);
		if (!res && t && strcmp (t, "()")) {
			res = t;
		} else {
			free (t);
		}
	}
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
	return (i > 0)? swift_typeref_str (ctx, buf, R_MIN (i, n), va): NULL;
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

// return the idx-th camelcase word of the identifiers in a mangled context,
// as used by the swift mangling word substitutions ("AA" and friends)
static char *swift_prefix_word(const char *prefix, int idx) {
	const char *p = prefix;
	while (p && *p) {
		if (!isdigit (*p)) {
			p++;
			continue;
		}
		const int n = atoi (p);
		p = r_str_trim_head_digits (p);
		if (n < 1 || n > (int)strlen (p)) {
			break;
		}
		int i = 0;
		while (i < n) {
			int j = i + 1;
			while (j < n && !isupper (p[j])) {
				j++;
			}
			if (j - i > 1) {
				if (idx == 0) {
					return r_str_ndup (p + i, j - i);
				}
				idx--;
			}
			i = j;
		}
		p += n;
	}
	return NULL;
}

// extract the member name and attributes from the tail of a mangled swift
// symbol after its nominal context ("3fooSivg" -> "foo" + GETTER); returns
// NULL for symbols that are not callable members (metadata, witnesses, ...)
static char *swift_member_name(const char *prefix, const char *rest, ut64 *attr) {
	if (R_STR_ISEMPTY (rest)) {
		return NULL;
	}
	char *mname = NULL;
	if (isdigit (*rest)) {
		const int n = atoi (rest);
		const char *e = r_str_trim_head_digits (rest);
		if (n > 0 && n <= (int)strlen (e)) {
			mname = r_str_ndup (e, n);
		}
	} else if (rest[0] == 'A' && isupper (rest[1])) {
		// word-substituted member name referencing the context words
		mname = swift_prefix_word (prefix, rest[1] - 'A');
	}
	size_t rl = strlen (rest);
	if (rest[rl - 1] == 'Z') {
		*attr |= R_BIN_ATTR_STATIC;
		rl--;
	}
	if (rl < 2) {
		free (mname);
		return NULL;
	}
	const char *tail = rest + rl - 2;
	if (!strncmp (tail, "fC", 2) || !strncmp (tail, "fc", 2)) {
		*attr |= R_BIN_ATTR_CONSTRUCTOR;
		free (mname);
		return strdup ("init");
	}
	if (!strncmp (tail, "fD", 2) || !strncmp (tail, "fd", 2)) {
		free (mname);
		return strdup ("deinit");
	}
	if (!mname) {
		return NULL;
	}
	if (!strncmp (tail, "vg", 2)) {
		*attr |= R_BIN_ATTR_GETTER;
	} else if (!strncmp (tail, "vs", 2)) {
		*attr |= R_BIN_ATTR_SETTER;
	} else if (!strncmp (tail, "vM", 2) || !strncmp (tail, "vr", 2)) {
		// modify/read coroutine accessors
	} else if (tail[1] == 'F') {
		if ((rl >= 3 && !strncmp (rest + rl - 3, "YaF", 3))
				|| (rl >= 4 && !strncmp (rest + rl - 4, "YaKF", 4))) {
			*attr |= R_BIN_ATTR_ASYNC;
		}
	} else {
		free (mname);
		return NULL; // metadata, witness tables, thunks, ...
	}
	return mname;
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
				dname = swift_member_name (prefix, rn + 2 + strlen (prefix), &mattr);
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
		char *mname = swift_member_name (prefix, rest, &attr);
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

RList *MACH0_(parse_classes)(RBinFile *bf, objc_cache_opt_info *oi) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);

	ut64 num_of_unnamed_class = 0;
	ut32 size = 0;
	RList *sctns = NULL;
	mach0_ut p = 0;
	ut32 left = 0;
	int len;
	ut8 pp[sizeof (mach0_ut)] = {0};

	const int limit = bf->rbin->options.limit;

	if (!bf->bo->bin_obj || !bf->bo->info) {
		return NULL;
	}
	const bool bigendian = bf->bo->info->big_endian;
	const RSkipList *relocs = MACH0_(load_relocs) (bf->bo->bin_obj);

	/* check if it's Swift */
	MetaSections ms = metadata_sections_init (bf);
	// R_DUMP (&ms);

	RList /*<RBinClass>*/ *ret = MACH0_(parse_categories) (bf, &ms, relocs, oi);
	if (!ret) {
		ret = r_list_newf ((RListFree)r_bin_class_free);
		if (!ret) {
			goto get_classes_error;
		}
	}
	if (limit > 0 && r_list_length (ret) >= limit) {
		metadata_sections_fini (&ms);
		return ret;
	}

	const bool want_swift = !r_sys_getenv_asbool ("RABIN2_MACHO_NOSWIFT");
	if (want_swift && ms.types.have) {
		SwiftCtx ctx = {
			.bf = bf,
			.relocs = relocs,
			.symbols_ht = class_names_only (bf)? NULL: _load_symbol_by_vaddr_hashtable (bf),
			.mangled_ht = ht_pp_new0 (),
		};
		const ut32 ntypes = ms.types.size / 4;
		ut32 i;
		for (i = 0; i < ntypes; i++) {
			if (limit > 0 && r_list_length (ret) >= limit) {
				R_LOG_WARN ("swift class limit reached");
				break;
			}
			const ut64 entry = ms.types.vaddr + (i * 4);
			const st32 word = swift_s32 (bf, entry);
			if (!word) {
				continue;
			}
			SwiftType st = swift_parse_type_entry (bf, entry + word);
			if (st.valid) {
				swift_parse_type (&ctx, ret, st);
			}
		}
		if (ms.protos.have) {
			swift_parse_protocols (&ctx, ret, &ms.protos);
		}
		if (ctx.symbols_ht && !class_names_only (bf)) {
			swift_attach_symbols (&ctx);
		}
		ht_up_free (ctx.symbols_ht);
		ht_pp_free (ctx.mangled_ht);
	}
	if (!ms.clslist.size || !ms.clslist.have) {
		goto get_classes_error;
	}

	if (!ms.clslist.have) {
		// eprintf ("there is no section __objc_classlist\n");
		goto get_classes_error;
	}
	// end of seaching of section with name __objc_classlist
	// start of getting information about each class in file
	ut32 i;
	for (i = 0; i < ms.clslist.size; i += sizeof (mach0_ut)) {
		left = ms.clslist.size - i;
		if (limit > 0 && r_list_length (ret) >= limit) {
			R_LOG_WARN ("classes mo.limit reached");
			break;
		}
		if (left < sizeof (mach0_ut)) {
			R_LOG_ERROR ("Chopped classlist data");
			break;
		}
		RBinClass *klass = r_bin_class_new ("", "", R_BIN_ATTR_PUBLIC);
		r_bin_name_free (klass->name); // allow NULL name in rbinclass?
		klass->name = NULL;
		klass->lang = R_BIN_LANG_OBJC;
		klass->origin = R_BIN_CLASS_ORIGIN_BIN;
		size = sizeof (mach0_ut);
		if (ms.clslist.addr > bf->size || ms.clslist.addr + size > bf->size) {
			goto get_classes_error;
		}
		if (ms.clslist.addr + size < ms.clslist.addr) {
			goto get_classes_error;
		}
		len = r_buf_read_at (bf->buf, ms.clslist.addr + i, pp, sizeof (mach0_ut));
		if (len != sizeof (mach0_ut)) {
			goto get_classes_error;
		}
		p = r_read_ble (&pp[0], bigendian, 8 * sizeof (mach0_ut));
		MACH0_(get_class_t) (bf, klass, p, false, relocs, oi);
		if (klass->name) {
			const char *klass_name = r_bin_name_tostring (klass->name);
			if (!load_unnamed (bf) && R_STR_ISEMPTY (klass_name)) {
				r_bin_class_free (klass);
				continue;
			}
			if (strlen (klass_name) > 512) {
				R_LOG_INFO ("Invalid class name, probably corrupted binary");
				break;
			}
		} else {
			if (!load_unnamed (bf)) {
				r_bin_class_free (klass);
				continue;
			}
			char *klass_name = r_str_newf ("UnnamedClass%" PFMT64d, num_of_unnamed_class);
			klass->name = r_bin_name_new (klass_name);
			free (klass_name);
			num_of_unnamed_class++;
		}
		klass->index = r_list_length (bf->bo->classes) + r_list_length (ret);
		r_list_append (ret, klass);
	}
	metadata_sections_fini (&ms);
	return ret;

get_classes_error:
	metadata_sections_fini (&ms);
	r_list_free (sctns);
	r_list_free (ret);
	// XXX DOUBLE FREE r_bin_class_free (klass);
	return NULL;
}

static RList *MACH0_(parse_categories)(RBinFile *bf, MetaSections *ms, const RSkipList *relocs, objc_cache_opt_info *oi) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj && bf->bo->info, NULL);
	R_LOG_DEBUG ("parse objc categories");
	const size_t ptr_size = sizeof (mach0_ut);
	const int limit = bf->rbin->options.limit;
	if (!ms->catlist.have) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree)r_bin_class_free);
	if (!ret || !relocs) {
		goto error;
	}

	ut32 i;
	for (i = 0; i < ms->catlist.size; i += ptr_size) {
		if (limit > 0 && r_list_length (ret) >= limit) {
			break;
		}
		mach0_ut p;

		if ((ms->catlist.size - i) < ptr_size) {
			R_LOG_WARN ("Truncated catlist data");
			break;
		}
		RBinClass *klass = r_bin_class_new ("", NULL, 0);
		r_bin_name_free (klass->name);
		klass->name = NULL;
		klass->origin = R_BIN_CLASS_ORIGIN_BIN;
		if (!read_ptr_pa (bf, ms->catlist.addr + i, &p)) {
			r_bin_class_free (klass);
			goto error;
		}
		MACH0_(get_category_t) (bf, klass, p, relocs, oi);
		if (!klass->name) {
			r_bin_class_free (klass);
			continue;
		}
		klass->lang = R_BIN_LANG_OBJC;
		const char *klass_name = r_bin_name_tostring (klass->name);
		char *par = strchr (klass_name, '(');
		if (par) {
			size_t idx = par - klass_name;
			char *super = strdup (klass_name);
			super[idx++] = 0;
			char *cpar = strchr (super + idx, ')');
			if (cpar) {
				*cpar = 0;
			}
			if (klass->super == NULL) {
				klass->super = r_list_newf ((void *)r_bin_name_free);
			}
			RBinName *bn = r_bin_name_new (super);
			// TODO: demangle name!!
			r_list_append (klass->super, bn);
			free (super);
		//	char *name = strdup (super + idx);
		//	free (klass->name);
		//	klass->name = name;
		}
		klass->index = r_list_length (bf->bo->classes) + r_list_length (ret);
		r_list_append (ret, klass);
	}
	return ret;

error:
	r_list_free (ret);
	return NULL;
}

void MACH0_(get_category_t)(RBinFile *bf, RBinClass *klass, mach0_ut p, const RSkipList *relocs, objc_cache_opt_info *oi) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info);

	struct MACH0_(SCategory) c = {0};
	const int size = sizeof (struct MACH0_(SCategory));
	mach0_ut r = 0;
	ut32 offset = 0, left = 0;
	int len;
	bool bigendian = bf->bo->info->big_endian;
	ut8 sc[sizeof (struct MACH0_(SCategory))] = {0};

	if (!(r = va2pa (bf, p, &offset, &left))) {
		return;
	}
	if ((r + left) < r || (r + size) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + size > bf->size) {
		return;
	}
	if (left < size) {
		R_LOG_ERROR ("Cannot parse obj category info out of bounds");
		return;
	}
	len = r_buf_read_at (bf->buf, r, sc, size);
	if (len != size) {
		return;
	}

	const size_t ptr_size = sizeof (mach0_ut);
	const ut32 bits = 8 * ptr_size;

	const ut8 *scp = (const ut8*)&sc;
	c.name = r_read_ble (scp, bigendian, bits);
	scp += ptr_size;
	c.targetClass = r_read_ble (scp, bigendian, bits);
	scp += ptr_size;
	c.instanceMethods = r_read_ble (scp, bigendian, bits);
	scp += ptr_size;
	c.classMethods = r_read_ble (scp, bigendian, bits);
	scp += ptr_size;
	c.protocols = r_read_ble (scp, bigendian, bits);
	scp += ptr_size;
	c.properties = r_read_ble (scp, bigendian, bits);

	char *category_name = readstr (bf, c.name, &offset, &left);
	if (!category_name) {
		return;
	}

	char *target_class_name = NULL;
	if (c.targetClass == 0) {
		if (!relocs) {
			R_FREE (category_name);
			return;
		}
		struct reloc_t reloc_at_class_addr;
		reloc_at_class_addr.addr = p + ptr_size;
		RSkipListNode *found = r_skiplist_find (relocs, &reloc_at_class_addr);
		if (!found) {
			R_FREE (category_name);
			return;
		}

		const char _objc_class[] = "_OBJC_CLASS_$_";
		const int _objc_class_len = strlen (_objc_class);
		target_class_name = (char*) ((struct reloc_t*) found->data)->name;
		if (!r_str_startswith (target_class_name, _objc_class)) {
			R_FREE (category_name);
			return;
		}
		target_class_name += _objc_class_len;
		char *kname = r_str_newf ("%s(%s)", target_class_name, category_name);
		klass->name = r_bin_name_new (kname);
		free (kname);
	} else {
		mach0_ut ro_data_field = c.targetClass + 4 * ptr_size;
		mach0_ut ro_data;
		if (!read_ptr_va (bf, ro_data_field, &ro_data)) {
			R_FREE (category_name);
			return;
		}
		mach0_ut name_field = RO_DATA_PTR (ro_data) + 3 * 4 + ptr_size;
#ifdef R_BIN_MACH064
		name_field += 4;
#endif
		mach0_ut name_at;
		if (!read_ptr_va (bf, name_field & ~1, &name_at)) {
			R_FREE (category_name);
			return;
		}

		target_class_name = readstr (bf, name_at, &offset, &left);
		if (target_class_name) {
			char *kname = r_str_newf ("%s(%s)", target_class_name, category_name);
			klass->name = r_bin_name_new (kname);
			char *demangled = demangle_classname (bf, target_class_name);
			if (demangled) {
				char *dname = r_str_newf ("%s(%s)", demangled, category_name);
				r_bin_name_demangled (klass->name, dname);
				free (dname);
				free (demangled);
			}
			free (kname);
		}
		free (target_class_name);
	}

	klass->addr = p;

	R_FREE (category_name);

	const char *klass_name = r_bin_name_tostring (klass->name);
	if (R_STR_ISEMPTY (klass_name)) {
		R_LOG_ERROR ("Invalid class name");
		return;
	}
	if (class_names_only (bf)) {
		return;
	}
	if (c.instanceMethods > 0) {
		get_method_list (bf, klass, klass_name, false, oi, c.instanceMethods);
	}
	if (c.classMethods > 0) {
		get_method_list (bf, klass, klass_name, true, oi, c.classMethods);
	}
	if (c.protocols > 0) {
		get_protocol_list (bf, klass, oi, c.protocols);
	}
	if (c.properties > 0) {
		get_objc_property_list (bf, klass, c.properties);
	}
}

static bool read_ptr_pa(RBinFile *bf, ut64 paddr, mach0_ut *out) {
	R_RETURN_VAL_IF_FAIL (out && bf && bf->bo && bf->bo->info, false);

	const size_t ptr_size = sizeof (mach0_ut);
	ut8 pp[sizeof (mach0_ut)] = {0};
	const int len = r_buf_read_at (bf->buf, paddr, pp, ptr_size);
	if (len != ptr_size) {
		return false;
	}
	*out = r_read_ble (&pp[0], bf->bo->info->big_endian, 8 * ptr_size);
	return true;
}

static bool read_ptr_va(RBinFile *bf, ut64 vaddr, mach0_ut *out) {
	R_RETURN_VAL_IF_FAIL (bf, false);
	ut32 offset = 0, left = 0;
	mach0_ut paddr = va2pa (bf, vaddr, &offset, &left);
	if (paddr == 0 || left < sizeof (mach0_ut)) {
		return false;
	}
	return read_ptr_pa (bf, paddr, out);
}

static char *readstr(RBinFile *bf, mach0_ut p, ut32 *offset, ut32 *left) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	char *name = NULL;
	if (offset && left) {
		const mach0_ut paddr = va2pa (bf, p, offset, left);
		if (paddr == 0 || *left <= 1) {
			return NULL;
		}

		const int name_len = R_MIN (MAX_CLASS_NAME_LEN, *left);
		name = calloc (1, name_len + 1);
		int len = r_buf_read_at (bf->buf, paddr, (ut8 *)name, name_len);
		if (len < name_len) {
			R_FREE (name);
			return NULL;
		}
	} else {
		const size_t name_len = MAX_CLASS_NAME_LEN;
		name = calloc (1, name_len + 1);
		int len = r_buf_read_at (bf->buf, p, (ut8 *)name, name_len);
		if (len < 2) {
			R_FREE (name);
			return NULL;
		}
#if 0
		char *s = strdup (name);
		free (name);
		return s;
#endif
	}
	if ((ut8)name[0] == 0xff || !*name) {
		R_FREE (name);
		return NULL;
	}
	return name;
}
