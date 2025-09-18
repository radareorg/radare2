/* radare - LGPL - Copyright 2015-2025 - inisider, pancake */

#define R_LOG_ORIGIN "bin"

#include "../../i/private.h"
#include "mach0_classes.h"

#define RO_META (1 << 0)
// should be aligned to R_FLAG_NAME_SIZE i guess
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
	ut64 size;
	ut8 *data;
} MetaSection;

typedef struct {
	// swift
	MetaSection types;
	MetaSection fieldmd;
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
	const RVector *sections = MACH0_(load_sections) (bf->bo->bin_obj);
	if (sections) {
		struct section_t *section;
		r_vector_foreach (sections, section) {
			PARSECTION (&ms.clslist, "__objc_classlist");
			PARSECTION (&ms.catlist, "__objc_catlist");
			PARSECTION (&ms.types, "swift5_types");
			PARSECTION (&ms.fieldmd, "swift5_fieldmd");
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

static int sort_by_offset(const void *_a , const void *_b) {
	const RBinField *a = (const RBinField*)_a;
	const RBinField *b = (const RBinField*)_b;
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
		field = R_NEW0 (RBinField);
		if (!field) {
			break;
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
			// XXX the field name shouldnt contain the class name
			// field->realname = r_str_newf ("%s::%s%s", klass->name, "(ivar)", name);
			// field->name = r_str_newf ("%s::%s%s", klass->name, "(ivar)", name);
			field->name = r_bin_name_new (name);
			// r_bin_name_demangled (field->name, simplifiedNameGoesHere);
			free (name);
		} else {
			R_LOG_WARN ("not parsing ivars, wrong va2pa");
		}

		r = va2pa (bf, i.type, NULL, &left);
		if (r) {
			if (r + left < r) {
				goto error;
			}
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			char *type = NULL;
			if (mo->has_crypto) {
				type = strdup ("some_encrypted_data");
			// 	left = strlen (name) + 1;
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
				type = NULL;
			} else {
				r_bin_name_free (field->type);
				field->type = NULL;
			}
			if (field->name) {
				field->kind = R_BIN_FIELD_KIND_VARIABLE;
				r_list_append (klass->fields, field);
				field = NULL;
			} else {
				R_LOG_WARN ("field name is empty");
			}
		} else {
			R_LOG_DEBUG ("va2pa error");
			goto error;
		}
		p += sizeof (struct MACH0_(SIVar));
		offset += sizeof (struct MACH0_(SIVar));
	}
	r_list_sort (klass->fields, sort_by_offset);
	RBinField *isa = R_NEW0 (RBinField);
	if (isa) {
		isa->name = r_bin_name_new ("isa");
		isa->size = sizeof (mach0_ut);
		isa->type = r_bin_name_new ("struct objc_class *");
		// TODO r_bin_name_demangled (isa->type, "ObjC.Class*");
		isa->kind = R_BIN_FIELD_KIND_VARIABLE;
		isa->vaddr = 0;
		isa->offset = 0;
		r_list_prepend (klass->fields, isa);
	}
	return;
error:
	r_bin_field_free (field);
}

static void get_objc_property_list(RBinFile *bf, RBinClass *klass, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->info && klass);
	struct MACH0_(SObjcPropertyList) opl;
	struct MACH0_(SObjcProperty) op;
	mach0_ut r;
	ut32 offset, left, j;
	char *name = NULL;
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

		if (!(property = R_NEW0 (RBinField))) {
			// retain just for debug
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
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			if (r + left < r) {
				goto error;
			}
			if (bin->has_crypto) {
				// TODO: better + shorter name
				const char k[] = "some_encrypted_data";
				property->name = r_bin_name_new (k);
				left = strlen (k) + 1;
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
			// property->name = r_str_newf ("%s::%s%s", klass->name, "(property)", name);
			name = NULL;
			property->kind = R_BIN_FIELD_KIND_PROPERTY;
			property->offset = j;
			property->paddr = r;
		}
#if 0
		r = va2pa (bf, op.attributes, NULL, &left);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) bf->bo->bin_obj;
			int is_crypted = bin->has_crypto;

			if (r > bf->size || r + left > bf->size) goto error;
			if (r + left < r) goto error;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				len = r_buf_read_at (bf->buf, r, (ut8 *)name, left);
				if (len == 0 || len == -1) goto error;
			}

			R_FREE (name);
		}
#endif
		if (property->name) {
			r_list_append (klass->fields, property);
		} else {
			free (property);
		}

		p += sizeof (struct MACH0_(SObjcProperty));
		offset += sizeof (struct MACH0_(SObjcProperty));
	}
	return;
error:
	R_FREE (property);
	R_FREE (name);
	return;
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
	ut32 offset, left, i;
	char *name = NULL;
	char *rtype = NULL;
	int len;
	struct MACH0_(SMethodList) ml = {0};
	ut8 sml[sizeof (struct MACH0_(SMethodList))] = {0};
	ut8 sm[sizeof (struct MACH0_(SMethod))] = {0};

	const bool bigendian = bf->bo->info->big_endian;
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
		if (!method) {
			// retain just for debug
			return;
		}
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
			if (class_name) { // XXX to save memory we can just ref the RBinName instance from the class
				method->classname = strdup (class_name);
			} else {
				R_LOG_ERROR ("Invalid class name for method. Avoid parsing invalid data");
				goto error;
			}
			method->name = r_bin_name_new (name);
			R_FREE (name);
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
					free (rtype);
					goto error;
				}
				rtype[left] = 0;
			}
			method->rtype = strdup (rtype);
			R_FREE (rtype);
		}
		method->lang = R_BIN_LANG_OBJC;
		method->vaddr = m.imp;
		if (!method->vaddr) {
			R_FREE (method);
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
		r_list_append (klass->methods, method);
next:
		p += read_size;
		offset += read_size;
	}
	return;
error:
	R_FREE (method);
	R_FREE (name);
	return;
}

static void get_protocol_list(RBinFile *bf, RBinClass *klass, objc_cache_opt_info *oi, mach0_ut p) {
	R_RETURN_IF_FAIL (bf && klass && bf->bo && bf->bo->info && bf->bo->bin_obj);
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
		if (left < sizeof (ut32)) {
			if (r_buf_read_at (bf->buf, r, sptr, left) != left) {
				return;
			}
		} else {
			len = r_buf_read_at (bf->buf, r, sptr, sizeof (mach0_ut));
			if (len != sizeof (mach0_ut)) {
				return;
			}
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
		p += sizeof (ut32);
		offset += sizeof (ut32);
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

#if 0
static inline const char *skipnum(const char *s) {
	while (isdigit (*s)) {
		s++;
	}
	return s;
}
#endif

static char *demangle_classname(RBin *rbin, const char *s) {
	char *ret;
	if (r_str_startswith (s, "_TtC")) {
		ret = r_bin_demangle_swift (s, rbin->options.demangle_usecmd, rbin->options.demangle_trylib);
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
			klass->name = r_bin_name_new (name);
			char *dn = demangle_classname (bf->rbin, name);
			if (dn) {
				r_bin_name_demangled (klass->name, dn);
				free (dn);
			}
		}
		//eprintf ("0x%x  %s\n", s, klass->name);
		const char *klass_name = r_bin_name_tostring2 (klass->name, 'o');
		char *k = r_str_newf ("objc_class_%s.offset", klass_name);
		sdb_num_set (bin->kv, k, s, 0);
		free (k);
	}
#ifdef R_BIN_MACH064
	sdb_set (bin->kv, "objc_class.format", "lllll isa super cache vtable data", 0);
#else
	sdb_set (bin->kv, "objc_class.format", "xxxxx isa super cache vtable data", 0);
#endif

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
	RBin *bin = bf->rbin;
	bool trylib = bin? bin->options.demangle_trylib: false;
	bool usecmd = bin? bin->options.demangle_usecmd: false;
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
			char *dn = demangle_classname (bf->rbin, klass_name);
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
					char *dsuper = r_bin_demangle_swift (target_class_name, usecmd, trylib);
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
	if (!is_meta_class && !dupe) {
		mach0_ut isa_n_value = get_isa_value ();
		ut64 tmp = klass->addr;
		MACH0_(get_class_t) (bf, klass, c.isa + isa_n_value, true, relocs, oi);
		klass->addr = tmp;
	}
}

enum {
	NCD_FLAGS = 0,
	NCD_PARENT = 1,
	NCD_NAME = 2,
	NCD_ACCESSFCNPTR = 3,
	NCD_FIELDS = 4,
	NCD_SUPER = 5,
	NCD_MEMBERS = 8,
	NCD_NFIELDS = 9,
	NCD_OFIELDS = 10
};

typedef struct {
	bool valid;
	ut64 name_addr;
	ut64 super_addr;
	ut64 addr;
	ut64 fields;
	ut64 members;
	ut64 members_count;
	// internal //
	MetaSection fieldmd;
	st32 *fieldmd_data;
} SwiftType;

static SwiftType parse_type_entry(RBinFile *bf, ut64 typeaddr) {
	SwiftType st = {0};
	ut32 words[16] = {0};
	st32 *swords = (st32*)&words;
	if (r_buf_read_at (bf->buf, typeaddr, (ut8*)&words, sizeof (words)) < 1) {
		R_LOG_DEBUG ("Invalid pointers");
		return st;
	}
#if 0
// struct NominalClassDescriptor
ut32 flags
st32 parent
st32 name
st32 accessfcnptr
st32 fields
st32 superklass
ut32 ign;
ut32 ign;
ut32 members_count;
ut32 fields_count;
ut32 fields_offset;
#endif
#define NCD(x) (typeaddr + (x * 4) + swords[x])
#if 0
	eprintf ("0x%08"PFMT64x " swift_type_entry:\n", typeaddr);
	eprintf ("  flags:   0x%08x\n", words[0]);
	eprintf ("  parent:  0x%08"PFMT64x"\n", NCD (NCD_PARENT));
#endif
	st.name_addr = NCD (NCD_NAME);
	st.super_addr = NCD (NCD_SUPER);
#if 0
	char *typename = readstr (bf, typename_addr);
	eprintf ("  name:    0x%08"PFMT64x" (%s)\n", typename_addr, typename);
	eprintf ("  access:  0x%08"PFMT64x"\n", bf->bo->baddr + NCD (NCD_ACCESSFCNPTR));
	eprintf ("  fields:  0x%08"PFMT64x"\n", NCD (NCD_FIELDS));
	eprintf ("  super:   0x%08"PFMT64x"\n", NCD (NCD_SUPER));
	eprintf ("  members: 0x%08"PFMT64x"\n", NCD (NCD_MEMBERS));
	eprintf ("  fields:  0x%08"PFMT64x"\n", NCD (NCD_NFIELDS));
	eprintf ("  fieldsat:0x%08"PFMT64x"\n", NCD (NCD_OFIELDS));

	char * tn = r_name_filter_dup (typename);
	r_cons_printf ("f sym.swift.%s.init = 0x%08"PFMT64x"\n",
		tn, bf->bo->baddr + NCD (NCD_ACCESSFCNPTR));
	free (tn);
	free (typename);
#endif
	st.valid = true;
	st.fields = NCD (NCD_FIELDS);
	st.members = NCD (NCD_MEMBERS);
	st.members_count = NCD (NCD_MEMBERS);
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

static void parse_type(RBinFile *bf, RList *list, SwiftType st, HtUP *symbols_ht) {
	char *otypename = readstr (bf, st.name_addr, NULL, NULL);
	if (R_STR_ISEMPTY (otypename)) {
		R_LOG_DEBUG ("swift-type-parse missing name");
		return;
	}
	RBin *bin = bf->rbin;
	bool trylib = bin? bin->options.demangle_trylib: false;
	bool usecmd = bin? bin->options.demangle_usecmd: false;
	char *typename = r_name_filter_dup (otypename);
	RBinClass *klass = r_bin_class_new (typename, NULL, false);
	char *super_name = readstr (bf, st.super_addr, NULL, NULL);
	if (super_name) {
		if (*super_name > 5) {
			klass->super = r_list_newf ((void *)r_bin_name_free);
			RBinName *bn = r_bin_name_new (super_name);
			char *sname = r_bin_demangle_swift (super_name, usecmd, trylib);
			if (R_STR_ISNOTEMPTY (sname)) {
				r_bin_name_demangled (bn, sname);
			}
			r_list_append (klass->super, bn);
		}
		free (super_name);
	}
	klass->addr = st.addr;
	klass->lang = R_BIN_LANG_SWIFT;
	if (st.members != UT64_MAX) {
		ut8 buf[MAX_SWIFT_MEMBERS * 16];
		int i = 0;
		R_LOG_DEBUG ("parse_type.st.members 0x%08"PFMT64x, st.members);
		if ((int)st.members < 1 || st.members > bf->size) {
			R_LOG_DEBUG ("out of bounds");
		}
		int res = r_buf_read_at (bf->buf, st.members, buf, sizeof (buf));
		if (res != sizeof (buf)) {
			R_LOG_DEBUG ("Partial read on st.members");
		}
		ut32 count = R_MIN (MAX_SWIFT_MEMBERS, r_read_le32 (buf + 3));
		for (i = 0; i < count; i++) {
			int pos = (i * 8) + 3 + 8 + 8;
			st32 n = r_read_le32 (buf + pos);
			ut64 method_addr = st.members + pos + n;
			if (method_addr > r_buf_size (bf->buf)) {
				break;
			}
			method_addr += bf->bo->baddr;
			RBinSymbol *sym = NULL;
			char *method_name;
			char *rawname = NULL;
			if (symbols_ht && (sym = ht_up_find (symbols_ht, method_addr, NULL))) {
				rawname = strdup (r_bin_name_tostring (sym->name));
				method_name = r_name_filter_dup (rawname); // r_bin_name_tostring (sym->name));
				r_bin_name_filtered (sym->name, method_name);
				char *dname = r_bin_demangle_swift (method_name, usecmd, trylib);
				if (dname) {
					r_bin_name_demangled (sym->name, dname);
					free (sym->name->oname);
					sym->name->oname = strdup (rawname);
					free (method_name);
					method_name = dname;
				}
			} else {
				method_name = r_str_newf ("%d", i);
			}
			// skip namespace
			char *dot = strchr (method_name, '.');
			if (dot) {
				// skip classname
				dot = strchr (dot + 1, '.');
				if (dot) {
					char *p = method_name;
					method_name = strdup (dot + 1);
					free (p);
				}
			}
			if (rawname) {
				sym = r_bin_symbol_new (rawname, method_addr, method_addr);
				r_bin_name_demangled (sym->name, method_name);
			} else {
				sym = r_bin_symbol_new (method_name, method_addr, method_addr);
			}
#if 0
			if (oname) {
				r_bin_name_free (sym->name);
				sym->name = r_bin_name_clone (oname);
			}
#endif
			sym->lang = R_BIN_LANG_SWIFT;
			r_list_append (klass->methods, sym);
#if 0
			// TODO. try to resolve the method name by symbol table or debug info
			r_cons_printf ("f sym.swift.%s.method.%s = 0x%" PFMT64x"\n", typename, method_name, method_addr);
#endif
			free (method_name);
		}
	}
	klass->index = r_list_length (bf->bo->classes) + r_list_length (list);
	r_list_append (list, klass);

	if (st.fields != UT64_MAX) {
		int i;
		size_t dmax = st.fieldmd.size / 4;
		for (i = 0; i < 128; i += 3) {
			const int j = (st.fields - st.fieldmd.addr) / 4;
			const int d = 6 + j + i;
			if (d >= dmax) {
				break;
			}
			RBinField *field = R_NEW0 (RBinField);
			if (!field) {
				break;
			}
			ut64 field_name_addr = st.fieldmd.addr + (d * 4) + st.fieldmd_data[d];
			ut64 field_type_addr = st.fieldmd.addr + (d * 4) + st.fieldmd_data[d - 1] - 4;
			ut64 field_method_addr = field_name_addr;
#if 0
			if (field_method_addr & 1) {
				// unaligned aka invalid
				break;
			}
#endif
			ut64 vaddr = r_bin_file_get_baddr (bf) + field_method_addr;
			char *field_name = readstr (bf, field_name_addr, NULL, NULL);
			if (R_STR_ISEMPTY (field_name)) {
				free (field);
				break;
			}

			char *field_type = readstr (bf, field_type_addr, NULL, NULL);
			if (field_type) {
				const char *ftype = field_type;
				if (*ftype < 6) {
					// basic type
					ftype += r_str_nlen (ftype, 6);
				}
				const char *mangled_type = ftype;
				if (!field->type) {
					field->type = r_bin_name_new (mangled_type);
					char *demangled_type = r_bin_demangle_swift (mangled_type, usecmd, trylib);
					if (demangled_type) {
						r_bin_name_demangled (field->type, demangled_type);
						free (demangled_type);
					}
				}
				free (field_type);
			}
			field->name = r_bin_name_new (field_name);
			char *fname = r_name_filter_dup (field_name);
			r_bin_name_filtered (field->name, fname);
			free (fname);

			field->paddr = field_method_addr;
			field->vaddr = vaddr;
#if 0
			r_cons_printf ("f sym.swift.%s.field.%s = 0x%08"PFMT64x"\n",
				typename, field->name, bf->bo->baddr + field_method_addr);
#endif
			free (field_name);
			field->kind = R_BIN_FIELD_KIND_PROPERTY;
			r_list_append (klass->fields, field);
		}
	}
	free (typename);
	free (otypename);
}

static void *read_section(RBinFile *bf, MetaSection *ms, ut64 *asize) {
	if (ms->data) {
		return ms->data;
	}
	void *data = calloc (ms->size + 4, 1);
	if (data) {
		// align size and addr
		if (ms->addr % 4) {
			R_LOG_WARN ("Unaligned address for section");
		}
		*asize = ms->size + (ms->size % 4);
		if (r_buf_read_at (bf->buf, ms->addr, data, *asize) != *asize) {
			R_FREE (ms->data);
			return NULL;
		}
		free (ms->data);
		ms->data = data;
	}
	return data;
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

	const bool want_swift = !r_sys_getenv_asbool ("RABIN2_MACHO_NOSWIFT");
	// 2s / 16s
	if (want_swift && ms.types.have && ms.fieldmd.have) {
		ut64 asize = ms.fieldmd.size;
		st32 *fieldmd = read_section (bf, &ms.fieldmd, &asize);

		const int aligned_fieldmd_size = ms.fieldmd.size + (ms.fieldmd.size % 4);
		const int fieldmd_count = asize / 4;
		R_LOG_DEBUG ("swift5_fieldmd: pxd %d @ 0x%x", fieldmd_count, ms.fieldmd.addr);
		if (fieldmd) {
			ut64 atsize = ms.types.size;
			int aligned_types_count = atsize / 4;
			st32 *types = read_section (bf, &ms.types, &atsize);
			if (types) {
				if (limit > 0 && aligned_types_count > limit) {
					R_LOG_WARN ("swift class limit reached");
					aligned_types_count = limit;
				}
				HtUP *symbols_ht = _load_symbol_by_vaddr_hashtable (bf);
				ut32 i;
				for (i = 0; i < aligned_types_count; i++) {
					st32 word = r_read_le32 (&types[i]);
					ut64 type_address = ms.types.addr + (i * 4) + word;
					SwiftType st = parse_type_entry (bf, type_address);
					st.addr = type_address;
					st.fieldmd_data = fieldmd;
					st.fieldmd.addr = ms.fieldmd.addr;
					st.fieldmd.size = aligned_fieldmd_size;
					R_LOG_DEBUG ("Name address 0x%"PFMT64x" for 0x%"PFMT64x, st.name_addr, ms.fieldmd.addr);
					if (st.fields != UT64_MAX) {
						parse_type (bf, ret, st, symbols_ht);
					}
				}
				ht_up_free (symbols_ht);
			}
		}
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
	ut32 ordinal = 0;
	for (i = 0; i < ms.clslist.size; i += sizeof (mach0_ut)) {
		left = ms.clslist.size - i;
		if (limit > 0 && ordinal++ > limit) {
			R_LOG_WARN ("classes mo.limit reached");
			break;
		}
		if (left < sizeof (mach0_ut)) {
			R_LOG_ERROR ("Chopped classlist data");
			break;
		}
		RBinClass *klass = r_bin_class_new ("", "", R_BIN_ATTR_PUBLIC);
		R_FREE (klass->name); // allow NULL name in rbinclass?
		klass->lang = R_BIN_LANG_OBJC;
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
			if (strlen (klass_name) > 512) {
				R_LOG_INFO ("Invalid class name, probably corrupted binary");
				break;
			}
		} else {
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
	if (!ms->catlist.have) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree)r_bin_class_free);
	if (!ret || !relocs) {
		goto error;
	}

	ut32 i;
	for (i = 0; i < ms->catlist.size; i += ptr_size) {
		mach0_ut p;

		if ((ms->catlist.size - i) < ptr_size) {
			R_LOG_WARN ("Truncated catlist data");
			break;
		}
		RBinClass *klass = r_bin_class_new ("", NULL, 0);
		R_FREE (klass->name);
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
			char *demangled = demangle_classname (bf->rbin, target_class_name);
			if (demangled) {
				char *dname = r_str_newf ("%s(%s)", demangled, category_name);
				r_bin_name_demangled (klass->name, dname);
				free (dname);
				free (demangled);
			}
			free (kname);
		}
	}

	klass->addr = p;

	R_FREE (category_name);

	const char *klass_name = r_bin_name_tostring (klass->name);
	if (R_STR_ISEMPTY (klass_name)) {
		R_LOG_ERROR ("Invalid class name");
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
