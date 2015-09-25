/* radare - LGPL - Copyright 2015 - inisider */

#include "mach0_classes.h"

#define RO_META               (1<<0)

struct MACH0_(SMethodList) {
	ut32 entsize;
	ut32 count;
	/* SMethod first;  These structures follow inline */
};

struct MACH0_(SMethod) {
	mach0_ut name;		/* SEL (32/64-bit pointer) */
	mach0_ut types;		/* const char * (32/64-bit pointer) */
	mach0_ut imp;		/* IMP (32/64-bit pointer) */
};

struct MACH0_(SClass) {
	mach0_ut isa;			/* SClass* (32/64-bit pointer) */
	mach0_ut superclass;	/* SClass* (32/64-bit pointer) */
	mach0_ut cache;			/* Cache (32/64-bit pointer) */
	mach0_ut vtable;		/* IMP * (32/64-bit pointer) */
	mach0_ut data;			/* SClassRoT * (32/64-bit pointer) */
};

struct MACH0_(SClassRoT) {
	ut32 flags;
	ut32 instanceStart;
	ut32 instanceSize;
#ifdef R_BIN_MACH064
	ut32 reserved;
#endif
	mach0_ut ivarLayout;		/* const uint8_t* (32/64-bit pointer) */
	mach0_ut name;				/* const char* (32/64-bit pointer) */
	mach0_ut baseMethods;		/* const SMEthodList* (32/64-bit pointer) */
	mach0_ut baseProtocols; 	/* const SProtocolList* (32/64-bit pointer) */
	mach0_ut ivars;				/* const SIVarList* (32/64-bit pointer) */
	mach0_ut weakIvarLayout; 	/* const uint8_t * (32/64-bit pointer) */
	mach0_ut baseProperties; 	/* const SObjcPropertyList* (32/64-bit pointer) */
};

struct MACH0_(SProtocolList) {
	mach0_ut count;	/* uintptr_t (a 32/64-bit value) */
	/* SProtocol* list[0];  These pointers follow inline */
};

struct MACH0_(SProtocol) {
	mach0_ut isa;					/* id* (32/64-bit pointer) */
	mach0_ut name;					/* const char * (32/64-bit pointer) */
	mach0_ut protocols;				/* SProtocolList*
									(32/64-bit pointer) */
	mach0_ut instanceMethods;		/* SMethodList* (32/64-bit pointer) */
	mach0_ut classMethods;			/* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalInstanceMethods;	/* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalClassMethods;	/* SMethodList* (32/64-bit pointer) */
	mach0_ut instanceProperties;	/* struct SObjcPropertyList*
									(32/64-bit pointer) */
};

struct MACH0_(SIVarList) {
	ut32 entsize;
	ut32 count;
	/* SIVar first;  These structures follow inline */
};

struct MACH0_(SIVar) {
	mach0_ut offset;	/* uintptr_t * (32/64-bit pointer) */
	mach0_ut name;		/* const char * (32/64-bit pointer) */
	mach0_ut type;		/* const char * (32/64-bit pointer) */
	ut32 alignment;
	ut32 size;
};

struct MACH0_(SObjcProperty) {
	mach0_ut name;			/* const char * (32/64-bit pointer) */
	mach0_ut attributes;	/* const char * (32/64-bit pointer) */
};

struct MACH0_(SObjcPropertyList) {
	ut32 entsize;
	ut32 count;
	/* struct SObjcProperty first;  These structures follow inline */
};

///////////////////////////////////////////////////////////////////////////////
static mach0_ut get_pointer (mach0_ut p,
							ut32 *offset,
							ut32 *left,
							RBinFile *arch);

static void copy_sym_name_with_namespace (char *class_name, char *read_name, RBinSymbol *sym);

static void get_ivar_list_t (mach0_ut p, RBinFile *arch, RBinClass *processed_class);

static void get_objc_property_list (mach0_ut p, RBinFile *arch, RBinClass *processed_class);

static void get_method_list_t (mach0_ut p, RBinFile *arch, char *class_name, RBinClass *processed_class);

static void get_protocol_list_t (mach0_ut p, RBinFile *arch, RBinClass *processed_class);

static void get_class_ro_t (mach0_ut p, RBinFile *arch, ut32 *is_meta_class, RBinClass *processed_class);

static void get_class_t (mach0_ut p, RBinFile *arch, RBinClass *processed_class);

static void __r_bin_class_free(RBinClass *p);

static int is_thumb(RBinFile *arch) {
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
	if (bin->hdr.cputype == 12) {
		if (bin->hdr.cpusubtype == 9)
			return 1;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static mach0_ut get_pointer (mach0_ut p,
							ut32 *offset,
							ut32 *left,
							RBinFile *arch)
{
	mach0_ut r;
	mach0_ut addr;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;

	sctns = r_bin_plugin_mach.sections(arch);
	if (sctns == NULL) {
		// retain just for debug
		// eprintf ("there is no sections\n");
		return 0;
	}

	addr = p;
	r_list_foreach (sctns, iter, s) {
		if (addr >= s->vaddr && addr < s->vaddr + s->vsize) {
			if (offset != NULL) {
				*offset = addr - s->vaddr;
			}
			if (left != NULL) {
				*left = s->vsize - (addr - s->vaddr);
			}

			r = (s->paddr + (addr - s->vaddr));

			r_list_free (sctns);
			return r;
		}
	}

	if (offset != NULL) {
		*offset = 0;
	}
	if (left != NULL) {
		*left = 0;
	}

	r_list_free (sctns);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static void copy_sym_name_with_namespace (char *class_name,
										char *read_name,
										RBinSymbol *sym)
{
	size_t len = 0;
	char *tmp = 0;

	len = class_name ? strlen (class_name) : 0;
	memcpy (sym->classname, class_name,
		(len < R_BIN_SIZEOF_STRINGS) ?
		len : R_BIN_SIZEOF_STRINGS);

	tmp = r_str_newf ("%s", read_name); //class_name, read_name);
	if (tmp) {
		len = strlen (tmp);
		memcpy (sym->name, tmp,
			(len < R_BIN_SIZEOF_STRINGS) ?
			len : R_BIN_SIZEOF_STRINGS);
		r_str_free (tmp);
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_ivar_list_t (mach0_ut p,
							RBinFile *arch,
							RBinClass *processed_class)
{
	struct MACH0_(SIVarList) il;
	struct MACH0_(SIVar) i;
	mach0_ut r;
	ut32 offset, left, j;
	char *name;
	mach0_ut ivar_offset_p, ivar_offset;
	RBinField *field = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		eprintf("uncorrect RBinFile pointer\n");
		return;
	}

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0) {
		return;
	}

	memset (&il, '\0', sizeof (struct MACH0_(SIVarList)));

	if (left < sizeof (struct MACH0_(SIVarList))) {
		r_buf_read_at (arch->buf, r, (ut8 *)&il, left);
	} else {
		r_buf_read_at (arch->buf, r,
					(ut8 *)&il,
					sizeof (struct MACH0_(SIVarList)));
	}

	p += sizeof (struct MACH0_(SIVarList));
	offset += sizeof (struct MACH0_(SIVarList));
	for (j = 0; j < il.count; j++){
		r = get_pointer (p, &offset, &left, arch);
		if (r == 0) {
			return;
		}

		if (!(field = R_NEW0 (RBinField))) {
			// retain just for debug
			// eprintf ("RBinField allocation error\n");
			return;
		}

		memset (&i, '\0', sizeof (struct MACH0_(SIVar)));
		if (left < sizeof (struct MACH0_(SIVar))) {
			r_buf_read_at (arch->buf, r, (ut8 *)&i, left);
		}
		else {
			r_buf_read_at (arch->buf, r,
						(ut8 *)&i,
						sizeof (struct MACH0_(SIVar)));
		}

		ivar_offset_p = get_pointer (i.offset, NULL, &left, arch);
		if (ivar_offset_p != 0 && left >= sizeof (mach0_ut)) {
			r_buf_read_at (arch->buf,
						ivar_offset_p,
						(ut8 *)&ivar_offset,
						sizeof (ivar_offset));
			field->vaddr = ivar_offset;
		}

		r = get_pointer (i.name, NULL, &left, arch);
		if (r != 0) {
			char *tmp = NULL;
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}
			tmp = r_str_newf ("%s::%s%s", processed_class->name,
					"(ivar)", name);
			strncpy (field->name, tmp, sizeof (field->name)-1);
			field->name[sizeof(field->name)-1] = 0;
			R_FREE (tmp);
			R_FREE (name);
		}

		r = get_pointer (i.type, NULL, &left, arch);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			R_FREE (name);
		}

		r_list_append (processed_class->fields, field);

		p += sizeof (struct MACH0_(SIVar));
		offset += sizeof (struct MACH0_(SIVar));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_objc_property_list (mach0_ut p,
									RBinFile *arch,
									RBinClass *processed_class)
{
	struct MACH0_(SObjcPropertyList) opl;
	struct MACH0_(SObjcProperty) op;
	mach0_ut r;
	ut32 offset, left, j;
	char *name;
	RBinField *property = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		eprintf("uncorrect RBinFile pointer\n");
		return;
	}

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0) {
		return;
	}

	memset (&opl, '\0', sizeof (struct MACH0_(SObjcPropertyList)));
	if (left < sizeof (struct MACH0_(SObjcPropertyList))){
		r_buf_read_at (arch->buf, r, (ut8 *)&opl, left);
	}
	else {
		r_buf_read_at (arch->buf,
					r,
					(ut8 *)&opl,
					sizeof (struct MACH0_(SObjcPropertyList)));
	}

	p += sizeof (struct MACH0_(SObjcPropertyList));
	offset += sizeof (struct MACH0_(SObjcPropertyList));
	for (j = 0; j < opl.count; j++){
		r = get_pointer (p, &offset, &left, arch);
		if (r == 0)
			return;

		if (!(property = R_NEW0 (RBinField))) {
			// retain just for debug
			// eprintf("RBinClass allocation error\n");
			return;
		}

		memset (&op, '\0', sizeof (struct MACH0_(SObjcProperty)));
		if (left < sizeof (struct MACH0_(SObjcProperty))){
			r_buf_read_at (arch->buf, r, (ut8 *)&op, left);
		} else {
			r_buf_read_at (arch->buf,
						r,
						(ut8 *)&op,
						sizeof (struct MACH0_(SObjcProperty)));
		}

		r = get_pointer (op.name, NULL, &left, arch);
		if (r != 0) {
			char *tmp = NULL;
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			tmp = r_str_newf ("%s::%s%s",
							processed_class->name,
							"(property)",
							name);

			strncpy (property->name, tmp, sizeof (property->name)-1);

			R_FREE (tmp);
			R_FREE (name);
		}

		r = get_pointer (op.attributes, NULL, &left, arch);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			R_FREE (name);
		}

		r_list_append (processed_class->fields, property);

		p += sizeof (struct MACH0_(SObjcProperty));
		offset += sizeof (struct MACH0_(SObjcProperty));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_list_t (mach0_ut p,
							RBinFile *arch,
							char *class_name,
							RBinClass *processed_class)
{
	struct MACH0_(SMethodList) ml;
	struct MACH0_(SMethod) m;
	mach0_ut r;
	ut32 offset, left, i;
	char *name = NULL;

	RBinSymbol *method = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		eprintf("uncorrect RBinFile pointer\n");
		return;
	}

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0)
		return;
	memset (&ml, '\0', sizeof (struct MACH0_(SMethodList)));
	if (left < sizeof (struct MACH0_(SMethodList))){
		r_buf_read_at (arch->buf, r, (ut8 *)&ml, left);
	}
	else {
		r_buf_read_at (arch->buf,
					r,
					(ut8 *)&ml,
					sizeof (struct MACH0_(SMethodList)));
	}

	p += sizeof (struct MACH0_(SMethodList));
	offset += sizeof (struct MACH0_(SMethodList));
	for (i = 0; i < ml.count; i++) {
		r = get_pointer (p, &offset, &left, arch);
		if (r == 0) {
			return;
		}

		if (!(method = R_NEW0 (RBinSymbol))) {
			// retain just for debug
			// eprintf ("RBinClass allocation error\n");
			return;
		}

		memset (&m, '\0', sizeof (struct MACH0_(SMethod)));
		if (left < sizeof (struct MACH0_(SMethod))){
			r_buf_read_at (arch->buf, r, (ut8 *)&ml, left);
		} else {
			r_buf_read_at (arch->buf, r, (ut8 *)&m,
				sizeof (struct MACH0_(SMethod)));
		}

		r = get_pointer (m.name, NULL, &left, arch);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			copy_sym_name_with_namespace (class_name, name, method);

			R_FREE (name);
		}

		r = get_pointer (m.types, NULL, &left, arch);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			R_FREE (name);
		}

		method->vaddr = m.imp;

		if (is_thumb (arch)) {
			if (method->vaddr & 1) {
				method->vaddr >>= 1;
				method->vaddr <<= 1;
				//eprintf ("0x%08llx METHOD %s\n", method->vaddr, method->name);
			}
		}

		r_list_append (processed_class->methods, method);

		p += sizeof (struct MACH0_(SMethod));
		offset += sizeof (struct MACH0_(SMethod));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_protocol_list_t (mach0_ut p, RBinFile *arch, RBinClass *processed_class) {
	struct MACH0_(SProtocolList) pl;
	mach0_ut q;
	struct MACH0_(SProtocol) pc;
	mach0_ut r;
	ut32 offset, left, i;
	char *class_name = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		eprintf("uncorrect RBinFile pointer\n");
		return;
	}

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0) {
		return;
	}
	memset (&pl, '\0', sizeof (struct MACH0_(SProtocolList)));
	if (left < sizeof (struct MACH0_(SProtocolList))){
		r_buf_read_at (arch->buf, r, (ut8 *)&pl, left);
	}
	else {
		r_buf_read_at (arch->buf, r,
					(ut8 *)&pl,
					sizeof (struct MACH0_(SProtocolList)));
	}

	p += sizeof (struct MACH0_(SProtocolList));
	offset += sizeof (struct MACH0_(SProtocolList));
	for (i = 0; i < pl.count; i++){
		r = get_pointer (p, &offset, &left, arch);
		if (r == 0)
			return;

		q = 0;
		if (left < sizeof (ut32)){
			r_buf_read_at (arch->buf, r, (ut8 *)&q, left);
		}
		else {
			r_buf_read_at (arch->buf, r, (ut8 *)&q, sizeof (mach0_ut));
		}

		r = get_pointer (q, &offset, &left, arch);
		if (r == 0) {
			return;
		}
		memset (&pc, '\0', sizeof (struct MACH0_(SProtocol)));
		if (left < sizeof (struct MACH0_(SProtocol))){
			r_buf_read_at (arch->buf, r, (ut8 *)&pc, left);
		}
		else {
			r_buf_read_at (arch->buf, r,
						(ut8 *)&pc,
						sizeof (struct MACH0_(SProtocol)));
		}

		r = get_pointer (pc.name, NULL, &left, arch);
		if (r != 0) {
			char *name = NULL;
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				r_buf_read_at (arch->buf, r, (ut8 *)name, left);
			}

			class_name = r_str_newf ("%s::%s%s",
									processed_class->name,
									"(protocol)",
									name);

			R_FREE(name);
		}

		if (pc.instanceMethods != 0) {
			get_method_list_t (pc.instanceMethods,
							arch, class_name,
							processed_class);
		}

		if (pc.classMethods != 0) {
			get_method_list_t (pc.classMethods,
							arch,
							class_name,
							processed_class);
		}

		R_FREE (class_name);

		p += sizeof (ut32);
		offset += sizeof (ut32);
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_ro_t (mach0_ut p,
							RBinFile *arch,
							ut32 *is_meta_class,
							RBinClass *processed_class)
{
	struct MACH0_(SClassRoT) cro;
	ut64 r;
	ut32 offset, left;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		eprintf("uncorrect RBinFile pointer\n");
		return;
	}

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0)
		return;
	memset (&cro, '\0', sizeof (struct MACH0_(SClassRoT)));
	if(left < sizeof (struct MACH0_(SClassRoT))){
		r_buf_read_at (arch->buf, r, (ut8 *)&cro, left);
	}
	else {
		r_buf_read_at (arch->buf, r,
					(ut8 *)&cro,
					sizeof (struct MACH0_(SClassRoT)));
	}

	r = get_pointer (cro.name, NULL, &left, arch);
	if (r != 0) {
		struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) arch->o->bin_obj;
		int is_crypted = bin->has_crypto;

		if (is_crypted == 1) {
			processed_class->name = strdup ("some_encrypted_data");
			left = strlen (processed_class->name) + 1;
		} else {
			processed_class->name = malloc (left);
			r_buf_read_at (arch->buf, r, (ut8 *)processed_class->name, left);
		}
	}

	if (cro.baseMethods != 0) {
		get_method_list_t (cro.baseMethods,
						arch,
						processed_class->name,
						processed_class);
	}

	if (cro.baseProtocols != 0) {
		get_protocol_list_t (cro.baseProtocols,
							arch,
							processed_class);
	}

	if (cro.ivars != 0) {
		get_ivar_list_t (cro.ivars,
						arch,
						processed_class);
	}

	if (cro.baseProperties != 0) {
		get_objc_property_list (cro.baseProperties,
								arch,
								processed_class);
	}

	if (is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) ? 1 : 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_t (mach0_ut p,
						RBinFile *arch,
						RBinClass *processed_class)
{
	struct MACH0_(SClass) c;
	mach0_ut r = 0;
	ut32 offset = 0, left = 0;
	ut32 is_meta_class = 0;

	r = get_pointer (p, &offset, &left, arch);
	if (r == 0) {
		return;
	}
	memset (&c, '\0', sizeof (struct MACH0_(SClass)));

	if (left < sizeof (struct MACH0_(SClass))) {
		r_buf_read_at (arch->buf, r, (ut8 *)&c, left);
	} else {
		r_buf_read_at (arch->buf,
					r,
					(ut8 *)&c,
					sizeof (struct MACH0_(SClass)));
	}

	processed_class->addr = c.isa;
	get_class_ro_t ((c.data) & ~0x3,
					arch,
					&is_meta_class,
					processed_class);
}

///////////////////////////////////////////////////////////////////////////////
static void __r_bin_class_free (RBinClass *p) {
	RListIter *iter = NULL;
	RBinSymbol *symbol = NULL;
	RBinField *field = NULL;

	if (!p) {
		return;
	}

	r_list_foreach (p->methods, iter, symbol) {
		R_FREE (symbol);
	}

	r_list_foreach (p->fields, iter, field) {
		R_FREE (field);
	}

	r_list_free (p->methods);
	r_list_free (p->fields);
	r_bin_class_free (p);
}

RList* MACH0_(parse_classes)(RBinFile *arch)
{
	RList/*<RBinClass>*/ *ret = NULL;

	RBinClass *processed_class = NULL;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;
	ut32 i = 0, size = 0;
	mach0_ut p = 0;
	ut32 left = 0;
	ut8 is_found = 0;

	ut64 num_of_unnamed_class = 0;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;

	// searching of section with name __objc_classlist
	sctns = r_bin_plugin_mach.sections (arch);
	if (sctns == NULL) {
		// retain just for debug
		// eprintf ("there is no sections\n");
		return NULL;
	}

	r_list_foreach (sctns, iter, s) {
		if (strstr (s->name, "__objc_classlist") != NULL) {
			is_found = 1;
			break;
		}
	}

	if (!is_found) {
		// retain just for debug
		// eprintf ("there is no section __objc_classlist\n");
		goto get_classes_error;
	}
	// end of seaching of section with name __objc_classlist

	if (!(ret = r_list_new ())) {
		// retain just for debug
		// eprintf ("RList<RBinClass> allocation error\n");
		goto get_classes_error;
	}

	ret->free = (RListFree) __r_bin_class_free;

	// start of getting information about each class in file
	for (i = 0; i < s->size; i+= sizeof (mach0_ut)) {
		if (!(processed_class = R_NEW0 (RBinClass))) {
			// retain just for debug
			// eprintf ("RBinClass allocation error\n");
			goto get_classes_error;
		}

		if (!(processed_class->methods = r_list_new())) {
			// retain just for debug
			// eprintf ("RList<RBinField> allocation error\n");
			goto get_classes_error;
		}

		if (!(processed_class->fields = r_list_new())) {
			// retain just for debug
			// eprintf ("RList<RBinSymbol> allocation error\n");
			goto get_classes_error;
		}

		p = 0;

		left = s->size - i;
		size = left < sizeof (mach0_ut) ? left : sizeof (mach0_ut);

		r_buf_read_at (arch->buf,
					s->paddr + i,
					(ut8 *)&p,
					size);

		get_class_t (p, arch, processed_class);

		if (!processed_class->name) {
			processed_class->name = r_str_newf (
				"UnnamedClass%"PFMT64d,
				num_of_unnamed_class);
			if (!processed_class->name) {
				goto get_classes_error;
			}

			num_of_unnamed_class++;
		}

		r_list_append (ret, processed_class);
	}

	r_list_free (sctns);

	return ret;

get_classes_error:
	r_list_free (sctns);
	r_list_free (ret);
	if (processed_class) {
		r_list_free (processed_class->fields);
		r_list_free (processed_class->methods);
	}
	__r_bin_class_free (processed_class);

	return NULL;
}
