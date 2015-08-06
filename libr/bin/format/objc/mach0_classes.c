#include "mach0_classes.h"

#define RO_META               (1<<0)

Mach0_struct_(SMethodList) {
	ut32 entsize;
	ut32 count;
	/* SMethod first;  These structures follow inline */
};

Mach0_struct_(SMethod) {
	mach0_ut name;	/* SEL (32/64-bit pointer) */
	mach0_ut types;	/* const char * (32/64-bit pointer) */
	mach0_ut imp;		/* IMP (32/64-bit pointer) */
};

Mach0_struct_(SClass) {
	mach0_ut isa;			/* SClass* (32/64-bit pointer) */
	mach0_ut superclass;	/* SClass* (32/64-bit pointer) */
	mach0_ut cache;		/* Cache (32/64-bit pointer) */
	mach0_ut vtable;		/* IMP * (32/64-bit pointer) */
	mach0_ut data;		/* SClassRoT * (32/64-bit pointer) */
};

Mach0_struct_(SClassRoT) {
	ut32 flags;
	ut32 instanceStart;
	ut32 instanceSize;
#ifdef R_MACH0_CLASS64
	ut32 reserved;
#endif
	mach0_ut ivarLayout;		/* const uint8_t* (32/64-bit pointer) */
	mach0_ut name;			/* const char* (32/64-bit pointer) */
	mach0_ut baseMethods; 	/* const SMEthodList* (32/64-bit pointer) */
	mach0_ut baseProtocols; 	/* const SProtocolList* (32/64-bit pointer) */
	mach0_ut ivars; 		/* const SIVarList* (32/64-bit pointer) */
	mach0_ut weakIvarLayout; 	/* const uint8_t * (32/64-bit pointer) */
	mach0_ut baseProperties; 	/* const SObjcPropertyList* (32/64-bit pointer) */
};

Mach0_struct_(SProtocolList) {
	mach0_ut count;	/* uintptr_t (a 32/64-bit value) */
	/* SProtocol* list[0];  These pointers follow inline */
};

Mach0_struct_(SProtocol) {
	mach0_ut isa;						/* id* (32/64-bit pointer) */
	mach0_ut name;					/* const char * (32/64-bit pointer) */
	mach0_ut protocols;				/* SProtocolList*
									(32/64-bit pointer) */
	mach0_ut instanceMethods;			/* SMethodList* (32/64-bit pointer) */
	mach0_ut classMethods;			/* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalInstanceMethods;	/* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalClassMethods;	/* SMethodList* (32/64-bit pointer) */
	mach0_ut instanceProperties;		/* struct SObjcPropertyList*
									(32/64-bit pointer) */
};

Mach0_struct_(SIVarList) {
	ut32 entsize;
	ut32 count;
	/* SIVar first;  These structures follow inline */
};

Mach0_struct_(SIVar) {
	mach0_ut offset;		/* uintptr_t * (32/64-bit pointer) */
	mach0_ut name;		/* const char * (32/64-bit pointer) */
	mach0_ut type;		/* const char * (32/64-bit pointer) */
	ut32 alignment;
	ut32 size;
};

Mach0_struct_(SObjcProperty) {
	mach0_ut name;		/* const char * (32/64-bit pointer) */
	mach0_ut attributes;	/* const char * (32/64-bit pointer) */
};

Mach0_struct_(SObjcPropertyList) {
	ut32 entsize;
	ut32 count;
	/* struct SObjcProperty first;  These structures follow inline */
};

///////////////////////////////////////////////////////////////////////////////
static mach0_ut Mach0_class_(get_pointer)(mach0_ut p, ut32 *offset, ut32 *left,
									RBinFile *arch);

static void Mach0_class_(copy_sym_name_with_namespace)(char *class_name,
													char *read_name,
													RBinSymbol *sym);

static void Mach0_class_(get_ivar_list_t)(mach0_ut p, RBinFile *arch,
										RBinClass *processed_class);

static void Mach0_class_(get_objc_property_list)(mach0_ut p, RBinFile *arch,
												RBinClass *processed_class);

static void Mach0_class_(get_method_list_t)(mach0_ut p, RBinFile *arch,
											char *class_name,
											RBinClass *processed_class);

static void Mach0_class_(get_protocol_list_t)(mach0_ut p, RBinFile *arch,
											RBinClass *processed_class);

static void Mach0_class_(get_class_ro_t)(mach0_ut p, RBinFile *arch,
										ut32 *is_meta_class,
										RBinClass *processed_class);

static void Mach0_class_(get_class_t)(mach0_ut p, RBinFile *arch,
									RBinClass *processed_class);

static void Mach0_class_(__r_bin_class_free)(RBinClass *p);

///////////////////////////////////////////////////////////////////////////////
static mach0_ut Mach0_class_(get_pointer)(mach0_ut p, ut32 *offset, ut32 *left,
							RBinFile *arch)
{
	mach0_ut r;
	mach0_ut addr;
	mach0_ut section_content_addr;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;

	sctns = r_bin_plugin_mach.sections(arch);
	if (sctns == NULL) {
		printf("there is no sections\n");
		return 0;
	}

	addr = p;
	r_list_foreach(sctns, iter, s) {
		if (addr >= s->vaddr && addr < s->vaddr + s->vsize) {
			if (offset != NULL) {
				*offset = addr - s->vaddr;
			}
			if (left != NULL) {
				*left = s->vsize - (addr - s->vaddr);
			}

			//		if(sections[i].protected == TRUE && sections[i].cstring == TRUE)
			//			r = "some string from a protected section";
			//		else
			//			r = sections[i].contents + (addr - sections[i].addr);
			//		return(r);
			//		}

			section_content_addr = (s->vaddr - r_bin_plugin_mach.baddr(arch));
			r = (section_content_addr + (addr - s->vaddr));

			return r;
		}
	}

	if(offset != NULL) {
		*offset = 0;
	}
	if(left != NULL) {
		*left = 0;
	}

	return (0);
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(copy_sym_name_with_namespace)(char *class_name,
													char *read_name,
													RBinSymbol *sym)
{
	size_t len = 0;
	char *tmp = 0;

	len = strlen(class_name);
	memcpy(sym->classname,
		   class_name,
		   (len < R_BIN_SIZEOF_STRINGS) ? len : R_BIN_SIZEOF_STRINGS);

	tmp = r_str_newf("%s::%s", class_name, read_name);
	len = strlen(tmp);
	memcpy(sym->name,
		   tmp,
		   (len < R_BIN_SIZEOF_STRINGS) ? len : R_BIN_SIZEOF_STRINGS);
	r_str_free(tmp);
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_ivar_list_t)(mach0_ut p, RBinFile *arch,
										RBinClass *processed_class)
{
	Mach0_struct_(SIVarList) il;
	Mach0_struct_(SIVar) i;
	mach0_ut r;
	ut32 offset, left, j;
	char *name;
	mach0_ut ivar_offset_p, ivar_offset;
	RBinField *field = NULL;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}
	memset(&il, '\0', sizeof(Mach0_struct_(SIVarList)));
	if(left < sizeof(Mach0_struct_(SIVarList))) {
		r_buf_read_at(arch->buf, r, (ut8 *)&il, left);
	} else {
		r_buf_read_at(arch->buf, r,
					(ut8 *)&il,
					sizeof(Mach0_struct_(SIVarList)));
	}

	p += sizeof(Mach0_struct_(SIVarList));
	offset += sizeof(Mach0_struct_(SIVarList));
	for(j = 0; j < il.count; j++){
		r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
		if(r == 0) {
			return;
		}

		if (!(field = R_NEW0 (RBinField))) {
			printf("RBinField allocation error\n");
			return;
		}

		memset(&i, '\0', sizeof(Mach0_struct_(SIVar)));
		if(left < sizeof(Mach0_struct_(SIVar))) {
			r_buf_read_at(arch->buf, r, (ut8 *)&i, left);
		}
		else {
			r_buf_read_at(arch->buf, r,
						(ut8 *)&i,
						sizeof(Mach0_struct_(SIVar)));
		}

		ivar_offset_p = Mach0_class_(get_pointer)(i.offset, NULL, &left, arch);
		if (ivar_offset_p != 0 && left >= sizeof(mach0_ut)) {
			r_buf_read_at(arch->buf, ivar_offset_p, (ut8 *)&ivar_offset, sizeof(ivar_offset));
			field->vaddr = ivar_offset;
		}

		r = Mach0_class_(get_pointer)(i.name, NULL, &left, arch);
		if(r != 0) {
			char *tmp = NULL;
			int len = 0;

			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);

			tmp = r_str_newf("%s::%s%s",
							 processed_class->name,
							 "(ivar)",
							 name);
			len = strlen(tmp);

			memcpy(field->name,
				   tmp,
				   (len < R_BIN_SIZEOF_STRINGS) ? len : R_BIN_SIZEOF_STRINGS);

			R_FREE(tmp);
			R_FREE(name);
		}

		r = Mach0_class_(get_pointer)(i.type, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			R_FREE(name);
		}

		r_list_append(processed_class->fields, field);

		p += sizeof(Mach0_struct_(SIVar));
		offset += sizeof(Mach0_struct_(SIVar));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_objc_property_list)(mach0_ut p, RBinFile *arch,
									 RBinClass *processed_class)
{
	Mach0_struct_(SObjcPropertyList) opl;
	Mach0_struct_(SObjcProperty) op;
	mach0_ut r;
	ut32 offset, left, j;
	char *name;
	RBinSymbol *property = NULL;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}

	memset(&opl, '\0', sizeof(Mach0_struct_(SObjcPropertyList)));
	if(left < sizeof(Mach0_struct_(SObjcPropertyList))){
		r_buf_read_at(arch->buf, r, (ut8 *)&opl, left);
	}
	else {
		r_buf_read_at(arch->buf, r,
					(ut8 *)&opl,
					sizeof(Mach0_struct_(SObjcPropertyList)));
	}

	p += sizeof(Mach0_struct_(SObjcPropertyList));
	offset += sizeof(Mach0_struct_(SObjcPropertyList));
	for(j = 0; j < opl.count; j++){
		r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
		if(r == 0)
			return;

		if (!(property = R_NEW0 (RBinSymbol))) {
			printf("RBinClass allocation error\n");
			return;
		}

		memset(&op, '\0', sizeof(Mach0_struct_(SObjcProperty)));
		if(left < sizeof(Mach0_struct_(SObjcProperty))){
			r_buf_read_at(arch->buf, r, (ut8 *)&op, left);
		} else {
			r_buf_read_at(arch->buf,
						r,
						(ut8 *)&op,
						sizeof(Mach0_struct_(SObjcProperty)));
		}

		r = Mach0_class_(get_pointer)(op.name, NULL, &left, arch);
		if(r != 0) {
			char *tmp = NULL;

			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			tmp = r_str_newf("%s%s", "(property)", name);

			Mach0_class_(copy_sym_name_with_namespace)(processed_class->name, tmp, property);

			R_FREE(tmp);
			R_FREE(name);
		}

		r = Mach0_class_(get_pointer)(op.attributes, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			free(name);
			name = 0;
		}

		r_list_append(processed_class->methods, property);

		p += sizeof(Mach0_struct_(SObjcProperty));
		offset += sizeof(Mach0_struct_(SObjcProperty));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_method_list_t)(mach0_ut p, RBinFile *arch,
											char *class_name,
											RBinClass *processed_class)
{
	Mach0_struct_(SMethodList) ml;
	Mach0_struct_(SMethod) m;
	mach0_ut r;
	ut32 offset, left, i;
	char *name = NULL;

	RBinSymbol *method = NULL;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if(r == 0)
		return;
	memset(&ml, '\0', sizeof(Mach0_struct_(SMethodList)));
	if(left < sizeof(Mach0_struct_(SMethodList))){
		r_buf_read_at(arch->buf, r, (ut8 *)&ml, left);
	}
	else {
		r_buf_read_at(arch->buf,
					r,
					(ut8 *)&ml,
					sizeof(Mach0_struct_(SMethodList)));
	}

	p += sizeof(Mach0_struct_(SMethodList));
	offset += sizeof(Mach0_struct_(SMethodList));
	for(i = 0; i < ml.count; i++) {
		r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
		if(r == 0) {
			return;
		}

		if (!(method = R_NEW0 (RBinSymbol))) {
			printf("RBinClass allocation error\n");
			return;
		}

		memset(&m, '\0', sizeof(Mach0_struct_(SMethod)));
		if(left < sizeof(Mach0_struct_(SMethod))){
			r_buf_read_at(arch->buf, r, (ut8 *)&ml, left);
		}
		else {
			r_buf_read_at(arch->buf,
						r,
						(ut8 *)&m,
						sizeof(Mach0_struct_(SMethod)));
		}

		r = Mach0_class_(get_pointer)(m.name, NULL, &left, arch);
		if (r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);

			Mach0_class_(copy_sym_name_with_namespace)(class_name, name, method);

			R_FREE(name);
		}
		r = Mach0_class_(get_pointer)(m.types, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			R_FREE(name);
		}

		method->vaddr = m.imp;

		r_list_append(processed_class->methods, method);

		p += sizeof(Mach0_struct_(SMethod));
		offset += sizeof(Mach0_struct_(SMethod));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_protocol_list_t)(mach0_ut p, RBinFile *arch,
											RBinClass *processed_class)
{
	Mach0_struct_(SProtocolList) pl;
	mach0_ut q;
	Mach0_struct_(SProtocol) pc;
	mach0_ut r;
	ut32 offset, left, i;
	char *class_name;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}
	memset(&pl, '\0', sizeof(Mach0_struct_(SProtocolList)));
	if(left < sizeof(Mach0_struct_(SProtocolList))){
		r_buf_read_at(arch->buf, r, (ut8 *)&pl, left);
	}
	else {
		r_buf_read_at(arch->buf, r,
					(ut8 *)&pl,
					sizeof(Mach0_struct_(SProtocolList)));
	}

	p += sizeof(Mach0_struct_(SProtocolList));
	offset += sizeof(Mach0_struct_(SProtocolList));
	for(i = 0; i < pl.count; i++){
		r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
		if(r == 0)
			return;

		q = 0;
		if(left < sizeof(ut32)){
			r_buf_read_at(arch->buf, r, (ut8 *)&q, left);
		}
		else {
			r_buf_read_at(arch->buf, r, (ut8 *)&q, sizeof(mach0_ut));
		}

		r = Mach0_class_(get_pointer)(q, &offset, &left, arch);
		if(r == 0) {
			return;
		}
		memset(&pc, '\0', sizeof(Mach0_struct_(SProtocol)));
		if(left < sizeof(Mach0_struct_(SProtocol))){
			r_buf_read_at(arch->buf, r, (ut8 *)&pc, left);
		}
		else {
			r_buf_read_at(arch->buf, r,
						(ut8 *)&pc,
						sizeof(Mach0_struct_(SProtocol)));
		}

		r = Mach0_class_(get_pointer)(pc.name, NULL, &left, arch);
		if(r != 0) {
			char *name = NULL;

			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);

			class_name = r_str_newf("%s::%s%s", processed_class->name,
									"(protocol)",
									name);

			R_FREE(name);
		}

		if(pc.instanceMethods != 0) {
			Mach0_class_(get_method_list_t)(pc.instanceMethods,
											arch, class_name,
											processed_class);
		}

		if(pc.classMethods != 0) {
			Mach0_class_(get_method_list_t)(pc.classMethods,
											arch, class_name,
											processed_class);
		}

		R_FREE(class_name);

		p += sizeof(ut32);
		offset += sizeof(ut32);
	}
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_class_ro_t)(mach0_ut p, RBinFile *arch,
										ut32 *is_meta_class,
										RBinClass *processed_class)
{
	Mach0_struct_(SClassRoT) cro;
	ut64 r;
	ut32 offset, left;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if(r == 0)
		return;
	memset(&cro, '\0', sizeof(Mach0_struct_(SClassRoT)));
	if(left < sizeof(Mach0_struct_(SClassRoT))){
		r_buf_read_at(arch->buf, r, (ut8 *)&cro, left);
	}
	else {
		r_buf_read_at(arch->buf, r,
					(ut8 *)&cro,
					sizeof(Mach0_struct_(SClassRoT)));
	}

	r = Mach0_class_(get_pointer)(cro.name, NULL, &left, arch);
	if(r != 0) {
		processed_class->name = malloc(left);
		r_buf_read_at(arch->buf, r, (ut8 *)processed_class->name, left);

//		R_FREE(name);
	}

	if(cro.baseMethods != 0) {
		Mach0_class_(get_method_list_t)(cro.baseMethods, arch,
										processed_class->name,
										processed_class);
	}

	if(cro.baseProtocols != 0) {
		Mach0_class_(get_protocol_list_t)(cro.baseProtocols,
										arch,
										processed_class);
	}

	if(cro.ivars != 0) {
		Mach0_class_(get_ivar_list_t)(cro.ivars,
									arch,
									processed_class);
	}

	if(cro.baseProperties != 0) {
		Mach0_class_(get_objc_property_list)(cro.baseProperties,
											arch,
											processed_class);
	}

	if(is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) ? 1 : 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(get_class_t)(mach0_ut p, RBinFile *arch,
									RBinClass *processed_class)
{
	Mach0_struct_(SClass) c;
	mach0_ut r;
	ut32 offset, left;
	ut32 is_meta_class = 0;

	r = Mach0_class_(get_pointer)(p, &offset, &left, arch);
	if (r == 0) {
		return;
	}
	memset(&c, '\0', sizeof(Mach0_struct_(SClass)));

	if (left < sizeof(Mach0_struct_(SClass))) {
		r_buf_read_at(arch->buf, r, (ut8 *)&c, left);
	} else {
		r_buf_read_at(arch->buf, r, (ut8 *)&c, sizeof(Mach0_struct_(SClass)));
	}

	processed_class->addr = c.isa;
	Mach0_class_(get_class_ro_t)((c.data) & ~0x3, arch,\
								&is_meta_class, processed_class);
}

///////////////////////////////////////////////////////////////////////////////
static void Mach0_class_(__r_bin_class_free)(RBinClass *p) {
	RListIter *iter = NULL;
	RBinSymbol *symbol = NULL;
	RBinField *field = NULL;

	r_list_foreach(p->methods, iter, symbol) {
		R_FREE(symbol);
	}

	r_list_foreach(p->fields, iter, field) {
		R_FREE(field);
	}

	r_list_free(p->methods);
	r_list_free(p->fields);
	r_bin_class_free (p);
}

RList* Mach0_class_(get_classes)(RBinFile *arch)
{
	RList/*<RBinClass>*/ *ret = NULL;

	RBinClass *processed_class = NULL;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;
	ut32 i = 0, size = sizeof(ut32);
	mach0_ut p;
	ut32 left;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;

	if (!(ret = r_list_new ())) {
		printf("RList<RBinClass> allocation error\n");
		return NULL;
	}

	ret->free = (RListFree)Mach0_class_(__r_bin_class_free);

	// searching of section with name __objc_classlist
	sctns = r_bin_plugin_mach.sections(arch);
	if (sctns == NULL) {
		printf("there is no sections\n");
		return NULL;
	}

	r_list_foreach(sctns, iter, s) {
		if (strstr(s->name, "__objc_classlist") != NULL) {
			break;
		}
	}

	if (s == NULL) {
		printf("there is no section __objc_classlist\n");
		return NULL;
	}
	// end of seaching of section with name __objc_classlist

	// start of getting information about each class in file
	for (i = 0; i < s->size; i+= sizeof(mach0_ut)) {
		if (!(processed_class = R_NEW0 (RBinClass))) {
			printf("RBinClass allocation error\n");
			return NULL;
		}

		if (!(processed_class->methods = r_list_new())) {
			printf("RList<RBinField> allocation error\n");
			return NULL;
		}

		if (!(processed_class->fields = r_list_new())) {
			printf("RList<RBinSymbol> allocation error\n");
			return NULL;
		}

		memset(&p, '\0', sizeof(mach0_ut));

		left = s->size - i;
		size = left < sizeof(mach0_ut) ? left : sizeof(mach0_ut);

		r_buf_read_at(arch->buf, s->vaddr - r_bin_plugin_mach.baddr(arch) + i, (ut8 *)&p, size);

		Mach0_class_(get_class_t)(p, arch, processed_class);

		r_list_append(ret, processed_class);
	}

	return ret;
}
