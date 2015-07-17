#include "mach032_classes.h"

#define RO_META               (1<<0)

struct SMethodList32 {
	ut32 entsize;
	ut32 count;
	/* SMethod first;  These structures follow inline */
};

struct SMethod32 {
	ut32 name;	/* SEL (32-bit pointer) */
	ut32 types;	/* const char * (32-bit pointer) */
	ut32 imp;	/* IMP (32-bit pointer) */
};

struct SCLass32 {
	ut32 isa;		/* SClass* (32-bit pointer) */
	ut32 superclass;	/* SClass* (32-bit pointer) */
	ut32 cache;		/* Cache (32-bit pointer) */
	ut32 vtable;		/* IMP * (32-bit pointer) */
	ut32 data;		/* SClassRoT * (32-bit pointer) */
};

struct SClassRoT32 {
	ut32 flags;
	ut32 instanceStart;
	ut32 instanceSize;
//	ut32 reserved;
	ut32 ivarLayout;	/* const uint8_t* (32-bit pointer) */
	ut32 name; 		/* const char* (32-bit pointer) */
	ut32 baseMethods; 	/* const SMEthodList* (32-bit pointer) */
	ut32 baseProtocols; 	/* const SProtocolList* (32-bit pointer) */
	ut32 ivars; 		/* const SIVarList* (32-bit pointer) */
	ut32 weakIvarLayout; 	/* const uint8_t * (32-bit pointer) */
	ut32 baseProperties; 	/* const SObjcPropertyList* (32-bit pointer) */
};

struct SProtocolList32 {
	ut32 count;	/* uintptr_t (a 32-bit value) */
	/* SProtocol* list[0];  These pointers follow inline */
};

struct SProtocol32 {
	ut32 isa;			/* id* (32-bit pointer) */
	ut32 name;			/* const char * (32-bit pointer) */
	ut32 protocols;			/* SProtocolList*
							(32-bit pointer) */
	ut32 instanceMethods;		/* SMethodList* (32-bit pointer) */
	ut32 classMethods;		/* SMethodList* (32-bit pointer) */
	ut32 optionalInstanceMethods;	/* SMethodList* (32-bit pointer) */
	ut32 optionalClassMethods;	/* SMethodList* (32-bit pointer) */
	ut32 instanceProperties;	/* struct SObjcPropertyList*
							   (32-bit pointer) */
};


struct SIVarList32 {
	ut32 entsize;
	ut32 count;
	/* SIVar first;  These structures follow inline */
};

struct SIVar32 {
	ut32 offset;	/* uintptr_t * (32-bit pointer) */
	ut32 name;	/* const char * (32-bit pointer) */
	ut32 type;	/* const char * (32-bit pointer) */
	ut32 alignment;
	ut32 size;
};

struct SObjcProperty32 {
	ut32 name;		/* const char * (32-bit pointer) */
	ut32 attributes;	/* const char * (32-bit pointer) */
};

struct SObjcPropertyList32 {
	ut32 entsize;
	ut32 count;
	/* struct SObjcProperty first;  These structures follow inline */
};

static ut32 get_pointer_32(ut32 p, ut32 *offset, ut32 *left,
							RBinFile *arch);

static void copy_sym_name_with_namespace(char *class_name, char *read_name,
										 RBinSymbol *sym);

static void copy_sym_name_with_namespace(char *class_name, char *read_name,
										 RBinSymbol *sym);

static void get_ivar_list_t(ut32 p, RBinFile *arch,
							  RBinClass *processed_class);

static void get_objc_property_list(ut32 p, RBinFile *arch,
									 RBinClass *processed_class);

static void get_method_list_t(ut32 p, RBinFile *arch, char *class_name,
								RBinClass *processed_class);

static void get_protocol_list_t(ut32 p, RBinFile *arch,
								  RBinClass *processed_class);

static void get_class_ro_t(ut32 p, RBinFile *arch,
							 ut32 *is_meta_class,
							 RBinClass *processed_class);

static void get_class_t(ut32 p, RBinFile *arch,
						  RBinClass *processed_class);

static void __r_bin_class_free(RBinClass *p);

static ut32 get_pointer_32(ut32 p, ut32 *offset, ut32 *left,
							RBinFile *arch)
{
	ut32 r;
	ut32 addr;
	ut32 section_content_addr;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;

	sctns = r_bin_plugin_mach0.sections(arch);
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

			section_content_addr = (s->vaddr - r_bin_plugin_mach0.baddr(arch));
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

static void copy_sym_name_with_namespace(char *class_name, char *read_name,
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

static void get_ivar_list_t(ut32 p, RBinFile *arch,
							  RBinClass *processed_class)
{
	struct SIVarList32 il;
	struct SIVar32 i;
	ut32 r;
	ut32 offset, left, j;
	char *name;
	ut32 ivar_offset_p, ivar_offset;
	RBinField *field = NULL;

	r = get_pointer_32(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}
	memset(&il, '\0', sizeof(struct SIVarList32));
	if(left < sizeof(struct SIVarList32)) {
		r_buf_read_at(arch->buf, r, (ut8 *)&il, left);
	} else {
		r_buf_read_at(arch->buf, r, (ut8 *)&il, sizeof(struct SIVarList32));
	}

	p += sizeof(struct SIVarList32);
	offset += sizeof(struct SIVarList32);
	for(j = 0; j < il.count; j++){
		r = get_pointer_32(p, &offset, &left, arch);
		if(r == 0) {
			return;
		}

		if (!(field = R_NEW0 (RBinField))) {
			printf("RBinField allocation error\n");
			return;
		}

		memset(&i, '\0', sizeof(struct SIVar32));
		if(left < sizeof(struct SIVar32)) {
			r_buf_read_at(arch->buf, r, (ut8 *)&i, left);
		}
		else {
			r_buf_read_at(arch->buf, r, (ut8 *)&i, sizeof(struct SIVar32));
		}

		ivar_offset_p = get_pointer_32(i.offset, NULL, &left, arch);
		if (ivar_offset_p != 0 && left >= sizeof(ut32)) {
			r_buf_read_at(arch->buf, ivar_offset_p, (ut8 *)&ivar_offset, sizeof(ivar_offset));
			field->vaddr = ivar_offset;
		}

		r = get_pointer_32(i.name, NULL, &left, arch);
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

		r = get_pointer_32(i.type, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			R_FREE(name);
		}

		r_list_append(processed_class->fields, field);

		p += sizeof(struct SIVar32);
		offset += sizeof(struct SIVar32);
	}
}

static void get_objc_property_list(ut32 p, RBinFile *arch,
									 RBinClass *processed_class)
{
	struct SObjcPropertyList32 opl;
	struct SObjcProperty32 op;
	ut32 r;
	ut32 offset, left, j;
	char *name;
	RBinSymbol *property = NULL;

	r = get_pointer_32(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}

	memset(&opl, '\0', sizeof(struct SObjcPropertyList32));
	if(left < sizeof(struct SObjcPropertyList32)){
		r_buf_read_at(arch->buf, r, (ut8 *)&opl, left);
	}
	else {
		r_buf_read_at(arch->buf, r, (ut8 *)&opl, sizeof(struct SObjcPropertyList32));
	}

	p += sizeof(struct SObjcPropertyList32);
	offset += sizeof(struct SObjcPropertyList32);
	for(j = 0; j < opl.count; j++){
		r = get_pointer_32(p, &offset, &left, arch);
		if(r == 0)
			return;

		if (!(property = R_NEW0 (RBinSymbol))) {
			printf("RBinClass allocation error\n");
			return;
		}

		memset(&op, '\0', sizeof(struct SObjcProperty32));
		if(left < sizeof(struct SObjcProperty32)){
			r_buf_read_at(arch->buf, r, (ut8 *)&op, left);
		} else {
			r_buf_read_at(arch->buf, r, (ut8 *)&op, sizeof(struct SObjcProperty32));
		}

		r = get_pointer_32(op.name, NULL, &left, arch);
		if(r != 0) {
			char *tmp = NULL;

			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			tmp = r_str_newf("%s%s", "(property)", name);

			copy_sym_name_with_namespace(processed_class->name, tmp, property);

			R_FREE(tmp);
			R_FREE(name);
		}

		r = get_pointer_32(op.attributes, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			free(name);
			name = 0;
		}

		r_list_append(processed_class->methods, property);

		p += sizeof(struct SObjcProperty32);
		offset += sizeof(struct SObjcProperty32);
	}
}

static void get_method_list_t(ut32 p, RBinFile *arch, char *class_name,
								RBinClass *processed_class)
{
	struct SMethodList32 ml;
	struct SMethod32 m;
	ut32 r;
	ut32 offset, left, i;
	char *name = NULL;

	RBinSymbol *method = NULL;

	r = get_pointer_32(p, &offset, &left, arch);
	if(r == 0)
		return;
	memset(&ml, '\0', sizeof(struct SMethodList32));
	if(left < sizeof(struct SMethodList32)){
		r_buf_read_at(arch->buf, r, (ut8 *)&ml, left);
	}
	else {
		r_buf_read_at(arch->buf, r, (ut8 *)&ml, sizeof(struct SMethodList32));
	}

	p += sizeof(struct SMethodList32);
	offset += sizeof(struct SMethodList32);
	for(i = 0; i < ml.count; i++) {
		r = get_pointer_32(p, &offset, &left, arch);
		if(r == 0) {
			return;
		}

		if (!(method = R_NEW0 (RBinSymbol))) {
			printf("RBinClass allocation error\n");
			return;
		}

		memset(&m, '\0', sizeof(struct SMethod32));
		if(left < sizeof(struct SMethod32)){
			r_buf_read_at(arch->buf, r, (ut8 *)&ml, left);
		}
		else {
			r_buf_read_at(arch->buf, r, (ut8 *)&m, sizeof(struct SMethod32));
		}

		r = get_pointer_32(m.name, NULL, &left, arch);
		if (r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);

			copy_sym_name_with_namespace(class_name, name, method);

			R_FREE(name);
		}
		r = get_pointer_32(m.types, NULL, &left, arch);
		if(r != 0) {
			name = malloc(left);
			r_buf_read_at(arch->buf, r, (ut8 *)name, left);
			R_FREE(name);
		}

		method->vaddr = m.imp;

		r_list_append(processed_class->methods, method);

		p += sizeof(struct SMethod32);
		offset += sizeof(struct SMethod32);
	}
}

static void get_protocol_list_t(ut32 p, RBinFile *arch,
								  RBinClass *processed_class)
{
	struct SProtocolList32 pl;
	ut32 q;
	struct SProtocol32 pc;
	ut32 r;
	ut32 offset, left, i;
	char *class_name;

	r = get_pointer_32(p, &offset, &left, arch);
	if(r == 0) {
		return;
	}
	memset(&pl, '\0', sizeof(struct SProtocolList32));
	if(left < sizeof(struct SProtocolList32)){
		r_buf_read_at(arch->buf, r, (ut8 *)&pl, left);
	}
	else {
		r_buf_read_at(arch->buf, r, (ut8 *)&pl, sizeof(struct SProtocolList32));
	}

	p += sizeof(struct SProtocolList32);
	offset += sizeof(struct SProtocolList32);
	for(i = 0; i < pl.count; i++){
		r = get_pointer_32(p, &offset, &left, arch);
		if(r == 0)
			return;

		q = 0;
		if(left < sizeof(ut32)){
			r_buf_read_at(arch->buf, r, (ut8 *)&q, left);
		}
		else {
			r_buf_read_at(arch->buf, r, (ut8 *)&q, sizeof(ut32));
		}

		r = get_pointer_32(q, &offset, &left, arch);
		if(r == 0) {
			return;
		}
		memset(&pc, '\0', sizeof(struct SProtocol32));
		if(left < sizeof(struct SProtocol32)){
			r_buf_read_at(arch->buf, r, (ut8 *)&pc, left);
		}
		else {
			r_buf_read_at(arch->buf, r, (ut8 *)&pc, sizeof(struct SProtocol32));
		}

		r = get_pointer_32(pc.name, NULL, &left, arch);
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
			get_method_list_t(pc.instanceMethods, arch, class_name, processed_class);
		}

		if(pc.classMethods != 0) {
			get_method_list_t(pc.classMethods, arch, class_name, processed_class);
		}

		R_FREE(class_name);

		p += sizeof(ut32);
		offset += sizeof(ut32);
	}
}

static void get_class_ro_t(ut32 p, RBinFile *arch,
							 ut32 *is_meta_class,
							 RBinClass *processed_class)
{
	struct SClassRoT32 cro;
	ut32 r;
	ut32 offset, left;

	r = get_pointer_32(p, &offset, &left, arch);
	if(r == 0)
		return;
	memset(&cro, '\0', sizeof(struct SClassRoT32));
	if(left < sizeof(struct SClassRoT32)){
		r_buf_read_at(arch->buf, r, (ut8 *)&cro, left);
	}
	else {
		r_buf_read_at(arch->buf, r, (ut8 *)&cro, sizeof(struct SClassRoT32));
	}

	r = get_pointer_32(cro.name, NULL, &left, arch);
	if(r != 0) {
		processed_class->name = malloc(left);
		r_buf_read_at(arch->buf, r, (ut8 *)processed_class->name, left);

//		R_FREE(name);
	}

	if(cro.baseMethods != 0) {
		get_method_list_t(cro.baseMethods, arch, processed_class->name, processed_class);
	}

	if(cro.baseProtocols != 0) {
		get_protocol_list_t(cro.baseProtocols, arch, processed_class);
	}

	if(cro.ivars != 0) {
		get_ivar_list_t(cro.ivars, arch, processed_class);
	}

	if(cro.baseProperties != 0) {
		get_objc_property_list(cro.baseProperties, arch, processed_class);
	}

	if(is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) ? 1 : 0;
	}
}

static void get_class_t(ut32 p, RBinFile *arch,
						  RBinClass *processed_class)
{
	struct SCLass32 c;
	ut32 r;
	uint32_t offset, left;
	ut32 is_meta_class = 0;

	r = get_pointer_32(p, &offset, &left, arch);
	if (r == 0) {
		return;
	}
	memset(&c, '\0', sizeof(struct SCLass32));

	if (left < sizeof(struct SCLass32)) {
		r_buf_read_at(arch->buf, r, (ut8 *)&c, left);
	} else {
		r_buf_read_at(arch->buf, r, (ut8 *)&c, sizeof(struct SCLass32));
	}

	processed_class->addr = c.isa;
	get_class_ro_t((c.data) & ~0x3, arch, &is_meta_class, processed_class);
}

static void __r_bin_class_free(RBinClass *p) {
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

RList* classes_mach032(RBinFile *arch)
{
	RList/*<RBinClass>*/ *ret = NULL;

	RBinClass *processed_class = NULL;

	RList *sctns = NULL;
	RListIter *iter = NULL;
	RBinSection *s = NULL;
	ut32 i = 0, size = sizeof(ut32);
	ut32 p;
	ut32 left;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;

	if (!(ret = r_list_new ())) {
		printf("RList<RBinClass> allocation error\n");
		return NULL;
	}

	ret->free = (RListFree)__r_bin_class_free;

	// searching of section with name __objc_classlist
	sctns = r_bin_plugin_mach0.sections(arch);
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
	for (i = 0; i < s->size; i+= sizeof(ut32)) {
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

		memset(&p, '\0', sizeof(ut32));

		left = s->size - i;
		size = left < sizeof(ut32) ? left : sizeof(ut32);

		r_buf_read_at(arch->buf, s->vaddr - r_bin_plugin_mach0.baddr(arch) + i, (ut8 *)&p, size);

		get_class_t(p, arch, processed_class);

		r_list_append(ret, processed_class);
	}

	return ret;
}
