/* radare - LGPL - Copyright 2009-2012 */
/* authors: pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../shlr/java/class.h"

static int load(RBinArch *arch) {
	if (!(arch->bin_obj = r_bin_java_new_buf (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	r_bin_java_free ((struct r_bin_java_obj_t*)arch->bin_obj);
	return R_TRUE;
}

static RList* entries(RBinArch *arch) {
	RBinAddr *ptr;
	RList *ret = r_list_new ();
	if (!ret) return NULL;
	ret->free = free;
	if (!(ptr = R_NEW (RBinAddr)))
		return ret;
	memset (ptr, '\0', sizeof (RBinAddr));
	ptr->offset = ptr->rva = r_bin_java_get_entrypoint (arch->bin_obj);
	r_list_append (ret, ptr);
	return ret;
}

static ut64 baddr(RBinArch *arch) {
	return 0;
}

static RList* classes(RBinArch *arch) {
	char *p;
	RBinClass *c;
	RList *ret = r_list_new ();
	if (!ret) return NULL;
	
	// TODO: add proper support for inner classes in Java
	c = R_NEW0 (RBinClass);
	c->visibility = R_BIN_CLASS_PUBLIC;
	c->name = strdup (arch->file);
	p = strchr (c->name, '.');
	if (p) *p = 0;
	p = r_str_lchr (c->name, '/');
	if (p) strcpy (c->name, p+1);
	c->super = strdup ("Object"); //XXX
	r_list_append (ret, c);

	return ret;
}

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_java_sym_t *s = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(s = r_bin_java_get_symbols ((struct r_bin_java_obj_t*)arch->bin_obj)))
		return ret;
	for (i = 0; !s[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, s[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->rva = ptr->offset = s[i].offset;
		ptr->size = s[i].size;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
	free (s);
	return ret;
}

static RList* strings(RBinArch *arch) {
	RList *ret = NULL;
	RBinString *ptr = NULL;
	struct r_bin_java_str_t *strings = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(strings = r_bin_java_get_strings((struct r_bin_java_obj_t*)arch->bin_obj)))
		return ret;
	for (i = 0; !strings[i].last; i++) {
		if (!(ptr = R_NEW (RBinString)))
			break;
		strncpy (ptr->string, strings[i].str, R_BIN_SIZEOF_STRINGS);
		ptr->rva = ptr->offset = strings[i].offset;
		ptr->size = strings[i].size;
		ptr->ordinal = strings[i].ordinal;
		r_list_append (ret, ptr);
	}
	free (strings);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	char *version;

	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	ret->lang = "java";
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS-1);
	version = r_bin_java_get_version (arch->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS-1);
	free (version);
	ret->has_va = 0;
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->arch, "java", R_BIN_SIZEOF_STRINGS-1);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static int check(RBinArch *arch) {
	int off, ret = R_FALSE;

	if (arch && arch->buf && arch->buf->buf)
	if (!memcmp (arch->buf->buf, "\xca\xfe\xba\xbe", 4)) {
		ret = R_TRUE;
		memcpy (&off, arch->buf->buf+4*sizeof(int), sizeof(int));
		r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
		if (off > 0 && off < arch->buf->length) {
			memmove (arch->buf->buf, arch->buf->buf+off, 4);
			if (	!memcmp (arch->buf->buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (arch->buf->buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (arch->buf->buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (arch->buf->buf, "\xcf\xfa\xed\xfe", 4))
				ret = R_FALSE;
		}
	}
	return ret;
}

static int retdemangle(const char *str) {
	return R_BIN_NM_JAVA;
}

static RBinAddr* binsym(RBinArch *arch, int sym) {
	RBinAddr *ret = NULL;
	switch (sym) {
	case R_BIN_SYM_ENTRY:
		if (!(ret = R_NEW0 (RBinAddr)))
			return NULL;
		ret->offset = r_bin_java_get_entrypoint (arch->bin_obj);
		break;
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW0 (RBinAddr)))
			return NULL;
		ret->offset = ret->rva = r_bin_java_get_main (arch->bin_obj);
		break;
	}
	return ret;
}

static RList* lines(RBinArch *arch) {
	int i;
	char *file = strdup (arch->file);
	RList *list = r_list_new ();
	RBinJavaObj *b = arch->bin_obj;
	file = r_str_replace (file, ".class", ".java", 0);
	for (i=0; i<b->lines.count; i++) {
		RBinDwarfRow *row = R_NEW (RBinDwarfRow);
		r_bin_dwarf_line_new (row, b->lines.addr[i], file, b->lines.line[i]);
		r_list_append (list, row);
	}
	free (file);
	return list;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_java_sym_t *s = NULL;
	RBinJavaObj *b = arch->bin_obj;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((s = r_bin_java_get_symbols (arch->bin_obj))) {
		if ((ptr = R_NEW (RBinSection))) {
			strcpy (ptr->name, "code");
			ptr->size = ptr->vsize = b->fsymsz;
			ptr->offset = ptr->rva = b->fsym;
			ptr->srwx = 4|1;
			r_list_append (ret, ptr);
		}
		if ((ptr = R_NEW (RBinSection))) {
			strcpy (ptr->name, "constpool");
			ptr->size = ptr->vsize = b->fsym;
			ptr->offset = ptr->rva = 0;
			ptr->srwx = 4;
			r_list_append (ret, ptr);
		}
		if ((ptr = R_NEW (RBinSection))) {
			strcpy (ptr->name, "data");
			ptr->offset = ptr->rva = b->fsymsz+b->fsym;
			ptr->size = ptr->vsize = arch->buf->length - ptr->rva;
			ptr->srwx = 4|2;
			r_list_append (ret, ptr);
		}
		free (s);
	}
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.lines = &lines,
	.write = NULL,
	.classes = classes,
	.demangle_type = retdemangle
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java
};
#endif
