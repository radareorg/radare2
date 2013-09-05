
/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../shlr/java/class.h"

static int load(RBinArch *arch) {
	return ((arch->bin_obj = r_bin_java_new_buf (arch->buf)))? 1: 0;
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
	/*char *p;
	RBinClass *c;
	RList *ret = r_list_new ();
	if (!ret) return NULL;
	
	// TODO: add proper support for inner classes in Java
	c = R_NEW0 (RBinClass);
	c->visibility = R_BIN_CLASS_PUBLIC;
	c->name = strdup (arch->file);
	p = strchr (c->name, '.');
	if (p) *p = 0;
	p = (char*)r_str_lchr (c->name, '/');
	if (p) strcpy (c->name, p+1);
	c->super = strdup ("Object"); //XXX
	r_list_append (ret, c);*/
	RList *ret;
	ret = r_bin_java_get_classes((struct r_bin_java_obj_t*)arch->bin_obj);
	return ret;
}

static RList* symbols(RBinArch *arch) {
	return r_bin_java_get_symbols ((struct r_bin_java_obj_t*)arch->bin_obj);
}

static RList* strings(RBinArch *arch) {
	return r_bin_java_get_strings((struct r_bin_java_obj_t*)arch->bin_obj);
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

	if (arch && arch->buf && arch->buf->buf && arch->buf->length>10)
	if (!memcmp (arch->buf->buf, "\xca\xfe\xba\xbe", 4)) {
		ut16 major = (arch->buf->buf[8]<<8) | arch->buf->buf[7];
		memcpy (&off, arch->buf->buf+4*sizeof(int), sizeof(int));
		r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
		if (major>=45 && major<=55)
			ret = R_TRUE;
		// TODO: in case of failed trick attempt discard on known mach0 headers?
#if 0
		/* KNOWN MACH0 HEADERS TO DISCARD */
		if (off > 0 && off+5 < arch->buf->length) {
			const ut8 * pbuf = arch->buf->buf+off;
			if (	!memcmp (pbuf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (pbuf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (pbuf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (pbuf, "\xcf\xfa\xed\xfe", 4))
				ret = R_FALSE;
		}
#endif
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
	return r_bin_java_get_sections (arch->bin_obj);
}

static RList* fields(RBinArch *arch) {
	return r_bin_java_get_fields (arch->bin_obj);
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
	.fields = fields,
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
