/* radare - LGPL - Copyright 2009-2011 */
/* authors: pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

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
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
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

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_java_sym_t *symbols = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbols = r_bin_java_get_symbols ((struct r_bin_java_obj_t*)arch->bin_obj)))
		return ret;
	for (i = 0; !symbols[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->rva = ptr->offset = symbols[i].offset;
		ptr->size = symbols[i].size;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
	free (symbols);
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
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS);
	version = r_bin_java_get_version (arch->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS);
	free (version);
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "java", R_BIN_SIZEOF_STRINGS);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static int check(RBinArch *arch) {
	int off, ret = R_FALSE;

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

struct r_bin_plugin_t r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = NULL,
	.entries = &entries,
	.sections = NULL,
	.symbols = &symbols,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.demangle_type = retdemangle
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java
};
#endif
