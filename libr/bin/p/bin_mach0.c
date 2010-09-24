/* radare - GPL3 - Copyright 2009 pancake<@nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static int load(RBinArch *arch) {
	if(!(arch->bin_obj = MACH0_(r_bin_mach0_new_buf) (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	MACH0_(r_bin_mach0_free) (arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return MACH0_(r_bin_mach0_get_baddr) (arch->bin_obj);
}

static RList* entries(RBinArch *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	struct r_bin_mach0_addr_t *entry = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(entry = MACH0_(r_bin_mach0_get_entrypoint) (arch->bin_obj)))
		return ret;
	if ((ptr = R_NEW (RBinAddr))) {
		memset (ptr, '\0', sizeof (RBinAddr));
		ptr->offset = entry->offset;
		ptr->rva = entry->addr;
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_mach0_section_t *sections = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(sections = MACH0_(r_bin_mach0_get_sections) (arch->bin_obj)))
		return ret;
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW (RBinSection)))
			break;
		strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].size;
		ptr->offset = sections[i].offset;
		ptr->rva = sections[i].addr;
		ptr->srwx = 0;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_mach0_symbol_t *symbols = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbols = MACH0_(r_bin_mach0_get_symbols) (arch->bin_obj)))
		return ret;
	for (i = 0; !symbols[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS); //XXX Get the right type
		if (symbols[i].type == R_BIN_MACH0_SYMBOL_TYPE_LOCAL)
			strncat (ptr->type, "_LOCAL", R_BIN_SIZEOF_STRINGS);
		ptr->rva = symbols[i].addr;
		ptr->offset = symbols[i].offset;
		ptr->size = symbols[i].size;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
	free (symbols);
	return ret;
}

static RList* imports(RBinArch *arch) {
	RList *ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_mach0_import_t *imports = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(imports = MACH0_(r_bin_mach0_get_imports) (arch->bin_obj)))
		return ret;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;
		strncpy (ptr->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		if (imports[i].type == R_BIN_MACH0_IMPORT_TYPE_FUNC)
			strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		else strncpy (ptr->type, "OBJECT", R_BIN_SIZEOF_STRINGS);
		ptr->rva = imports[i].addr;
		ptr->offset = imports[i].offset;
		ptr->size = 0;
		ptr->ordinal = 0;
		ptr->hint = 0;
		r_list_append (ret, ptr);
	}
	free (imports);
	return ret;
}

static RList* libs(RBinArch *arch) {
	RList *ret = NULL;
	char *ptr = NULL;
	struct r_bin_mach0_lib_t *libs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = MACH0_(r_bin_mach0_get_libs) (arch->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	char *str;
	RBinInfo *ret = NULL;

	if((ret = R_NEW (RBinInfo)) == NULL)
		return NULL;
	memset(ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if ((str = MACH0_(r_bin_mach0_get_class) (arch->bin_obj))) {
		strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy(ret->rclass, "mach0", R_BIN_SIZEOF_STRINGS);
	/* TODO get os*/
	strncpy(ret->os, "macos", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->subsystem, "macos", R_BIN_SIZEOF_STRINGS);
	if ((str = MACH0_(r_bin_mach0_get_cputype) (arch->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = MACH0_(r_bin_mach0_get_cpusubtype) (arch->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = MACH0_(r_bin_mach0_get_filetype) (arch->bin_obj))) {
		strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	ret->bits = MACH0_(r_bin_mach0_get_bits) (arch->bin_obj);
	ret->big_endian = MACH0_(r_bin_mach0_is_big_endian) (arch->bin_obj);
	/* TODO detailed debug info */
	ret->dbg_info = 0;
	return ret;
}

#if !R_BIN_MACH064
static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "\xce\xfa\xed\xfe", 4) ||
		!memcmp (arch->buf->buf, "\xfe\xed\xfa\xce", 4))
		return R_TRUE;
	return R_FALSE;
}

struct r_bin_plugin_t r_bin_plugin_mach0 = {
	.name = "mach0",
	.desc = "mach0 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.main = NULL,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0
};
#endif
#endif
