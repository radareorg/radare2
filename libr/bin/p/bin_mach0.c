/* radare - GPL3 - Copyright 2009 pancake<@nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static int load(RBin *bin)
{
	if(!(bin->bin_obj = MACH0_(r_bin_mach0_new) (bin->file)))
		return R_FALSE;
	bin->size = ((struct MACH0_(r_bin_mach0_obj_t)*) (bin->bin_obj))->size;
	bin->buf = ((struct MACH0_(r_bin_mach0_obj_t)*) (bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin)
{
	MACH0_(r_bin_mach0_free) (bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBin *bin)
{
	return MACH0_(r_bin_mach0_get_baddr) (bin->bin_obj);
}

static RFList entries(RBin *bin)
{
	RFList ret;
	RBinEntry *ptr = NULL;
	struct r_bin_mach0_entrypoint_t *entry = NULL;

	if (!(entry = MACH0_(r_bin_mach0_get_entrypoint) (bin->bin_obj)))
		return NULL;
	if (!(ret = r_flist_new (1)))
		return NULL;
	if (!(ptr = MALLOC_STRUCT (RBinEntry)))
		return ret;
	memset (ptr, '\0', sizeof (RBinEntry));
	ptr->offset = entry->offset;
	ptr->rva = entry->addr;
	r_flist_set (ret, 0, ptr);
	free (entry);
	return ret;
}

static RFList sections(RBin *bin)
{
	int count, i;
	RFList ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_mach0_section_t *sections = NULL;

	if (!(sections = MACH0_(r_bin_mach0_get_sections) (bin->bin_obj)))
		return NULL;
	for (count = 0; !sections[count].last; count++);
	if (!(ret = r_flist_new (count))) {
		free (sections);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinSection)))
			break;
		strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].size;
		ptr->offset = sections[i].offset;
		ptr->rva = sections[i].addr;
		ptr->characteristics = 0;
		r_flist_set (ret, i, ptr);
	}
	free (sections);
	return ret;
}

static RFList symbols(RBin *bin)
{
	int count, i;
	RFList ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_mach0_symbol_t *symbols = NULL;

	if (!(symbols = MACH0_(r_bin_mach0_get_symbols) (bin->bin_obj)))
		return NULL;
	for (count = 0; !symbols[count].last; count++);
	if (!(ret = r_flist_new (count))) {
		free (symbols);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinSymbol)))
			break;
		strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS); //XXX Not only FUNC
		ptr->rva = symbols[i].addr;
		ptr->offset = symbols[i].offset;
		ptr->size = symbols[i].size;
		ptr->ordinal = 0;
		r_flist_set (ret, i, ptr);
	}
	free (symbols);
	return ret;
}

static RFList imports(RBin *bin)
{
	int count, i;
	RFList ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_mach0_import_t *imports = NULL;

	if (!(imports = MACH0_(r_bin_mach0_get_imports) (bin->bin_obj)))
		return NULL;
	for (count = 0; !imports[count].last; count++);
	if (!(ret = r_flist_new (count))) {
		free (imports);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinImport)))
			break;
		strncpy (ptr->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->rva = imports[i].addr;
		ptr->offset = imports[i].offset;
		ptr->ordinal = 0;
		ptr->hint = 0;
		r_flist_set (ret, i, ptr);
	}
	free (imports);
	return ret;
}

static RFList libs(RBin *bin)
{
	RFList ret = NULL;
	char *ptr = NULL;
	struct r_bin_mach0_lib_t *libs = NULL;
	int i, count;

	if (!(libs = MACH0_(r_bin_mach0_get_libs) (bin->bin_obj)))
		return NULL;
	for (count = 0; !libs[count].last; count++);
	if (!(ret = r_flist_new (count))) {
		free (libs);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		ptr = strdup (libs[i].name);
		r_flist_set (ret, i, ptr);
	}
	free (libs);
	return ret;
}

static RBinInfo* info(RBin *bin)
{
	char *str;
	RBinInfo *ret = NULL;

	if((ret = MALLOC_STRUCT (RBinInfo)) == NULL)
		return NULL;
	memset(ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, bin->file, R_BIN_SIZEOF_STRINGS);
	if ((str = MACH0_(r_bin_mach0_get_class) (bin->bin_obj))) {
		strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy(ret->rclass, "mach0", R_BIN_SIZEOF_STRINGS);
	/* TODO get os*/
	strncpy(ret->os, "macos", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->subsystem, "macos", R_BIN_SIZEOF_STRINGS);
	if ((str = MACH0_(r_bin_mach0_get_cputype) (bin->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = MACH0_(r_bin_mach0_get_cpusubtype) (bin->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = MACH0_(r_bin_mach0_get_filetype) (bin->bin_obj))) {
		strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	ret->bits = MACH0_(r_bin_mach0_get_bits) (bin->bin_obj);
	ret->big_endian = MACH0_(r_bin_mach0_is_big_endian) (bin->bin_obj);
	/* TODO detailed debug info */
	ret->dbg_info = 0;
	return ret;
}

#if !R_BIN_MACH064
static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 4)))
		return R_FALSE;
	if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
		!memcmp (buf, "\xfe\xed\xfa\xce", 4))
		ret = R_TRUE;
	free (buf);
	return ret;
}

struct r_bin_handle_t r_bin_plugin_mach0 = {
	.name = "mach0",
	.desc = "mach0 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.meta = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0
};
#endif
#endif
