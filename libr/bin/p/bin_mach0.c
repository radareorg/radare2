/* radare - GPL3 - Copyright 2009 pancake<@nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static int load(RBin *bin)
{
	if(!(bin->bin_obj = r_bin_mach0_new (bin->file)))
		return R_FALSE;
	bin->size = ((struct r_bin_mach0_obj_t*) (bin->bin_obj))->size;
	bin->buf = ((struct r_bin_mach0_obj_t*) (bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin)
{
	r_bin_mach0_free ((struct r_bin_mach0_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBin *bin)
{
	return r_bin_mach0_get_baddr ((struct r_bin_mach0_obj_t*)bin->bin_obj);
}

static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 4)))
		return R_FALSE;
	if (!memcmp (buf, "\xce\xfa\xed\xfa", 4) ||
		!memcmp (buf, "\xfe\xed\xfa\xce", 4))
		ret = R_TRUE;
	free (buf);
	return ret;
}

static RArray sections(RBin *bin)
{
	int count, i;
	RArray ret = NULL;
	RBinSection *tmp = NULL;
	struct r_bin_mach0_section_t *sections = NULL;

	if (!(sections = r_bin_mach0_get_sections ((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; !sections[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (sections);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinSection)))
			break;
		strncpy (tmp->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		tmp->size = sections[i].size;
		tmp->vsize = sections[i].size;
		tmp->offset = sections[i].offset;
		tmp->rva = sections[i].addr;
		tmp->characteristics = 0;
		r_array_set (ret, i, tmp);
	}
	free (sections);
	return ret;
}

static RArray symbols(RBin *bin)
{
	int count, i;
	RArray ret = NULL;
	RBinSymbol *tmp = NULL;
	struct r_bin_mach0_symbol_t *symbols = NULL;

	if (!(symbols = r_bin_mach0_get_symbols ((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; !symbols[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (symbols);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinSymbol)))
			break;
		strncpy (tmp->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->type, "NONE", R_BIN_SIZEOF_STRINGS);
		tmp->rva = symbols[i].addr;
		tmp->offset = symbols[i].offset;
		tmp->size = symbols[i].size;
		tmp->ordinal = 0;
		r_array_set (ret, i, tmp);
	}
	free (symbols);
	return ret;
}

static RArray imports(RBin *bin)
{
	int count, i;
	RArray ret = NULL;
	RBinImport *tmp = NULL;
	struct r_bin_mach0_import_t *imports = NULL;

	if (!(imports = r_bin_mach0_get_imports((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; !imports[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (imports);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinImport)))
			break;
		strncpy (tmp->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->type, "NONE", R_BIN_SIZEOF_STRINGS);
		tmp->rva = imports[i].addr;
		tmp->offset = imports[i].offset;
		tmp->ordinal = 0;
		tmp->hint = 0;
		r_array_set (ret, i, tmp);
	}
	free (imports);
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
	.entries = NULL,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = NULL,
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0
};
#endif
