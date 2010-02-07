/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int load(RBin *bin)
{
	if(!(bin->bin_obj = r_bin_java_new(bin->file)))
		return R_FALSE;
	bin->size = ((struct r_bin_java_obj_t*)(bin->bin_obj))->size;
	bin->buf = ((struct r_bin_java_obj_t*)(bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin)
{
	r_bin_java_free((struct r_bin_java_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static RArray entries(RBin *bin)
{
	RArray ret;
	RBinEntry *tmp = NULL;

	if (!(ret = r_array_new (1)))
		return NULL;
	if (!(tmp = MALLOC_STRUCT (RBinEntry)))
		return ret;
	memset (tmp, '\0', sizeof (RBinEntry));
	tmp->offset = tmp->rva = r_bin_java_get_entrypoint (bin->bin_obj);
	r_array_set (ret, 0, tmp);
	return ret;
}

static ut64 baddr(RBin *bin)
{
	return 0;
}

static RArray symbols(RBin *bin)
{
	RArray ret = NULL;
	RBinSymbol *tmp = NULL;
	struct r_bin_java_sym_t *symbols = NULL;
	int count, i;

	if (!(symbols = r_bin_java_get_symbols ((struct r_bin_java_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; !symbols[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (symbols);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinSymbol)))
			break;
		strncpy (tmp->name, symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		tmp->rva = tmp->offset = symbols[i].offset;
		tmp->size = symbols[i].size;
		tmp->ordinal = 0;
		r_array_set (ret, i, tmp);
	}
	free (symbols);
	return ret;
}

static RArray strings(RBin *bin)
{
	RArray ret = NULL;
	RBinString *tmp = NULL;
	struct r_bin_java_str_t *strings = NULL;
	int count, i;

	if (!(strings = r_bin_java_get_strings((struct r_bin_java_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; !strings[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (strings);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinString)))
			break;
		strncpy (tmp->string, strings[i].str, R_BIN_SIZEOF_STRINGS);
		tmp->rva = tmp->offset = strings[i].offset;
		tmp->size = strings[i].size;
		tmp->ordinal = strings[i].ordinal;
	}
	free (strings);
	return ret;
}

static RBinInfo* info(RBin *bin)
{
	RBinInfo *ret = NULL;
	char *version;

	if(!(ret = MALLOC_STRUCT (RBinInfo)))
		return NULL;
	strncpy (ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS);
	version = r_bin_java_get_version (bin->bin_obj);
	strncpy (ret->class, version, R_BIN_SIZEOF_STRINGS);
	free (version);
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "javavm", R_BIN_SIZEOF_STRINGS);
	ret->big_endian= 0;
	ret->dbg_info = 0x04 | 0x08; /* LineNums | Syms */
	return ret;
}

static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 4)))
		return R_FALSE;
	if (!memcmp (buf, "\xca\xfe\xba\xbe", 4))
		ret = R_TRUE;
	free (buf);
	return ret;
}

struct r_bin_handle_t r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = NULL,
	.symbols = &symbols,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java
};
#endif
