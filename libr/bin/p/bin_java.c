/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int bopen(struct r_bin_t *bin)
{
	if((bin->bin_obj = MALLOC_STRUCT(struct r_bin_java_t)) == NULL)
		return R_FALSE;

	if ((bin->fd = r_bin_java_open(bin->bin_obj, bin->file)) == -1) {
		free(bin->bin_obj);
		return -1;
	}

	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	return r_bin_java_close(bin->bin_obj);
}

static struct r_bin_entry_t* entry(struct r_bin_t *bin)
{
	struct r_bin_entry_t *ret = NULL;

	if((ret = MALLOC_STRUCT(struct r_bin_entry_t)) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_entry_t));

	ret->offset = ret->rva = r_bin_java_get_entrypoint(bin->bin_obj);
	return ret;
}

static ut64 baddr(struct r_bin_t *bin)
{
	return 0;
}

static struct r_bin_symbol_t* symbols(struct r_bin_t *bin)
{
	int symbols_count, i;
	struct r_bin_symbol_t *ret = NULL;
	struct r_bin_java_sym_t *symbol = NULL;

	symbols_count = r_bin_java_get_symbols_count(bin->bin_obj);

	if ((symbol = malloc(symbols_count * sizeof(struct r_bin_java_sym_t))) == NULL)
		return NULL;
	if ((ret = malloc((symbols_count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;
	memset(ret, '\0', (symbols_count + 1) * sizeof(struct r_bin_symbol_t));

	r_bin_java_get_symbols(bin->bin_obj,symbol);

	for (i = 0; i < symbols_count; i++) {
		strncpy(ret[i].name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ret[i].rva = ret[i].offset = symbol[i].offset;
		ret[i].size = symbol[i].size;
		ret[i].ordinal = 0;
		ret[i].last = 0;
	}
	ret[i].last = 1;

	free(symbol);

	return ret;
}

static struct r_bin_string_t* strings(struct r_bin_t *bin)
{
	int strings_count, i;
	struct r_bin_string_t *ret = NULL;
	struct r_bin_java_str_t *string = NULL;

	strings_count = r_bin_java_get_strings_count(bin->bin_obj);

	if ((string = malloc(strings_count * sizeof(struct r_bin_java_str_t))) == NULL)
		return NULL;
	if ((ret = malloc((strings_count + 1) * sizeof(struct r_bin_string_t))) == NULL)
		return NULL;
	memset(ret, '\0', (strings_count + 1) * sizeof(struct r_bin_string_t));

	r_bin_java_get_strings(bin->bin_obj,string);

	for (i = 0; i < strings_count; i++) {
		strncpy(ret[i].string, string[i].str, R_BIN_SIZEOF_STRINGS);
		ret[i].rva = ret[i].offset = string[i].offset;
		ret[i].size = string[i].size;
		ret[i].ordinal = string[i].ordinal;
		ret[i].last = 0;
	}
	ret[i].last = 1;

	free(string);

	return ret;
}

static struct r_bin_info_t* info(struct r_bin_t *bin)
{
	struct r_bin_info_t *ret = NULL;
	char version[32];

	if((ret = malloc(sizeof(struct r_bin_info_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_info_t));

	version[0] = '\0';
	r_bin_java_get_version(bin->bin_obj, version);

	strncpy(ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->class, version, R_BIN_SIZEOF_STRINGS);
	strncpy(ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS);
	strncpy(ret->arch, "javavm", R_BIN_SIZEOF_STRINGS);
	ret->big_endian= 0;
	ret->dbg_info = 0x04 | 0x08; /* LineNums | Syms */

	return ret;
}

static int check(struct r_bin_t *bin)
{
	ut8 buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1)
		return R_FALSE;
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);
	close(bin->fd);

	if (!memcmp(buf, "\xca\xfe\xba\xbe", 4))
		return R_TRUE;
	
	return R_FALSE;
}

struct r_bin_handle_t r_bin_plugin_java = {
	.name = "bin_java",
	.desc = "java bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = &check,
	.baddr = &baddr,
	.entry = &entry,
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
