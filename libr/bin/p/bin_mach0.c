/* radare - GPL3 - Copyright 2009 pancake<@nopcode.org> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static int bopen(struct r_bin_t *bin)
{
	struct r_bin_mach0_obj_t* mach0_obj;
	if(!(bin->bin_obj = r_bin_mach0_new(bin->file)))
		return -1;
	mach0_obj = (struct r_bin_mach0_obj_t*)bin->bin_obj; 
	bin->fd = mach0_obj->fd;
	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	r_bin_mach0_free((struct r_bin_mach0_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(struct r_bin_t *bin)
{
	return r_bin_mach0_get_baddr((struct r_bin_mach0_obj_t*)bin->bin_obj);
}

static int check(struct r_bin_t *bin)
{
	int ret = R_FALSE;
	ut8 buf[4];

	if ((bin->fd = open(bin->file, 0)) != -1) {
		lseek(bin->fd, 0, SEEK_SET);
		read(bin->fd, buf, 4);
		close(bin->fd);
		if (!memcmp(buf, "\xce\xfa\xed\xfa", 4) ||
			!memcmp(buf, "\xfe\xed\xfa\xce", 4))
			ret = R_TRUE;
	}
	return ret;
}

static struct r_bin_section_t* sections(struct r_bin_t *bin)
{
	int count, i;
	struct r_bin_section_t *ret = NULL;
	struct r_bin_mach0_section_t *sections = NULL;

	if (!(sections = r_bin_mach0_get_sections((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; sections && !sections[count].last; count++);
	if (count == 0)
		return NULL;
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_section_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_section_t));

	for (i = 0; sections && !sections[i].last; i++) {
		strncpy(ret[i].name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ret[i].size = sections[i].size;
		ret[i].vsize = sections[i].size;
		ret[i].offset = sections[i].offset;
		ret[i].rva = sections[i].addr;
		ret[i].characteristics = 0;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(sections);
	return ret;
}

static struct r_bin_symbol_t* symbols(struct r_bin_t *bin)
{
	int count, i;
	struct r_bin_symbol_t *ret = NULL;
	struct r_bin_mach0_symbol_t *symbols = NULL;

	if (!(symbols = r_bin_mach0_get_symbols((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; symbols && !symbols[count].last; count++);
	if (count == 0)
		return NULL;
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_symbol_t));

	for (i = 0; symbols && !symbols[i].last; i++) {
		strncpy(ret[i].name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_STRINGS);
		ret[i].rva = symbols[i].addr;
		ret[i].offset = symbols[i].offset;
		ret[i].size = symbols[i].size;
		ret[i].ordinal = 0;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(symbols);
	return ret;
}

static struct r_bin_import_t* imports(struct r_bin_t *bin)
{
	int count, i;
	struct r_bin_import_t *ret = NULL;
	struct r_bin_mach0_import_t *imports = NULL;

	if (!(imports = r_bin_mach0_get_imports((struct r_bin_mach0_obj_t*)bin->bin_obj)))
		return NULL;
	for (count = 0; imports && !imports[count].last; count++);
	if (count == 0)
		return NULL;
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_import_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_import_t));

	for (i = 0; imports && !imports[i].last; i++) {
		strncpy(ret[i].name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_STRINGS);
		ret[i].rva = imports[i].addr;
		ret[i].offset = imports[i].offset;
		ret[i].ordinal = 0;
		ret[i].hint = 0;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(imports);
	return ret;
}

struct r_bin_handle_t r_bin_plugin_mach0 = {
	.name = "mach0",
	.desc = "mach0 bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = &check,
	.baddr = &baddr,
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
