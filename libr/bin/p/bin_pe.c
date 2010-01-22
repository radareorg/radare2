/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static int bopen(struct r_bin_t *bin)
{
	if(!(bin->bin_obj = PE_(r_bin_pe_new)(bin->file)))
		return -1;
	bin->fd = 1;
	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	PE_(r_bin_pe_free)((struct PE_(r_bin_pe_obj_t)*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(struct r_bin_t *bin)
{
	return PE_(r_bin_pe_get_image_base)(bin->bin_obj);
}

static struct r_bin_entry_t* entry(struct r_bin_t *bin)
{
	struct r_bin_entry_t *ret = NULL;
	struct r_bin_pe_entrypoint_t *entry = NULL;

	if((ret = malloc(sizeof(struct r_bin_entry_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_entry_t));
	if (!(entry = PE_(r_bin_pe_get_entrypoint)(bin->bin_obj)))
		return NULL;
	ret->offset = entry->offset;
	ret->rva = entry->rva;
	free(entry);
	return ret;
}

static struct r_bin_section_t* sections(struct r_bin_t *bin)
{
	struct r_bin_section_t *ret = NULL;
	struct r_bin_pe_section_t *sections = NULL;
	int i, count;
	
	if (!(sections = PE_(r_bin_pe_get_sections)(bin->bin_obj)))
		return NULL;
	for (count = 0; sections && !sections[count].last; count++);
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_section_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_section_t));
	for (i = 0; i < count; i++) {
		strncpy(ret[i].name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ret[i].size = sections[i].size;
		ret[i].vsize = sections[i].vsize;
		ret[i].offset = sections[i].offset;
		ret[i].rva = sections[i].rva;
		ret[i].characteristics = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE(sections[i].characteristics))
			ret[i].characteristics |= 0x1;
		if (R_BIN_PE_SCN_IS_WRITABLE(sections[i].characteristics))
			ret[i].characteristics |= 0x2;
		if (R_BIN_PE_SCN_IS_READABLE(sections[i].characteristics))
			ret[i].characteristics |= 0x4;
		if (R_BIN_PE_SCN_IS_SHAREABLE(sections[i].characteristics))
			ret[i].characteristics |= 0x8;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(sections);
	return ret;
}

static struct r_bin_symbol_t* symbols(struct r_bin_t *bin)
{
	struct r_bin_symbol_t *ret = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	int i, count;

	if (!(symbols = PE_(r_bin_pe_get_exports)(bin->bin_obj)))
		return NULL;
	for (count = 0; symbols && !symbols[count].last; count++);
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_symbol_t));
	for (i = 0; i < count; i++) {
		strncpy(ret[i].name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].forwarder, (char*)symbols[i].forwarder, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_STRINGS);
		ret[i].rva = symbols[i].rva;
		ret[i].offset = symbols[i].offset;
		ret[i].size = 0;
		ret[i].ordinal = symbols[i].ordinal;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(symbols);
	return ret;
}

static struct r_bin_import_t* imports(struct r_bin_t *bin)
{
	struct r_bin_import_t *ret = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i, count;

	if (!(imports = PE_(r_bin_pe_get_imports)(bin->bin_obj)))
		return NULL;
	for (count = 0; imports && !imports[count].last; count++);
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_import_t))) == NULL)
		return NULL;
	memset(ret, '\0', (count + 1) * sizeof(struct r_bin_import_t));
	for (i = 0; i < count; i++) {
		strncpy(ret[i].name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_STRINGS);
		ret[i].rva = imports[i].rva;
		ret[i].offset = imports[i].offset;
		ret[i].ordinal = imports[i].ordinal;
		ret[i].hint = imports[i].hint;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(imports);
	return ret;
}

static struct r_bin_info_t* info(struct r_bin_t *bin)
{
	char *str;
	struct r_bin_info_t *ret = NULL;

	if((ret = malloc(sizeof(struct r_bin_info_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_info_t));
	if ((str = PE_(r_bin_pe_get_class)(bin->bin_obj))) {
		strncpy(ret->class, str, R_BIN_SIZEOF_STRINGS);
		free(str);
	}
	strncpy(ret->rclass, "pe", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_os)(bin->bin_obj))) {
		strncpy(ret->os, str, R_BIN_SIZEOF_STRINGS);
		free(str);
	}
	if ((str = PE_(r_bin_pe_get_arch)(bin->bin_obj))) {
		strncpy(ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free(str);
	}
	if ((str = PE_(r_bin_pe_get_machine)(bin->bin_obj))) {
		strncpy(ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free(str);
	}
	if ((str = PE_(r_bin_pe_get_subsystem)(bin->bin_obj))) {
		strncpy(ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
		free(str);
	}
	if (PE_(r_bin_pe_is_dll)(bin->bin_obj))
		strncpy(ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_STRINGS);
	else
		strncpy(ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->big_endian = PE_(r_bin_pe_is_big_endian)(bin->bin_obj);
	ret->dbg_info = 0;
	if (!PE_(r_bin_pe_is_stripped_debug)(bin->bin_obj))
		ret->dbg_info |= 0x01;
	if (PE_(r_bin_pe_is_stripped_line_nums)(bin->bin_obj))
		ret->dbg_info |= 0x04;
	if (PE_(r_bin_pe_is_stripped_local_syms)(bin->bin_obj))
		ret->dbg_info |= 0x08;
	if (PE_(r_bin_pe_is_stripped_relocs)(bin->bin_obj))
		ret->dbg_info |= 0x10;
	return ret;
}

#if !R_BIN_PE64
static int check(struct r_bin_t *bin)
{
	ut8 buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1)
		return R_FALSE;
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);
	close(bin->fd);

	if (!memcmp(buf, "\x4d\x5a", 2) &&
		!memcmp(buf+(buf[0x3c]|(buf[0x3d]<<8)), "\x50\x45", 2) && 
		!memcmp(buf+(buf[0x3c]|buf[0x3d]<<8)+0x18, "\x0b\x01", 2))
		return R_TRUE;
	
	return R_FALSE;
}

struct r_bin_handle_t r_bin_plugin_pe = {
	.name = "pe",
	.desc = "PE bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = &check,
	.baddr = &baddr,
	.entry = &entry,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
#endif
