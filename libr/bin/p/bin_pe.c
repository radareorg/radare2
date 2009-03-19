/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static int bopen(struct r_bin_t *bin)
{
	if((bin->bin_obj = MALLOC_STRUCT(PE_(r_bin_pe_obj))) == NULL)
		return R_FALSE;

	if ((bin->fd = PE_(r_bin_pe_open)(bin->bin_obj, bin->file)) == -1) {
		free(bin->bin_obj);
		return R_FALSE;
	}

	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	return PE_(r_bin_pe_close)(bin->bin_obj);
}

static u64 baddr(struct r_bin_t *bin)
{
	return PE_(r_bin_pe_get_image_base)(bin->bin_obj);
}

static struct r_bin_entry_t* entry(struct r_bin_t *bin)
{
	struct r_bin_entry_t *ret;
	PE_(r_bin_pe_entrypoint) entry;

	if((ret = malloc(sizeof(struct r_bin_entry_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_entry_t));

	PE_(r_bin_pe_get_entrypoint)(bin->bin_obj, &entry);
	ret->offset = entry.offset;
	ret->rva = entry.rva;
	return ret;
}

static struct r_bin_section_t* sections(struct r_bin_t *bin)
{
	int sections_count, i;
	struct r_bin_section_t *ret = NULL;
	PE_(r_bin_pe_section) *section = NULL;

	sections_count = PE_(r_bin_pe_get_sections_count)(bin->bin_obj);

	if ((section = malloc(sections_count * sizeof(PE_(r_bin_pe_section)))) == NULL)
		return NULL;
	if ((ret = malloc((sections_count + 1) * sizeof(struct r_bin_section_t))) == NULL)
		return NULL;
	memset(ret, '\0', (sections_count + 1) * sizeof(struct r_bin_section_t));

	PE_(r_bin_pe_get_sections)(bin->bin_obj, section);

	for (i = 0; i < sections_count; i++) {
		strncpy(ret[i].name, (char*)section[i].name, R_BIN_SIZEOF_NAMES);
		ret[i].size = section[i].size;
		ret[i].vsize = section->vsize;
		ret[i].offset = section[i].offset;
		ret[i].rva = section[i].rva;
		ret[i].characteristics = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE(section[i].characteristics))
			ret[i].characteristics |= 0x1;
		if (R_BIN_PE_SCN_IS_WRITABLE(section[i].characteristics))
			ret[i].characteristics |= 0x2;
		if (R_BIN_PE_SCN_IS_READABLE(section[i].characteristics))
			ret[i].characteristics |= 0x4;
		if (R_BIN_PE_SCN_IS_SHAREABLE(section[i].characteristics))
			ret[i].characteristics |= 0x8;
		ret[i].last = 0;
	}
	ret[i].last = 1;

	free(section);
	return ret;
}

static struct r_bin_symbol_t* symbols(struct r_bin_t *bin)
{
	int symbols_count, i;
	struct r_bin_symbol_t *ret = NULL;
	PE_(r_bin_pe_export) *symbol = NULL;

	symbols_count = PE_(r_bin_pe_get_exports_count)(bin->bin_obj);

	if ((symbol = malloc(symbols_count * sizeof(PE_(r_bin_pe_export)))) == NULL)
		return NULL;
	if ((ret = malloc((symbols_count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;
	memset(ret, '\0', (symbols_count + 1) * sizeof(struct r_bin_symbol_t));

	PE_(r_bin_pe_get_exports)(bin->bin_obj, symbol);

	for (i = 0; i < symbols_count; i++) {
		strncpy(ret[i].name, (char*)symbol[i].name, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].forwarder, (char*)symbol[i].forwarder, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_NAMES);
		ret[i].rva = symbol[i].rva;
		ret[i].offset = symbol[i].offset;
		ret[i].size = 0;
		ret[i].ordinal = symbol[i].ordinal;
		ret[i].last = 0;
	}
	ret[i].last = 1;

	free(symbol);

	return ret;
}

static struct r_bin_import_t* imports(struct r_bin_t *bin)
{
	int imports_count, i;
	struct r_bin_import_t *ret = NULL;
	PE_(r_bin_pe_import) *import = NULL;

	imports_count = PE_(r_bin_pe_get_imports_count)(bin->bin_obj);

	if ((import = malloc(imports_count * sizeof(PE_(r_bin_pe_import)))) == NULL)
		return NULL;
	if ((ret = malloc((imports_count + 1) * sizeof(struct r_bin_import_t))) == NULL)
		return NULL;
	memset(ret, '\0', (imports_count + 1) * sizeof(struct r_bin_import_t));

	PE_(r_bin_pe_get_imports)(bin->bin_obj, import);

	for (i = 0; i < imports_count; i++) {
		strncpy(ret[i].name, (char*)import[i].name, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].bind, "NONE", R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].type, "NONE", R_BIN_SIZEOF_NAMES);
		ret[i].rva = import[i].rva;
		ret[i].offset = import[i].offset;
		ret[i].ordinal = import[i].ordinal;
		ret[i].hint = import[i].hint;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(import);
	return ret;
}

static struct r_bin_info_t* info(struct r_bin_t *bin)
{
	char pe_class_str[PE_NAME_LENGTH], pe_os_str[PE_NAME_LENGTH], pe_machine_str[PE_NAME_LENGTH];
	char pe_arch_str[PE_NAME_LENGTH], pe_subsystem_str[PE_NAME_LENGTH];
	struct r_bin_info_t *ret = NULL;

	if((ret = malloc(sizeof(struct r_bin_info_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_info_t));

		if (PE_(r_bin_pe_get_class)(bin->bin_obj, pe_class_str))
			strncpy(ret->class, pe_class_str, R_BIN_SIZEOF_NAMES);
		strncpy(ret->rclass, "pe", R_BIN_SIZEOF_NAMES);
		if (PE_(r_bin_pe_get_os)(bin->bin_obj, pe_os_str))
			strncpy(ret->os, pe_os_str, R_BIN_SIZEOF_NAMES);
		if (PE_(r_bin_pe_get_arch)(bin->bin_obj, pe_arch_str))
			strncpy(ret->arch, pe_arch_str, R_BIN_SIZEOF_NAMES);
		if (PE_(r_bin_pe_get_machine)(bin->bin_obj, pe_machine_str))
			strncpy(ret->machine, pe_machine_str, R_BIN_SIZEOF_NAMES);
		if (PE_(r_bin_pe_get_subsystem)(bin->bin_obj, pe_subsystem_str))
			strncpy(ret->subsystem, pe_subsystem_str, R_BIN_SIZEOF_NAMES);
		if (PE_(r_bin_pe_is_dll)(bin->bin_obj))
			strncpy(ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_NAMES);
		else
			strncpy(ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_NAMES);
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
struct r_bin_handle_t r_bin_plugin_pe = {
	.name = "bin_pe",
	.desc = "pe bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.baddr = &baddr,
	.entry = &entry,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.resize_section = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
#endif
