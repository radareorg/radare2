/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int bopen(struct r_bin_t *bin)
{
	if((bin->bin_obj = MALLOC_STRUCT(ELF_(r_bin_elf_obj))) == NULL)
		return R_FALSE;

	if ((bin->fd = ELF_(r_bin_elf_open)(bin->bin_obj,bin->file,bin->rw)) == -1) {
		free(bin->bin_obj);
		return R_FALSE;
	}

	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	return ELF_(r_bin_elf_close)(bin->bin_obj);
}

static u64 baddr(struct r_bin_t *bin)
{
	return ELF_(r_bin_elf_get_base_addr)(bin->bin_obj);
}

static struct r_bin_entry_t* entry(struct r_bin_t *bin)
{
	struct r_bin_entry_t *ret = NULL;

	if((ret = MALLOC_STRUCT(struct r_bin_entry_t)) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_entry_t));

	ret->offset = ret->rva = ELF_(r_bin_elf_get_entry_offset)(bin->bin_obj);
	return ret;
}

static struct r_bin_section_t* sections(struct r_bin_t *bin)
{
	int sections_count, i;
	struct r_bin_section_t *ret = NULL;
	r_bin_elf_section *section = NULL;

	sections_count = ELF_(r_bin_elf_get_sections_count)(bin->bin_obj);

	if((section = malloc(sections_count * sizeof(r_bin_elf_section))) == NULL)
		return NULL;
	if((ret = malloc((sections_count + 1) * sizeof(struct r_bin_section_t))) == NULL)
		return NULL;
	memset(ret, '\0', (sections_count + 1) * sizeof(struct r_bin_section_t));

	ELF_(r_bin_elf_get_sections)(bin->bin_obj,section);

	for (i = 0; i < sections_count; i++) {
		strncpy(ret[i].name, (char*)section[i].name, R_BIN_SIZEOF_NAMES);
		ret[i].size = section[i].size;
		ret[i].vsize = section[i].size;
		ret[i].offset = section[i].offset;
		ret[i].rva = section[i].offset;
		ret[i].characteristics = 0;
		if (R_BIN_ELF_SCN_IS_EXECUTABLE(section[i].flags))
			ret[i].characteristics |= 0x1;
		if (R_BIN_ELF_SCN_IS_WRITABLE(section[i].flags))
			ret[i].characteristics |= 0x2;
		if (R_BIN_ELF_SCN_IS_READABLE(section[i].flags))
			ret[i].characteristics |= 0x4;
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
	r_bin_elf_symbol *symbol = NULL;

	symbols_count = ELF_(r_bin_elf_get_symbols_count)(bin->bin_obj);

	if ((symbol = malloc(symbols_count * sizeof(r_bin_elf_symbol))) == NULL)
		return NULL;
	if ((ret = malloc((symbols_count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;
	memset(ret, '\0', (symbols_count + 1) * sizeof(struct r_bin_symbol_t));

	ELF_(r_bin_elf_get_symbols)(bin->bin_obj,symbol);

	for (i = 0; i < symbols_count; i++) {
		strncpy(ret[i].name, symbol[i].name, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].forwarder, "NONE", R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].bind, symbol[i].bind, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].type, symbol[i].type, R_BIN_SIZEOF_NAMES);
		ret[i].rva = symbol[i].offset;
		ret[i].offset = symbol[i].offset;
		ret[i].size = symbol[i].size;
		ret[i].ordinal = 0;
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
	r_bin_elf_import *import = NULL;

	imports_count = ELF_(r_bin_elf_get_imports_count)(bin->bin_obj);

	if ((import = malloc(imports_count * sizeof(r_bin_elf_import))) == NULL)
		return NULL;
	if ((ret = malloc((imports_count + 1) * sizeof(struct r_bin_import_t))) == NULL)
		return NULL;
	memset(ret, '\0', (imports_count + 1) * sizeof(struct r_bin_import_t));

	ELF_(r_bin_elf_get_imports)(bin->bin_obj,import);

	for (i = 0; i < imports_count; i++) {
		strncpy(ret[i].name, import[i].name, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].bind, import[i].bind, R_BIN_SIZEOF_NAMES);
		strncpy(ret[i].type, import[i].type, R_BIN_SIZEOF_NAMES);
		ret[i].rva = import[i].offset;
		ret[i].offset = import[i].offset;
		ret[i].ordinal = 0;
		ret[i].hint = 0;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(import);
	return ret;
}

static struct r_bin_info_t* info(struct r_bin_t *bin)
{
	struct r_bin_info_t *ret = NULL;

	if((ret = malloc(sizeof(struct r_bin_info_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_info_t));

	strncpy(ret->type, ELF_(r_bin_elf_get_file_type)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	strncpy(ret->class, ELF_(r_bin_elf_get_elf_class)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	strncpy(ret->rclass, "elf", R_BIN_SIZEOF_NAMES);
	strncpy(ret->os, ELF_(r_bin_elf_get_osabi_name)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	strncpy(ret->subsystem, ELF_(r_bin_elf_get_osabi_name)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	strncpy(ret->machine, ELF_(r_bin_elf_get_machine_name)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	strncpy(ret->arch, ELF_(r_bin_elf_get_arch)(bin->bin_obj), R_BIN_SIZEOF_NAMES);
	ret->big_endian=ELF_(r_bin_elf_is_big_endian)(bin->bin_obj);
	ret->dbg_info = 0;
	if (ELF_(r_bin_elf_get_stripped)(bin->bin_obj)) {
		ret->dbg_info |= 0x01;
	} else {
		ret->dbg_info |= 0x04;
		ret->dbg_info |= 0x08;
		ret->dbg_info |= 0x10;
	}
	if (ELF_(r_bin_elf_get_static)(bin->bin_obj))
		ret->dbg_info |= 0x02;
	return ret;
}

static u64 resize_section(struct r_bin_t *bin, char *name, u64 size)
{
	return ELF_(r_bin_elf_resize_section)(bin->bin_obj, name, size);
}

#if !R_BIN_ELF64
static int check(struct r_bin_t *bin)
{
	u8 buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1)
		return R_FALSE;
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);
	close(bin->fd);

	if (!memcmp(buf, "\x7F\x45\x4c\x46", 4) &&
		buf[4] == 1)  /* buf[EI_CLASS] == ELFCLASS32 */
		return R_TRUE;
	
	return R_FALSE;
}

struct r_bin_handle_t r_bin_plugin_elf = {
	.name = "bin_elf",
	.desc = "elf bin plugin",
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
	.resize_section = &resize_section
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
