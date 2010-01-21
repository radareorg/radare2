/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int bopen(struct r_bin_t *bin)
{
	struct Elf_(r_bin_elf_obj_t)* elf_obj;
	if(!(bin->bin_obj = Elf_(r_bin_elf_new)(bin->file)))
		return -1;
	elf_obj = (struct Elf_(r_bin_elf_obj_t)*)bin->bin_obj; 
	bin->fd = 1;
	return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	Elf_(r_bin_elf_free)((struct Elf_(r_bin_elf_obj_t)*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(struct r_bin_t *bin)
{
	return Elf_(r_bin_elf_get_baddr)(bin->bin_obj);
}

static struct r_bin_entry_t* entry(struct r_bin_t *bin)
{
	struct r_bin_entry_t *ret = MALLOC_STRUCT(struct r_bin_entry_t);
	if (ret) {
		memset(ret, '\0', sizeof(struct r_bin_entry_t));
		ret->offset = ret->rva = \
			Elf_(r_bin_elf_get_entry_offset)(bin->bin_obj);
	}
	return ret;
}

static struct r_bin_section_t* sections(struct r_bin_t *bin)
{
	int sections_count, i;
	struct r_bin_section_t *ret = NULL;
	struct r_bin_elf_section_t *section = NULL;

	section = Elf_(r_bin_elf_get_sections)(bin->bin_obj);
	for (sections_count = 0; section && !section[sections_count].last; sections_count++);
	if ((ret = malloc((sections_count + 1) * sizeof(struct r_bin_section_t))) == NULL)
		return NULL;

	for (i = 0; i < sections_count; i++) {
		strncpy(ret[i].name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
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
	struct r_bin_elf_symbol_t *symbol = NULL;

	symbol = Elf_(r_bin_elf_get_symbols)(bin->bin_obj, R_BIN_ELF_SYMBOLS);
	for (symbols_count = 0; symbol && !symbol[symbols_count].last; symbols_count++);
	if ((ret = malloc((symbols_count + 1) * sizeof(struct r_bin_symbol_t))) == NULL)
		return NULL;

	for (i = 0; i < symbols_count; i++) {
		strncpy(ret[i].name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
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
	struct r_bin_elf_symbol_t *import = NULL;

	import = Elf_(r_bin_elf_get_symbols)(bin->bin_obj, R_BIN_ELF_IMPORTS);
	for (imports_count = 0; import && !import[imports_count].last; imports_count++);
	if ((ret = malloc((imports_count + 1) * sizeof(struct r_bin_import_t))) == NULL)
		return NULL;

	for (i = 0; i < imports_count; i++) {
		strncpy(ret[i].name, import[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].bind, import[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy(ret[i].type, import[i].type, R_BIN_SIZEOF_STRINGS);
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
	char *str;

	if((ret = malloc(sizeof(struct r_bin_info_t))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(struct r_bin_info_t));

	if ((str = Elf_(r_bin_elf_get_file_type)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->type, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	if ((str = Elf_(r_bin_elf_get_elf_class)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->class, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	if ((str = Elf_(r_bin_elf_get_osabi_name)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->os, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	if ((str = Elf_(r_bin_elf_get_osabi_name)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	if ((str = Elf_(r_bin_elf_get_machine_name)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->machine, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	if ((str = Elf_(r_bin_elf_get_arch)(bin->bin_obj)) == NULL)
		return NULL;
	strncpy(ret->arch, str, R_BIN_SIZEOF_STRINGS);
	free(str);

	strncpy(ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->big_endian=Elf_(r_bin_elf_is_big_endian)(bin->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped)(bin->bin_obj)) {
		ret->dbg_info |= 0x04;
		ret->dbg_info |= 0x08;
		ret->dbg_info |= 0x10;
	} else  ret->dbg_info |= 0x01;
	if (Elf_(r_bin_elf_get_static)(bin->bin_obj))
		ret->dbg_info |= 0x02;
	return ret;
}

static struct r_bin_field_t* fields(struct r_bin_t *bin)
{
	struct r_bin_field_t *ret = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i, count;
	
	field = Elf_(r_bin_elf_get_fields)(bin->bin_obj);
	for (count = 0; field && !field[count].last; count++);
	if ((ret = malloc((count + 1) * sizeof(struct r_bin_field_t))) == NULL)
		return NULL;
	for (i = 0; i < count; i++) {
		strncpy(ret[i].name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ret[i].rva = field[i].offset;
		ret[i].offset = field[i].offset;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	free(field);
	return ret;
}

#if !R_BIN_ELF64
static int check(struct r_bin_t *bin)
{
	int ret = R_FALSE;
	ut8 buf[8];

	if ((bin->fd = open(bin->file, 0)) != -1) {
		lseek(bin->fd, 0, SEEK_SET);
		read(bin->fd, buf, 8);
		close(bin->fd);
		/* buf[EI_CLASS] == ELFCLASS32 */
		if (!memcmp(buf, "\x7F\x45\x4c\x46\x01", 5))
			ret = R_TRUE;
	}
	return ret;
}

struct r_bin_handle_t r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
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
	.fields = &fields,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
