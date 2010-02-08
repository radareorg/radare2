/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int load(RBin *bin)
{
	if(!(bin->bin_obj = Elf_(r_bin_elf_new) (bin->file)))
		return R_FALSE;
	bin->size = ((struct Elf_(r_bin_elf_obj_t)*) (bin->bin_obj))->size;
	bin->buf = ((struct Elf_(r_bin_elf_obj_t)*) (bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin)
{
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBin *bin)
{
	return Elf_(r_bin_elf_get_baddr) (bin->bin_obj);
}

static RArray entries(RBin *bin)
{
	RArray ret;
	RBinEntry *ptr = NULL;

	if (!(ret = r_array_new (1)))
		return NULL;
	if (!(ptr = MALLOC_STRUCT (RBinEntry)))
		return ret;
	memset (ptr, '\0', sizeof (RBinEntry));
	ptr->offset = ptr->rva = Elf_(r_bin_elf_get_entry_offset) (bin->bin_obj);
	r_array_set (ret, 0, ptr);
	return ret;
}

static RArray sections(RBin *bin)
{
	int sections_count, i;
	RArray ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;

	if (!(section = Elf_(r_bin_elf_get_sections) (bin->bin_obj)))
		return NULL;
	for (sections_count = 0; !section[sections_count].last; sections_count++);
	if (!(ret = r_array_new (sections_count))) {
		free (section);
		return NULL;
	}
	for (i = 0; i < sections_count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinSection)))
			break;
		strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = section[i].size;
		ptr->vsize = section[i].size;
		ptr->offset = section[i].offset;
		ptr->rva = section[i].offset;
		ptr->characteristics = 0;
		if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags))
			ptr->characteristics |= 0x1;
		if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags))
			ptr->characteristics |= 0x2;
		if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags))
			ptr->characteristics |= 0x4;
		r_array_set (ret, i, ptr);
	}
	free (section);
	return ret;
}

static RArray symbols(RBin *bin)
{
	int symbols_count, i;
	RArray ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_elf_symbol_t *symbol = NULL;

	if (!(symbol = Elf_(r_bin_elf_get_symbols) (bin->bin_obj, R_BIN_ELF_SYMBOLS)))
		return NULL;
	for (symbols_count = 0; !symbol[symbols_count].last; symbols_count++);
	if (!(ret = r_array_new (symbols_count))) {
		free (symbol);
		return NULL;
	}
	for (i = 0; i < symbols_count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinSymbol)))
			break;
		strncpy (ptr->name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = symbol[i].offset;
		ptr->offset = symbol[i].offset;
		ptr->size = symbol[i].size;
		ptr->ordinal = 0;
		r_array_set (ret, i, ptr);
	}
	free (symbol);
	return ret;
}

static RArray imports(RBin *bin)
{
	int imports_count, i;
	RArray ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_elf_symbol_t *import = NULL;

	if (!(import = Elf_(r_bin_elf_get_symbols) (bin->bin_obj, R_BIN_ELF_IMPORTS)))
		return NULL;
	for (imports_count = 0; !import[imports_count].last; imports_count++);
	if (!(ret = r_array_new (imports_count))) {
		free (import);
		return NULL;
	}
	for (i = 0; i < imports_count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinImport)))
			break;
		strncpy(ptr->name, import[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy(ptr->bind, import[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy(ptr->type, import[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = import[i].offset;
		ptr->offset = import[i].offset;
		ptr->ordinal = 0;
		ptr->hint = 0;
		r_array_set (ret, i, ptr);
	}
	free (import);
	return ret;
}

static RBinInfo* info(RBin *bin)
{
	struct r_bin_info_t *ret = NULL;
	char *str;

	if(!(ret = MALLOC_STRUCT (RBinInfo)))
		return NULL;
	memset(ret, '\0', sizeof (RBinInfo));
	if ((str = Elf_(r_bin_elf_get_file_type) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_elf_class) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_osabi_name) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_osabi_name) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_machine_name) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_arch) (bin->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	strncpy (ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->big_endian=Elf_(r_bin_elf_is_big_endian) (bin->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (bin->bin_obj)) {
		ret->dbg_info |= 0x04;
		ret->dbg_info |= 0x08;
		ret->dbg_info |= 0x10;
	} else  ret->dbg_info |= 0x01;
	if (Elf_(r_bin_elf_get_static) (bin->bin_obj))
		ret->dbg_info |= 0x02;
	return ret;
}

static RArray fields(RBin *bin)
{
	RArray ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i, fields_count;
	
	if (!(field = Elf_(r_bin_elf_get_fields) (bin->bin_obj)))
		return NULL;
	for (fields_count = 0; !field[fields_count].last; fields_count++);
	if (!(ret = r_array_new (fields_count))) {
		free (field);
		return NULL;
	}
	for (i = 0; i < fields_count; i++) {
		if (!(ptr = MALLOC_STRUCT (RBinField)))
			break;
		strncpy (ptr->name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->rva = field[i].offset;
		ptr->offset = field[i].offset;
		r_array_set (ret, i, ptr);
	}
	free (field);
	return ret;
}

#if !R_BIN_ELF64
static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 5)))
		return R_FALSE;
	/* buf[EI_CLASS] == ELFCLASS32 */
	if (!memcmp (buf, "\x7F\x45\x4c\x46\x01", 5))
		ret = R_TRUE;
	free (buf);
	return ret;
}

struct r_bin_handle_t r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
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
	.fields = &fields,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
