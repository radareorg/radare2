/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int load(RBin *bin) {
	if(!(bin->bin_obj = Elf_(r_bin_elf_new) (bin->file)))
		return R_FALSE;
	bin->size = ((struct Elf_(r_bin_elf_obj_t)*) (bin->bin_obj))->size;
	bin->buf = ((struct Elf_(r_bin_elf_obj_t)*) (bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBin *bin) {
	return Elf_(r_bin_elf_get_baddr) (bin->bin_obj);
}

static RBinAddr* binmain(RBin *bin) {
	RBinAddr *ret = NULL;

	if (!(ret = R_NEW (RBinAddr)))
		return NULL;
	memset (ret, '\0', sizeof (RBinAddr));
	ret->offset = ret->rva = Elf_(r_bin_elf_get_main_offset) (bin->bin_obj);
	return ret;
}

static RList* entries(RBin *bin) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW (RBinAddr)))
		return ret;
	memset (ptr, '\0', sizeof (RBinAddr));
	ptr->offset = ptr->rva = Elf_(r_bin_elf_get_entry_offset) (bin->bin_obj);
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBin *bin) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(section = Elf_(r_bin_elf_get_sections) (bin->bin_obj)))
		return ret;
	for (i = 0; !section[i].last; i++) {
		if (!(ptr = R_NEW (RBinSection)))
			break;
		strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = section[i].size;
		ptr->vsize = section[i].size;
		ptr->offset = section[i].offset;
		ptr->rva = section[i].rva;
		ptr->srwx = 0;
		if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags))
			ptr->srwx |= 1;
		if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags))
			ptr->srwx |= 2;
		if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags))
			ptr->srwx |= 4;
		r_list_append (ret, ptr);
	}
	free (section);
	return ret;
}

static RList* symbols(RBin *bin) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_elf_symbol_t *symbol = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (bin->bin_obj, R_BIN_ELF_SYMBOLS)))
		return ret;
	for (i = 0; !symbol[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = symbol[i].offset;
		ptr->offset = symbol[i].offset;
		ptr->size = symbol[i].size;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
	free (symbol);
	return ret;
}

static RList* imports(RBin *bin) {
	RList *ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_elf_symbol_t *import = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(import = Elf_(r_bin_elf_get_symbols) (bin->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !import[i].last; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;
		strncpy (ptr->name, import[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, import[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, import[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = import[i].offset;
		ptr->offset = import[i].offset;
		ptr->ordinal = 0;
		ptr->hint = 0;
		r_list_append (ret, ptr);
	}
	free (import);
	return ret;
}

static RList* libs(RBin *bin) {
	RList *ret = NULL;
	char *ptr = NULL;
	struct r_bin_elf_lib_t *libs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = Elf_(r_bin_elf_get_libs) (bin->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RBinInfo* info(RBin *bin) {
	RBinInfo *ret = NULL;
	char *str;

	if(!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, bin->file, R_BIN_SIZEOF_STRINGS);
	if ((str = Elf_(r_bin_elf_get_rpath)(bin->bin_obj))) {
		strncpy (ret->rpath, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	} else strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
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
	ret->bits = Elf_(r_bin_elf_get_bits) (bin->bin_obj);
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

static RList* fields(RBin *bin) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;
	
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (bin->bin_obj)))
		return ret;
	for (i = 0; !field[i].last; i++) {
		if (!(ptr = R_NEW (RBinField)))
			break;
		strncpy (ptr->name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->rva = field[i].offset;
		ptr->offset = field[i].offset;
		r_list_append (ret, ptr);
	}
	free (field);
	return ret;
}

#if !R_BIN_ELF64
static int check(RBin *bin) {
	ut8 *buf;
	int n, ret = R_FALSE;

	if ((buf = (ut8*)r_file_slurp_range (bin->file, 0, 5, &n))) {
		/* buf[EI_CLASS] == ELFCLASS32 */
		if (n == 5)
		if (!memcmp (buf, "\x7F\x45\x4c\x46\x01", 5))
			ret = R_TRUE;
		free (buf);
	}
	return ret;
}

extern struct r_bin_meta_t r_bin_meta_elf;
extern struct r_bin_write_t r_bin_write_elf;

struct r_bin_plugin_t r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.main = &binmain,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.libs = &libs,
	.meta = &r_bin_meta_elf,
	.write = &r_bin_write_elf,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
