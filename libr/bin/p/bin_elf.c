/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int load(RBinArch *arch) {
	if(!(arch->bin_obj = Elf_(r_bin_elf_new_buf) (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return Elf_(r_bin_elf_get_baddr) (arch->bin_obj);
}

static RBinAddr* binmain(RBinArch *arch) {
	RBinAddr *ret = NULL;

	if (!(ret = R_NEW (RBinAddr)))
		return NULL;
	memset (ret, '\0', sizeof (RBinAddr));
	ret->offset = ret->rva = Elf_(r_bin_elf_get_main_offset) (arch->bin_obj);
	return ret;
}

static RList* entries(RBinArch *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW (RBinAddr)))
		return ret;
	memset (ptr, '\0', sizeof (RBinAddr));
	ptr->offset = ptr->rva = Elf_(r_bin_elf_get_entry_offset) (arch->bin_obj);
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(section = Elf_(r_bin_elf_get_sections) (arch->bin_obj)))
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

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_elf_symbol_t *symbol = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (arch->bin_obj, R_BIN_ELF_SYMBOLS)))
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
		ptr->ordinal = symbol[i].ordinal;
		r_list_append (ret, ptr);
	}
	free (symbol);
	return ret;
}

static RList* imports(RBinArch *arch) {
	RList *ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_elf_symbol_t *import = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(import = Elf_(r_bin_elf_get_symbols) (arch->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !import[i].last; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;
		strncpy (ptr->name, import[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, import[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, import[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = import[i].offset;
		ptr->offset = import[i].offset;
		ptr->size = import[i].size;
		ptr->ordinal = import[i].ordinal;
		ptr->hint = 0;
		r_list_append (ret, ptr);
	}
	free (import);
	return ret;
}

static RList* libs(RBinArch *arch) {
	RList *ret = NULL;
	char *ptr = NULL;
	struct r_bin_elf_lib_t *libs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = Elf_(r_bin_elf_get_libs) (arch->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RList* relocs(RBinArch *arch) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	struct r_bin_elf_reloc_t *relocs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(relocs = Elf_(r_bin_elf_get_relocs) (arch->bin_obj)))
		return ret;
	for (i = 0; !relocs[i].last; i++) {
		if (!(ptr = R_NEW (RBinReloc)))
			break;
		strncpy (ptr->name, relocs[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->rva = relocs[i].offset;
		ptr->offset = relocs[i].offset;
		ptr->type = relocs[i].type;
		ptr->sym = relocs[i].sym;
		r_list_append (ret, ptr);
	}
	free (relocs);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	char *str;

	if(!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	if ((str = Elf_(r_bin_elf_get_rpath)(arch->bin_obj))) {
		strncpy (ret->rpath, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	} else strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if ((str = Elf_(r_bin_elf_get_file_type) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_elf_class) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_osabi_name) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_osabi_name) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_machine_name) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if ((str = Elf_(r_bin_elf_get_arch) (arch->bin_obj)) == NULL)
		return NULL;
	strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	strncpy (ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->bits = Elf_(r_bin_elf_get_bits) (arch->bin_obj);
	ret->big_endian=Elf_(r_bin_elf_is_big_endian) (arch->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (arch->bin_obj)) {
		ret->dbg_info |= 0x04;
		ret->dbg_info |= 0x08;
		ret->dbg_info |= 0x10;
	} else  ret->dbg_info |= 0x01;
	if (Elf_(r_bin_elf_get_static) (arch->bin_obj))
		ret->dbg_info |= 0x02;
	return ret;
}

static RList* fields(RBinArch *arch) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;
	
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (arch->bin_obj)))
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
static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "\x7F\x45\x4c\x46\x01", 5))
		return R_TRUE;
	return R_FALSE;
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
	.relocs = &relocs,
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
