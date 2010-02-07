/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static int load(RBin *bin)
{
	if(!(bin->bin_obj = PE_(r_bin_pe_new) (bin->file)))
		return R_FALSE;
	bin->size = ((struct PE_(r_bin_pe_obj_t)*) (bin->bin_obj))->size;
	bin->buf = ((struct PE_(r_bin_pe_obj_t)*) (bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy (RBin *bin)
{
	PE_(r_bin_pe_free) ((struct PE_(r_bin_pe_obj_t)*)bin->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBin *bin)
{
	return PE_(r_bin_pe_get_image_base) (bin->bin_obj);
}

static struct r_bin_entry_t* entry(RBin *bin)
{
	RArray ret;
	RBinEntry *tmp = NULL;
	struct r_bin_pe_entrypoint_t *entry = NULL;

	if (!(entry = PE_(r_bin_pe_get_entrypoint) (bin->bin_obj)))
		return NULL;
	if ((ret = !r_array_new (1)))
		return NULL;
	if (!(tmp = MALLOC_STRUCT (RBinEntry)))
		return ret;
	tmp->offset = entry->offset;
	tmp->rva = entry->rva;
	r_array_set (ret, 0, tmp);
	free (entry);
	return ret;
}

static RArray sections(RBin *bin)
{
	RArray ret = NULL;
	RBinSection *tmp = NULL;
	struct r_bin_pe_section_t *sections = NULL;
	int i, count;
	
	if (!(sections = PE_(r_bin_pe_get_sections)(bin->bin_obj)))
		return NULL;
	for (count = 0; !sections[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (sections);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinSection)))
			break;
		strncpy (tmp->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		tmp->size = sections[i].size;
		tmp->vsize = sections[i].vsize;
		tmp->offset = sections[i].offset;
		tmp->rva = sections[i].rva;
		tmp->characteristics = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].characteristics))
			tmp->characteristics |= 0x1;
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].characteristics))
			tmp->characteristics |= 0x2;
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].characteristics))
			tmp->characteristics |= 0x4;
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].characteristics))
			tmp->characteristics |= 0x8;
		r_array_set (ret, i, tmp);
	}
	free (sections);
	return ret;
}

static RArray symbols(RBin *bin)
{
	RArray ret = NULL;
	RBinSymbol *tmp = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	int i, count;

	if (!(symbols = PE_(r_bin_pe_get_exports)(bin->bin_obj)))
		return NULL;
	for (count = 0; !symbols[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (symbols);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinSymbol)))
			break;
		strncpy (tmp->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->forwarder, (char*)symbols[i].forwarder, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->type, "NONE", R_BIN_SIZEOF_STRINGS);
		tmp->rva = symbols[i].rva;
		tmp->offset = symbols[i].offset;
		tmp->size = 0;
		tmp->ordinal = symbols[i].ordinal;
		r_array_set (ret, i, tmp);
	}
	free (symbols);
	return ret;
}

static RArray imports(RBin *bin)
{
	RArray ret = NULL;
	RBinImport *tmp = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i, count;

	if (!(imports = PE_(r_bin_pe_get_imports)(bin->bin_obj)))
		return NULL;
	for (count = 0; !imports[count].last; count++);
	if (!(ret = r_array_new (count))) {
		free (import);
		return NULL;
	}
	for (i = 0; i < count; i++) {
		if (!(tmp = MALLOC_STRUCT (RBinImport)))
			break;
		strncpy (tmp->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (tmp->type, "NONE", R_BIN_SIZEOF_STRINGS);
		tmp->rva = imports[i].rva;
		tmp->offset = imports[i].offset;
		tmp->ordinal = imports[i].ordinal;
		tmp->hint = imports[i].hint;
		r_array_set (ret, i, tmp);
	}
	free (imports);
	return ret;
}

static RBinInfo* info(RBin *bin)
{
	char *str;
	RBinInfo *ret = NULL;

	if((ret = MALLOC_STRUCT (RBinInfo)) == NULL)
		return NULL;
	if ((str = PE_(r_bin_pe_get_class) (bin->bin_obj))) {
		strncpy (ret->class, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy(ret->rclass, "pe", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_os) (bin->bin_obj))) {
		strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_arch) (bin->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_machine) (bin->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_subsystem) (bin->bin_obj))) {
		strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if (PE_(r_bin_pe_is_dll) (bin->bin_obj))
		strncpy (ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_STRINGS);
	else strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->big_endian = PE_(r_bin_pe_is_big_endian) (bin->bin_obj);
	ret->dbg_info = 0;
	if (!PE_(r_bin_pe_is_stripped_debug) (bin->bin_obj))
		ret->dbg_info |= 0x01;
	if (PE_(r_bin_pe_is_stripped_line_nums) (bin->bin_obj))
		ret->dbg_info |= 0x04;
	if (PE_(r_bin_pe_is_stripped_local_syms) (bin->bin_obj))
		ret->dbg_info |= 0x08;
	if (PE_(r_bin_pe_is_stripped_relocs) (bin->bin_obj))
		ret->dbg_info |= 0x10;
	return ret;
}

#if !R_BIN_PE64
static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 1024)))
		return R_FALSE;
	if (!memcmp (buf, "\x4d\x5a", 2) &&
		!memcmp (buf+(buf[0x3c]|(buf[0x3d]<<8)), "\x50\x45", 2) && 
		!memcmp (buf+(buf[0x3c]|buf[0x3d]<<8)+0x18, "\x0b\x01", 2))
		ret = R_TRUE;
	free (buf);
	return ret;
}

struct r_bin_handle_t r_bin_plugin_pe = {
	.name = "pe",
	.desc = "PE bin plugin",
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
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
#endif
