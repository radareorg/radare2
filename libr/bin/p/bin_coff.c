/* radare - LGPL - Copyright 2014 - Fedor Sakharov */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff/coff.h"

static int load(RBinFile *arch)
{
	if (!(arch->o->bin_obj = r_bin_coff_new_buf(arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinFile *arch)
{
	r_bin_coff_free((struct r_bin_coff_obj*)arch->o->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch)
{
	return 0;
}

static RBinAddr *binsym(RBinFile *arch, int sym)
{
	return NULL;
}

static RList *entries(RBinFile *arch)
{
	size_t i;
	RList *ret;
	RBinAddr *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	if (!(ret = r_list_new ()))
		return NULL;

	ret->free = free;

	if (!(ptr = R_NEW (RBinAddr)))
		return ret;

	memset (ptr, '\0', sizeof (RBinAddr));

	if (obj->hdr.opt_hdr_size) {
		ptr->offset = ptr->rva = obj->opt_hdr.entry_point;
	} else {
		for (i = 0; i < obj->hdr.sections_num; i++) {
			if (!strcmp(obj->scn_hdrs[i].name, ".text")) {
				ptr->offset = obj->scn_hdrs[i].virtual_addr;
				ptr->rva = obj->scn_hdrs[i].virtual_addr;
				break;
			}
		}
	}

	r_list_append(ret, ptr);

	return ret;
}

static RList *sections(RBinFile *arch)
{
	size_t i;
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	ret = r_list_new();

	if (!ret)
		return NULL;

	for (i = 0; i < obj->hdr.sections_num; i++) {
		ptr = R_NEW0 (RBinSection);

		strncpy(ptr->name, obj->scn_hdrs[i].name, R_BIN_SIZEOF_STRINGS); 

		ptr->size = obj->scn_hdrs[i].raw_data_size;
		ptr->vsize = obj->scn_hdrs[i].virtual_size;
		ptr->offset = obj->scn_hdrs[i].raw_data_pointer;
		ptr->rva = obj->scn_hdrs[i].virtual_addr;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList *symbols(RBinFile *arch)
{
	size_t i;
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;

	struct r_bin_coff_obj *obj= (struct r_bin_coff_obj*)arch->o->bin_obj;

	if (!(ret = r_list_new()))
		return ret;

	ret->free = free;

	for (i = 0; i < obj->hdr.symbols_num; i++) {
		if (!(ptr = R_NEW0 (RBinSymbol)))
			break;

		strncpy (ptr->name, obj->symbols[i].name,
				R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE",
				R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "UNKNOWN", R_BIN_SIZEOF_STRINGS);
		ptr->rva = obj->symbols[i].value;
		ptr->offset = obj->symbols[i].value;
		ptr->size = 0;
		ptr->ordinal = 0;

		r_list_append (ret, ptr);

		i += obj->symbols[i].aux_sym_num;
	}

	return ret;
}

static RList *imports(RBinFile *arch)
{
	return NULL;
}

static RList *libs(RBinFile *arch)
{
	return NULL;
}

static RList *relocs(RBinFile *arch)
{
	return NULL;
}

static RBinInfo *info(RBinFile *arch)
{
	RBinInfo *ret = R_NEW0(RBinInfo);
	ret->has_va = 1;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	ret->big_endian = obj->endian;
	ret->dbg_info = 0;

	switch (obj->hdr.machine) {
	case IMAGE_FILE_MACHINE_I386:
		strncpy(ret->machine, "i386", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
		ret->bits = 32;
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		strncpy(ret->machine, "AMD 64", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
		ret->bits = 64;
		break;
	case IMAGE_FILE_MACHINE_H8300:
		strncpy(ret->machine, "H8300", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "h8300", R_BIN_SIZEOF_STRINGS);
		ret->bits = 16;
		break;

	case IMAGE_FILE_TI_COFF:
		if (obj->hdr.target_id == IMAGE_FILE_MACHINE_TMS320C54) {
			strncpy(ret->machine, "c54x", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		} else if (obj->hdr.target_id == IMAGE_FILE_MACHINE_TMS320C55) {
			strncpy(ret->machine, "c55x", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		} else if (obj->hdr.target_id == IMAGE_FILE_MACHINE_TMS320C55PLUS) {
			strncpy(ret->machine, "c55x+", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		}
		break;
	default:
		strncpy(ret->machine, "unknown", R_BIN_SIZEOF_STRINGS);
	}

	return ret;
}

static RList *fields(RBinFile *arch)
{
	return NULL;
}

static RBuffer *create(RBin *bin, const ut8 *code, int codelen,
		const ut8 *data, int datalen)
{
	return NULL;
}

static int size(RBinFile *arch)
{
	return 0;
}

static int check(RBinFile *arch)
{
	if (arch && arch->buf && arch->buf->buf) {
		if (coff_supported_arch(arch->buf->buf))
			return R_TRUE;
	}
	return R_FALSE;
}

RBinPlugin r_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = NULL,
	.create = &create,
	.write = NULL,
	.get_vaddr = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_coff
};
#endif
