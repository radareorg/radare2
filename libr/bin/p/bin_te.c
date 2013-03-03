/* radare - LGPL - Copyright 2009-2013 - nibble, pancake, xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "te/te_specs.h"
#include "te/te.h"

static int load(RBinArch *arch) {
	if(!(arch->bin_obj = r_bin_te_new_buf (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	r_bin_te_free ((struct r_bin_te_obj_t*)arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return r_bin_te_get_image_base (arch->bin_obj);
}

static RBinAddr* binsym(RBinArch *arch, int type) {
	RBinAddr *ret = NULL;
	switch (type) {
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW (RBinAddr)))
			return NULL;
		memset (ret, '\0', sizeof (RBinAddr));
		ret->offset = ret->rva = r_bin_te_get_main_offset (arch->bin_obj);
		break;
	}
	return ret;
}

static RList* entries(RBinArch *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;
	struct r_bin_te_addr_t *entry = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(entry = r_bin_te_get_entrypoint (arch->bin_obj)))
		return ret;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->offset = entry->offset;
		ptr->rva = entry->rva;
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_te_section_t *sections = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(sections = r_bin_te_get_sections(arch->bin_obj)))
		return NULL;
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW (RBinSection)))
			break;
		strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->offset = sections[i].offset;
		ptr->rva = sections[i].rva;
		ptr->srwx = 0;
		if (R_BIN_TE_SCN_IS_EXECUTABLE (sections[i].flags))
			ptr->srwx |= 0x1;
		if (R_BIN_TE_SCN_IS_WRITABLE (sections[i].flags))
			ptr->srwx |= 0x2;
		if (R_BIN_TE_SCN_IS_READABLE (sections[i].flags))
			ptr->srwx |= 0x4;
		if (R_BIN_TE_SCN_IS_SHAREABLE (sections[i].flags))
			ptr->srwx |= 0x8;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	char *str;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "TE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "te", R_BIN_SIZEOF_STRINGS);
	if ((str = r_bin_te_get_os (arch->bin_obj))) {
		strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = r_bin_te_get_arch (arch->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = r_bin_te_get_machine (arch->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = r_bin_te_get_subsystem (arch->bin_obj))) {
		strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->bits = r_bin_te_get_bits (arch->bin_obj);
	ret->big_endian = 1;
	ret->dbg_info = 0;
	ret->has_va = R_TRUE;
	return ret;
}

static int check(RBinArch *arch) {
	if (arch && arch->buf && arch->buf->buf)
	if (!memcmp (arch->buf->buf, "\x56\x5a", 2))
		return R_TRUE;
	return R_FALSE;
}

struct r_bin_plugin_t r_bin_plugin_te = {
	.name = "te",
	.desc = "TE bin plugin", // Terse Executable format
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = NULL, // TE doesn't have exports data directory
	.imports = NULL, // TE doesn't have imports data directory
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL, // TE doesn't have imports data directory
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.minstrlen = 4,
	.create = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_te
};
#endif
