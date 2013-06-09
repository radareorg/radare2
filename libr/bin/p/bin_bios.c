/* radare - LGPL - Copyright 2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check(RBinArch *arch);

static int load(RBinArch *arch) {
	if (check (arch))
		return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinArch *arch) {
	//r_bin_bios_free ((struct r_bin_bios_obj_t*)arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinArch *arch) {
	return NULL;
}

static RBinInfo* info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	ret->lang = NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "bios", sizeof (ret->type)-1); // asm.arch
	strncpy (ret->bclass, "1.0", sizeof (ret->bclass)-1);
	strncpy (ret->rclass, "bios", sizeof (ret->rclass)-1); // file.type
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strncpy (ret->subsystem, "unknown", sizeof (ret->subsystem)-1);
	strncpy (ret->machine, "pc", sizeof (ret->machine)-1);
	strcpy (ret->arch, "x86");
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinArch *arch) {
	const ut32 ep = 0x0007fff0;
	if (arch->buf && arch->buf->length > ep) {
		if (arch->buf->buf[0] == 0xff)
			if (arch->buf->buf[ep] != 0xff)
				return 1;
	}
	return 0;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	// program headers is another section
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "bootblk");
	ptr->vsize = ptr->size = 0x10000;
	ptr->offset = arch->buf->length - ptr->size;
	ptr->rva = 0xf0000;
	ptr->srwx = 7;
	r_list_append (ret, ptr);
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
	ptr->offset = ptr->rva = 0xffff0;
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_bios = {
	.name = "bios",
	.desc = "filesystem bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = NULL,
	.entries = entries,
	.sections = sections,
	.symbols = NULL,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.demangle_type = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bios
};
#endif
