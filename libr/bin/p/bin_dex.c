/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "dex/dex.h"

static int load(RBinArch *arch) {
	if(!(arch->bin_obj = r_bin_dex_new_buf(arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return 0;
}

static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "dex\n035\0", 8))
		return R_TRUE;
	else if (!memcmp (arch->buf->buf, "dex\n009\0", 8)) // M3 (Nov-Dec 07)
		return R_TRUE;
	else if (!memcmp (arch->buf->buf, "dex\n009\0", 8)) // M5 (Feb-Mar 08)
		return R_TRUE;
	return R_FALSE;
}

static RBinInfo * info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	char *version;

	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "DEX CLASS", R_BIN_SIZEOF_STRINGS);
	version = r_bin_dex_get_version (arch->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS);
	free (version);
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "linux", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "Dalvik VM", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "dalvik", R_BIN_SIZEOF_STRINGS);
	ret->bits = 32;
	ret->big_endian= 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static RList* strings(RBinArch *arch) {
	RList *ret = NULL;
	RBinString *ptr = NULL;
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->bin_obj;
	ut32 i, *string;
	char buf[6];
	int len;

	string = (ut32 *) malloc (bin->header.strings_size * sizeof (ut32));
	r_buf_read_at(bin->b, bin->header.strings_offset, (ut8*)string,
			bin->header.strings_size * sizeof (ut32));
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	for (i = 0; i < bin->header.strings_size; i++) {
		if (!(ptr = R_NEW (RBinString)))
			break;
		r_buf_read_at (bin->b, string[i], (ut8*)&buf, 6);
		len = dex_read_uleb128 (buf);
		//	len = R_BIN_SIZEOF_STRINGS-1;
		if (len>0 && len < R_BIN_SIZEOF_STRINGS) {
			r_buf_read_at(bin->b, string[i]+1, (ut8*)&ptr->string, len);
			ptr->string[(int) len]='\0';
			ptr->rva = ptr->offset = string[i]+1;
			ptr->size = len;
			ptr->ordinal = i+1;
			r_list_append (ret, ptr);
		} else eprintf ("dex_read_uleb128: invalid read\n");
	}
	free (string);
	return ret;
}

//TODO
static RList* classes (RBinArch *arch) {
	RList *ret = NULL;
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) arch->bin_obj;
	struct dex_class_t entry;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	for (i = 0; i < bin->header.class_size; i++) {
		r_buf_read_at (bin->b, (ut64) bin->header.class_offset, (ut8*)&entry,
				sizeof (struct dex_class_t));
		eprintf ("ut32 class_id = %08x;\n", entry.class_id);
		eprintf ("ut32 access_flags = %08x;\n", entry.access_flags);
		eprintf ("ut32 super_class = %08x;\n", entry.super_class);
		eprintf ("ut32 interfaces_offset = %08x;\n", entry.interfaces_offset);
		eprintf ("ut32 source_file = %08x;\n", entry.source_file);
		eprintf ("ut32 anotations_offset = %08x;\n", entry.anotations_offset);
		eprintf ("ut32 class_data_offset = %08x;\n", entry.class_data_offset);
		eprintf ("ut32 static_values_offset = %08x;\n", entry.static_values_offset);
	}
	return ret;
}

static int getoffset (RBinArch *arch, int type, int idx) {
	struct r_bin_dex_obj_t *dex = arch->bin_obj;
	switch (type) {
	case 's': // symbol name
		// dex->header.method_offset
		return 0; // TODO: must be the offset to the ptr
	}
	return 0;
}

struct r_bin_plugin_t r_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex format bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = NULL,
	.check = &check,
	.baddr = &baddr,
	.binsym = NULL,
	.entries = &classes,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.get_offset = &getoffset
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dex
};
#endif
