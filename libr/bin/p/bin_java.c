/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int load(RBin *bin) {
	if(!(bin->bin_obj = r_bin_java_new(bin->file)))
		return R_FALSE;
	bin->size = ((struct r_bin_java_obj_t*)(bin->bin_obj))->size;
	bin->buf = ((struct r_bin_java_obj_t*)(bin->bin_obj))->b;
	return R_TRUE;
}

static int destroy(RBin *bin) {
	r_bin_java_free ((struct r_bin_java_obj_t*)bin->bin_obj);
	return R_TRUE;
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
	ptr->offset = ptr->rva = r_bin_java_get_entrypoint (bin->bin_obj);
	r_list_append (ret, ptr);
	return ret;
}

static ut64 baddr(RBin *bin) {
	return 0;
}

static RList* symbols(RBin *bin) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_java_sym_t *symbols = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbols = r_bin_java_get_symbols ((struct r_bin_java_obj_t*)bin->bin_obj)))
		return ret;
	for (i = 0; !symbols[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->rva = ptr->offset = symbols[i].offset;
		ptr->size = symbols[i].size;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
	free (symbols);
	return ret;
}

static RList* strings(RBin *bin) {
	RList *ret = NULL;
	RBinString *ptr = NULL;
	struct r_bin_java_str_t *strings = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(strings = r_bin_java_get_strings((struct r_bin_java_obj_t*)bin->bin_obj)))
		return ret;
	for (i = 0; !strings[i].last; i++) {
		if (!(ptr = R_NEW (RBinString)))
			break;
		strncpy (ptr->string, strings[i].str, R_BIN_SIZEOF_STRINGS);
		ptr->rva = ptr->offset = strings[i].offset;
		ptr->size = strings[i].size;
		ptr->ordinal = strings[i].ordinal;
	}
	free (strings);
	return ret;
}

static RBinInfo* info(RBin *bin) {
	RBinInfo *ret = NULL;
	char *version;

	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	strncpy (ret->file, bin->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS);
	version = r_bin_java_get_version (bin->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS);
	free (version);
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "java", R_BIN_SIZEOF_STRINGS);
	ret->bits = 32;
	ret->big_endian= 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static int check(RBin *bin) {
	ut8 *filebuf, buf[4];
	int off, filesize, ret = R_FALSE;

	if ((filebuf = (ut8*)r_file_slurp (bin->file, &filesize))) {
		if (!memcmp (filebuf, "\xca\xfe\xba\xbe", 4)) {
			ret = R_TRUE;
			memcpy (&off, filebuf+4*sizeof(int), sizeof(int));
			r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
			if (off > 0 && off < filesize) {
				memcpy (buf, filebuf+off, 4);
				if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
					!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
					!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
					!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
					ret = R_FALSE;
			}
		}
		free (filebuf);
	}
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.extract = NULL,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.main = NULL,
	.entries = &entries,
	.sections = NULL,
	.symbols = &symbols,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java
};
#endif
