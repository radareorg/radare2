/* radare - LGPL - Copyright 2011-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../fs/types.h"

static int check(RBinFile *arch);

static char *fsname(RBinFile *arch) {
	ut8 buf[1024];
	int i, j, len, ret = R_FALSE;

	for (i=0; fstypes[i].name; i++) {
		RFSType *f = &fstypes[i];
		len = R_MIN (f->buflen, sizeof (buf));
		memset (buf, 0, sizeof (buf));
		r_buf_read_at (arch->buf, f->bufoff, buf, len);
		if ((f->buflen>0) && (len>=f->buflen)) {
			int min = R_MIN (f->buflen, sizeof (buf));
			if (!memcmp (buf, f->buf, min)) {
				ret = R_TRUE;
				len = R_MIN (f->bytelen, sizeof (buf));
				r_buf_read_at (arch->buf, f->byteoff, buf, len);
				for (j=0; j<f->bytelen; j++) {
					if (buf[j] != f->byte) {
						ret = R_FALSE;
						break;
					}
				}
				if (ret) return strdup (f->name);
			}
		}
	}
	return NULL;
}

static int load(RBinFile *arch) {
	if (check (arch))
		return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinFile *arch) {
	//r_bin_fs_free ((struct r_bin_fs_obj_t*)arch->o->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	char *p;
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
	ret->lang = NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "fs", sizeof (ret->type)-1); // asm.arch
	strncpy (ret->bclass, "1.0", sizeof (ret->bclass)-1);
	strncpy (ret->rclass, "fs", sizeof (ret->rclass)-1); // file.type
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strncpy (ret->subsystem, "unknown", sizeof (ret->subsystem)-1);
	strncpy (ret->machine, "any", sizeof (ret->machine)-1);
	p = fsname (arch);
	strncpy (ret->arch, p, sizeof (ret->arch)-1);
	free (p);
	ret->has_va = 0;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinFile *arch) {
	char *p;
	int ret;

	p = fsname (arch);
	ret = (p)? R_TRUE: R_FALSE;
	free (p);
	return ret;
}

RBinPlugin r_bin_plugin_fs = {
	.name = "fs",
	.desc = "filesystem bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = NULL,
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
	.demangle_type = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fs
};
#endif
