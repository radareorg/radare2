/* radare - LGPL - Copyright 2011 -- pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check(RBinArch *arch);
static const char *fsname(RBinArch *arch);

static int load(RBinArch *arch) {
	if (check (arch))
		return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinArch *arch) {
	//r_bin_fs_free ((struct r_bin_fs_obj_t*)arch->bin_obj);
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
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "fs", sizeof (ret->type)-1); // asm.arch
	strncpy (ret->bclass, "1.0", sizeof (ret->bclass)-1);
	strncpy (ret->rclass, "fs", sizeof (ret->rclass)-1); // file.type
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strncpy (ret->subsystem, "unknown", sizeof (ret->subsystem)-1);
	strncpy (ret->machine, "any", sizeof (ret->machine)-1);
	strncpy (ret->arch, fsname (arch), sizeof (ret->arch)-1);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

typedef struct r_bin_fs_type_t {
	const char *name;
	int bufoff;
	const char *buf;
	int buflen;
	int byteoff;
	ut8 byte;
	int bytelen;
} RBinFSType;

static RBinFSType fstypes[2] = {
	{ "hfsplus", 0x400, "H+", 2, 0, 0, 0x400 },
	{ NULL }
};

static const char *fsname(RBinArch *arch) {
	ut8 buf[1024];
	int i, j, len, ret = R_FALSE;

	for (i=0; fstypes[i].name; i++) {
		RBinFSType *f = &fstypes[i];
		len = R_MIN (f->buflen, sizeof (buf));
		r_buf_read_at (arch->buf, f->bufoff, buf, len);
		if (f->buflen>0 && !memcmp (buf, f->buf, f->buflen)) {
			ret = R_TRUE;
			len = R_MIN (f->bytelen, sizeof (buf));
			r_buf_read_at (arch->buf, f->byteoff, buf, len);
			for (j=0; j<f->bytelen; j++) {
				if (buf[j] != f->byte) {	
					ret = R_FALSE;
					break;
				}
			}
			if (ret) return f->name;
		}
	}
	return NULL;
}

static int check(RBinArch *arch) {
	return (fsname (arch))? R_TRUE: R_FALSE;
}

struct r_bin_plugin_t r_bin_plugin_fs = {
	.name = "fs",
	.desc = "filesystem bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
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
