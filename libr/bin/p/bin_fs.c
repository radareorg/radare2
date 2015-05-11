/* radare - LGPL - Copyright 2011-2015 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../fs/types.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

//static char *fsname(RBinFile *arch) {
static char *fsname(const ut8* buf, ut64 length) {
	ut8 fs_lbuf[1024];
	int i, j, len, ret = R_FALSE;

	for (i=0; fstypes[i].name ; i++) {
		RFSType *f = &fstypes[i];

		len = R_MIN (f->buflen, sizeof (fs_lbuf));
		memset (fs_lbuf, 0, sizeof (fs_lbuf));

		if (f->bufoff+len > length) break;
		memcpy (fs_lbuf, buf+f->bufoff, len);

		if (( f->buflen > 0) && (len >= f->buflen)) {
			int min = R_MIN (f->buflen, sizeof (fs_lbuf));
			if (!memcmp (fs_lbuf, f->buf, min)) {

				ret = R_TRUE;
				len = R_MIN (f->bytelen, sizeof (fs_lbuf));

				if (f->byteoff+len > length) break;
				memcpy (fs_lbuf, buf+f->byteoff, len);

				for (j=0; j<f->bytelen; j++) {
					if (fs_lbuf[j] != f->byte) {
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

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	if (check_bytes (buf, sz))
		return R_NOTNULL;
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
	RBinInfo *ret = NULL;
	const ut8 *bytes;
	ut64 sz;

	if (!arch) return NULL;
	bytes = r_buf_buffer (arch->buf);
	if (!bytes) return NULL;
	sz = arch->buf ? r_buf_size (arch->buf): 0;

	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = arch->file? strdup (arch->file): NULL;
	ret->type = strdup ("fs");
	ret->bclass = strdup ("1.0");
	ret->rclass = strdup ("fs");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("any");
	ret->arch = fsname (bytes, sz);
	ret->has_va = 0;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	char *p;
	int ret;
	if (!buf) return R_FALSE;
	p = fsname (buf, length);
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
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
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
	.dbginfo = NULL,
	.write = NULL,
	.demangle_type = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fs
};
#endif
