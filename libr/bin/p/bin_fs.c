/* radare - LGPL - Copyright 2011-2015 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../fs/types.h"

//static char *fsname(RBinFile *arch) {
static char *fsname(const ut8* buf, ut64 length) {
	ut8 fs_lbuf[1024];
	int i, j, len, ret = false;

	for (i = 0; fstypes[i].name; i++) {
		RFSType *f = &fstypes[i];

		len = R_MIN (f->buflen, sizeof (fs_lbuf));
		memset (fs_lbuf, 0, sizeof (fs_lbuf));

		if (f->bufoff + len > length) break;
		memcpy (fs_lbuf, buf + f->bufoff, len);

		if ((f->buflen > 0) && (len >= f->buflen)) {
			int min = R_MIN (f->buflen, sizeof (fs_lbuf));
			if (!memcmp (fs_lbuf, f->buf, min)) {
				ret = true;
				len = R_MIN (f->bytelen, sizeof (fs_lbuf));

				if (f->byteoff + len > length) break;
				memcpy (fs_lbuf, buf + f->byteoff, len);

				for (j = 0; j < f->bytelen; j++) {
					if (fs_lbuf[j] != f->byte) {
						ret = false;
						break;
					}
				}
				if (ret) return strdup (f->name);
			}
		}
	}
	return NULL;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || (st64)length < 1) {
		return false;
	}
	char *p = fsname (buf, length);
	free (p);
	return p != NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	if (check_bytes (buf, sz)) {
		return R_NOTNULL;
	}
	return NULL;
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	ut64 la = (arch && arch->o) ? arch->o->loadaddr: 0;
	return load_bytes (arch, bytes, sz, la, arch? arch->sdb: NULL) != NULL;
}

static int destroy(RBinFile *arch) {
	//r_bin_fs_free ((struct r_bin_fs_obj_t*)arch->o->bin_obj);
	return true;
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

RBinPlugin r_bin_plugin_fs = {
	.name = "fs",
	.desc = "filesystem bin plugin",
	.author = "pancake",
	.version = "1.0",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.strings = &strings,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fs,
	.version = R2_VERSION
};
#endif
