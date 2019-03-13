/* radare - LGPL - Copyright 2011-2017 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../fs/types.h"

static char *fsname(const ut8* buf, ut64 length) {
	ut8 fs_lbuf[1024];
	int i, j, len, ret = false;

	for (i = 0; fstypes[i].name; i++) {
		RFSType *f = &fstypes[i];

		len = R_MIN (f->buflen, sizeof (fs_lbuf));
		memset (fs_lbuf, 0, sizeof (fs_lbuf));
		if (f->bufoff + len > length) {
			break;
		}
		memcpy (fs_lbuf, buf + f->bufoff, len);
		if ((f->buflen > 0) && len >= f->buflen) {
			int min = R_MIN (f->buflen, sizeof (fs_lbuf));
			if (!memcmp (fs_lbuf, f->buf, min)) {
				ret = true;
				len = R_MIN (f->bytelen, sizeof (fs_lbuf));
				if (f->byteoff + len > length) {
					break;
				}
				memcpy (fs_lbuf, buf + f->byteoff, len);
				// for (j = 0; j < f->bytelen; j++) {
				for (j = 0; j < len; j++) {
					if (fs_lbuf[j] != f->byte) {
						ret = false;
						break;
					}
				}
				if (ret) {
					return strdup (f->name);
				}
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

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return check_bytes (buf, sz);
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf): 0;
	ut64 la = (bf && bf->o) ? bf->o->loadaddr: 0;
	return load_bytes (bf, bf? &bf->o->bin_obj: NULL, bytes, sz, la, bf? bf->sdb: NULL);
}

static int destroy(RBinFile *bf) {
	//r_bin_fs_free ((struct r_bin_fs_obj_t*)bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	const ut8 *bytes;
	ut64 sz;

	if (!bf) {
		return NULL;
	}
	bytes = r_buf_buffer (bf->buf);
	if (!bytes) {
		return NULL;
	}
	sz = bf->buf ? r_buf_size (bf->buf): 0;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("fs");
	ret->bclass = fsname (bytes, sz);
	ret->rclass = strdup ("fs");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("any");
	// ret->arch = strdup ("any");
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
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fs,
	.version = R2_VERSION
};
#endif
