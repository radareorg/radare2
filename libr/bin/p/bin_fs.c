/* radare - LGPL - Copyright 2011-2023 - pancake */

#include <r_bin.h>
#include <r_fs.h>

static char *fsname(RBuffer *b) {
	ut8 buf[1024];
	int i, j;

	for (i = 0; ; i++) {
		const RFSType *f = r_fs_type_index (i);
		if (!f || !f->name) {
			break;
		}

		if (r_buf_read_at (b, f->bufoff, buf, sizeof (buf)) != sizeof (buf)) {
			break;
		}
		if (f->buflen > 0) {
			size_t min = R_MIN (f->buflen, sizeof (buf));
			if (!memcmp (buf, f->buf, min)) {
				bool ret = true;
				min = R_MIN (f->bytelen, sizeof (buf));
				if (r_buf_read_at (b, f->byteoff, buf, min) != min) {
					break;
				}
				for (j = 0; j < min; j++) {
					if (buf[j] != f->byte) {
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

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	char *p = fsname (b);
	bool hasFs = p;
	free (p);
	return hasFs;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return check (bf, buf);
}

static void destroy(RBinFile *bf) {
	//r_bin_fs_free ((struct r_bin_fs_obj_t*)bf->bo->bin_obj);
}

/* accelerate binary load */
static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo* info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = bf->file? strdup (bf->file): NULL;
		ret->type = strdup ("fs");
		ret->bclass = fsname (bf->buf);
		ret->rclass = strdup ("fs");
		ret->os = strdup ("any");
		ret->subsystem = strdup ("unknown");
		ret->machine = strdup ("any");
		// ret->arch = strdup ("any");
		ret->has_va = 0;
		ret->bits = 32;
		ret->big_endian = 0;
		ret->dbg_info = 0;
	}
	return ret;
}

RBinPlugin r_bin_plugin_fs = {
	.meta = {
		.name = "fs",
		.desc = "Autodetect and mount RFS supported filesystems",
		.author = "pancake",
		.version = "1.0",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fs,
	.version = R2_VERSION
};
#endif
