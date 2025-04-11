/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_bin.h>
#include <r_magic.h>

static char *get_filetype(RBuffer *b) {
	RMagic *ck = r_magic_new (0);
	if (ck) {
		// TODO: use dir.magic here
		r_magic_load (ck, R2_SDB_MAGIC);
		ut8 buf[256] = {0};
		if (r_buf_read_at (b, 0, buf, sizeof (buf)) < 1) {
			return NULL;
		}
		const char *tmp = r_magic_buffer (ck, buf, sizeof (buf));
		r_magic_free (ck);
		return strdup (tmp);
	}
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = get_filetype (bf->buf);
	ret->has_retguard = -1;
	return ret;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return true;
}

static void fini(RBinFile *bf) {
	r_buf_free (bf->bo->bin_obj);
}

RBinPlugin r_bin_plugin_any = {
	.meta = {
		.name = "any",
		.desc = "Dummy parser using magic header",
		.license = "LGPL-3.0-only",
	},
	.load = load,
	.destroy = fini,
	.info = info,
	.minstrlen = 0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_any,
	.version = R2_VERSION
};
#endif
