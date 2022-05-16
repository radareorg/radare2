/* radare - LGPL - Copyright 2022 - pancake */

#include <r_lib.h>
#include <r_bin.h>

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) >= 0x20) {
		ut8 magic[4] = {0};
		if (r_buf_read_at (b, 0, magic, sizeof (magic)) != 4) {
			return false;
		}
		return !memcmp (magic, "XALZ", 4);
	}
	return false;
}

static RBinXtrData *get_the_meta(RBin *bin, RBuffer *buf) {
	RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
	meta->machine = "mono";
	meta->type = "assembly";
	meta->libname = NULL;
	meta->xtr_type = "xalz";

	ut32 osz = r_buf_read_le32_at (buf, 8);
	int datalen = r_buf_size (buf) - 0xc;
	ut8 *data = malloc (datalen);
	if (!data) {
		return NULL;
	}
	r_buf_read_at (buf, 0xc, data, datalen);
	int consumed = 0;
	int outsize = 0;
	ut8 *obuf = r_inflate_lz4 (data, datalen, &consumed, &outsize);
	if (obuf && outsize == osz) {
		buf = r_buf_new_with_pointers (obuf, outsize, true);
		RBinXtrData *res = r_bin_xtrdata_new (buf, 0, r_buf_size (buf), 0, meta);
		return res;
	}
	R_LOG_ERROR ("LZ4 decompression failed");
	return NULL;
}

static RList *oneshotall_buffer(RBin *bin, RBuffer *b) {
	RList *list = r_list_newf (free);
	RBinXtrData *meta = get_the_meta (bin, b);
	r_list_append (list, meta);
	return list;
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_xalz = {
	.name = "xtr.xalz",
	.desc = "XAmarin LZ4 assemblies",
	.license = "MIT",
	.extractall_from_buffer = &oneshotall_buffer,
	.check_buffer = check_buffer,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_xtr_xalz,
	.version = R2_VERSION
};
#endif
