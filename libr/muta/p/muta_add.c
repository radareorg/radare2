/* radare - LGPL - Copyright 2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static void addsum(struct xor_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	ut32 v = 0;
	for (i = 0; i < buflen; i++) {
		v += inbuf[i];
	}
	r_write_le32 (outbuf, v);
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	xor_crypt (&st, buf, obuf, len);
	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

static int get_key_size(RMutaSession *ms) {
	return 4;
}

RMutaPlugin r_muta_plugin_xor = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "add",
		.desc = "Add checksum used by Tar (sum all bytes into ut32)",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "add",
	.get_key_size = get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_xor,
	.version = R2_VERSION
};
#endif
