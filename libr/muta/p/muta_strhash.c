/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static bool update(RMutaJob *cj, const ut8 *buf, int len) {
	char *s = r_str_ndup ((const char *)buf, len);
	ut8 obuf[4];
	int n = r_str_hash (s);
	free (s);
	r_write_ble32 (obuf, n, cj->c->bigendian);
	r_muta_job_append (cj, obuf, 4);
	return true;
}

RMutaPlugin r_muta_plugin_strhash = {
	.meta = {
		.name = "strhash",
		.desc = "String hash using a modified DJB2 xor",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_CRYPTO_TYPE_HASH,
	.implements = "strhash",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_strhash,
	.version = R2_VERSION
};
#endif
