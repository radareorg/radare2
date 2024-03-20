/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_crypto.h>

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	char *s = r_str_ndup ((const char *)buf, len);
	int n = r_str_hash (s);
	free (s);
	cj->output = malloc (4);
	r_write_ble32 (cj->output, n, cj->c->bigendian);
	eprintf ("0x%x\n", n);
	cj->output_len = 4;
	return true;
}

RCryptoPlugin r_crypto_plugin_strhash = {
	.meta = {
		.name = "strhash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_CRYPTO_TYPE_HASHER,
	.implements = "strhash",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_strhash,
	.version = R2_VERSION
};
#endif
