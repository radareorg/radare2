/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static bool punycode_set_key(RMutaSession *ci, const ut8 *key, int keylen, int mode, int direction) {
	ci->flag = direction;
	return true;
}

static int punycode_get_key_size(RMutaSession *cry) {
	return 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	char *obuf = NULL;
	int olen = 0;
	switch (cj->flag) {
	case R_CRYPTO_DIR_DECRYPT:
		obuf = r_punycode_decode ((const char *)buf, len, &olen);
		break;
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = r_punycode_encode (buf, len, &olen);
		break;
	}
	r_muta_session_append (cj, (ut8 *)obuf, olen);
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_punycode = {
	.meta = {
		.name = "punycode",
		.desc = "Unicoded represented in plain ascii",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.type = R_MUTA_TYPE_CHARSET, // XXX this is an actual charset plugin!
	.implements = "punycode",
	.set_key = punycode_set_key,
	.get_key_size = punycode_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_punycode,
	.version = R2_VERSION
};
#endif
