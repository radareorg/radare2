/* radare - LGPL - Copyright 2016-2025 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_muta.h>
#include <r_util.h>

static bool base64_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return true;
}

static int base64_get_key_size(RMutaSession *cj) {
	return 0;
}

static bool base64_check(const char *algo) {
	return !strcmp (algo, "base64");
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		olen = ((len + 2) / 3 ) * 4;
		obuf = malloc (olen + 1);
		if (!obuf) {
			return false;
		}
		r_base64_encode ((char *)obuf, (const ut8 *)buf, len);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		olen = 4 + ((len / 4) * 3);
		if (len > 0) {
			olen -= (buf[len-1] == '=') ? ((buf[len-2] == '=') ? 2 : 1) : 0;
		}
		obuf = malloc (olen + 4);
		if (!obuf) {
			return false;
		}
		olen = r_base64_decode (obuf, (const char *)buf, len);
		break;
	}
	if (olen > 0) {
		r_muta_session_append (cj, obuf, olen);
	}
	free (obuf);
	return true;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_base64 = {
	.meta = {
		.name = "base64",
		.desc = "Binary to text encoding scheme using 64 ascii characters",
		.author = "rakholiyajenish.07",
		.license = "LGPL-3.0-only"
	},
	.type = R_MUTA_TYPE_CRYPTO,
	.set_key = base64_set_key,
	.get_key_size = base64_get_key_size,
	.check = base64_check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_base64,
	.version = R2_VERSION
};
#endif
