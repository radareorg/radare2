/* radare - LGPL - Copyright 2016-2025 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_muta.h>
#include <r_util.h>

#define INSIZE 32768

static bool base91_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return true;
}

static int base91_get_key_size(RMutaSession *cj) {
	return 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf && len > 0, false);

	int olen = INSIZE;
	ut8 *obuf = calloc (1, olen);
	if (!obuf) {
		return false;
	}
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		olen = r_base91_encode ((char *)obuf, (const ut8 *)buf, len);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		olen = r_base91_decode (obuf, (const char *)buf, len);
		break;
	}
	r_muta_session_append (cj, obuf, olen);
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_base91 = {
	.meta = {
		.desc = "Binary to text encoding scheme using 91 ascii characters",
		.name = "base91",
		.author = "rakholiyajenish.07",
		.license = "MIT",
	},
	.implements = "base91",
	.type = R_MUTA_TYPE_BASE, // _BASE?
	.set_key = base91_set_key,
	.get_key_size = base91_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_base91,
	.version = R2_VERSION
};
#endif
