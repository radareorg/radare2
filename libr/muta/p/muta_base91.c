/* radare - LGPL - Copyright 2016-2025 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_muta.h>
#include <r_util.h>

static bool base91_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	ms->dir = direction;
	return true;
}

static int base91_get_key_size(RMutaSession *ms) {
	return 0;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (ms && buf && len > 0, false);

	int olen = 0;
	ut8 *obuf = NULL;
	switch (ms->dir) {
	case R_MUTA_OP_ENCRYPT:
		{
			obuf = (ut8 *)r_base91_encode_dyn (buf, len);
			if (!obuf) {
				return false;
			}
			size_t encoded_len = strlen ((const char *)obuf);
			if (encoded_len > ST32_MAX) {
				free (obuf);
				return false;
			}
			olen = (int)encoded_len;
		}
		break;
	case R_MUTA_OP_DECRYPT:
		obuf = r_base91_decode_dyn ((const char *)buf, len, &olen);
		if (!obuf) {
			return false;
		}
		break;
	}
	if (olen > 0) {
		r_muta_session_append (ms, obuf, olen);
	}
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
