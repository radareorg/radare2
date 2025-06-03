/* radare - LGPL - Copyright 2016-2024 - pancake */

#include <r_muta.h>

#define NAME "rol"

#define MAX_ROL_KEY_SIZE 32768
struct rol_state {
	ut8 key[MAX_ROL_KEY_SIZE];
	int key_size;
};

static bool rol_init(struct rol_state *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen < 1 || keylen > MAX_ROL_KEY_SIZE) {
		return false;
	}
	int i;
	state->key_size = keylen;
	for (i = 0; i < keylen; i++) {
		state->key[i] = key[i];
	}
	return true;
}

static void rol_crypt(struct rol_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		ut8 count = state->key[i % state->key_size] & 7;
		ut8 inByte = inbuf[i];
		outbuf[i] = (inByte << count) | (inByte >> ((8 - count) & 7));
	}
}

static bool rol_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	free (cj->data);
	cj->data = R_NEW0 (struct rol_state);
	cj->flag = direction;
	struct rol_state *st = (struct rol_state*)cj->data;
	return rol_init (st, key, keylen);
}

static int rol_get_key_size(RMutaSession *cj) {
	struct rol_state *st = (struct rol_state*)cj->data;
	return st->key_size;
}

static bool fini(RMutaSession *cj) {
	R_FREE (cj->data);
	return true;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (cj->flag == R_CRYPTO_DIR_DECRYPT) {
		R_LOG_ERROR ("Use ROR instead of ROL");
		return false;
	}
	struct rol_state *st = (struct rol_state*)cj->data;
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	rol_crypt (st, buf, obuf, len);
	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_rol = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = NAME,
		.desc = "Rotate Left N bits",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.implements = NAME,
	.set_key = rol_set_key,
	.get_key_size = rol_get_key_size,
	.update = update,
	.end = update,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rol,
	.version = R2_VERSION
};
#endif
