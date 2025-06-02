/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>

#define MAX_xor_KEY_SIZE 32768

struct xor_state {
	ut8 *key;
	int key_size;
};

static struct xor_state st;

static bool xor_init(struct xor_state *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen < 1) { // || keylen > MAX_xor_KEY_SIZE) {
		return false;
	}
	state->key_size = keylen;
	state->key = malloc (keylen);
	if (state->key == NULL) {
		return false;
	}
	memcpy (state->key, key, keylen);
	return true;
}

/*
 * Encrypt/Decrypt xor state buffer using the supplied key
 */

static void xor_crypt(struct xor_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i] ^ state->key[(i%state->key_size)];
	}
}
static bool xor_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	return xor_init (&st, key, keylen);
}

static int xor_get_key_size(RMutaSession *cj) {
	return st.key_size;
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

RMutaPlugin r_muta_plugin_xor = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "xor",
		.desc = "Byte level Exclusive Or",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "xor",
	.set_key = xor_set_key,
	.get_key_size = xor_get_key_size,
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
