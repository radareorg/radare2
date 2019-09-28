/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_lib.h>
#include <r_crypto.h>

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
	memcpy (state->key, key, keylen);
	return true;
}

/*
 * Encrypt/Decrypt xor state buffer using the supplied key
 */

static void xor_crypt(struct xor_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;//index for input
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i] ^ state->key[(i%state->key_size)];
	}
}
static bool xor_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	return xor_init (&st, key, keylen);
}

static int xor_get_key_size(RCrypto *cry) {
	return st.key_size;
}

static bool xor_use(const char *algo) {
	return !strcmp (algo, "xor");
}

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	xor_crypt (&st, buf, obuf, len);
	r_crypto_append (cry, obuf, len);
	free (obuf);
	return true;
}

static bool final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_xor = {
	.name = "xor",
	.set_key = xor_set_key,
	.get_key_size = xor_get_key_size,
	.use = xor_use,
	.update = update,
	.final = final
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_xor,
	.version = R2_VERSION
};
#endif
