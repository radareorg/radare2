/* radare - LGPL - Copyright 2016 - pancake */

#include <r_lib.h>
#include <r_crypto.h>

#define NAME "rol"

enum { MAX_rol_KEY_SIZE = 32768 };

struct rol_state {
	ut8 key[MAX_rol_KEY_SIZE];
	int key_size;
};

static bool rol_init(struct rol_state *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen < 1 || keylen > MAX_rol_KEY_SIZE) {
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

static struct rol_state st;
static int flag = 0;

static bool rol_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	flag = direction;
	return rol_init (&st, key, keylen);
}

static int rol_get_key_size(RCrypto *cry) {
	return st.key_size;
}

static bool rol_use(const char *algo) {
	return !strcmp (algo, NAME);
}

static bool update(RCrypto *cry, const ut8 *buf, int len) {
	if (flag) {
		eprintf ("Use ROR\n");
		return false;
	}
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	rol_crypt (&st, buf, obuf, len);
	r_crypto_append (cry, obuf, len);
	free (obuf);
	return true;
}

RCryptoPlugin r_crypto_plugin_rol = {
	.name = NAME,
	.set_key = rol_set_key,
	.get_key_size = rol_get_key_size,
	.use = rol_use,
	.update = update,
	.final = update,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_rol,
	.version = R2_VERSION
};
#endif
