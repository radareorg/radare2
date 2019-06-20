/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "r_crypto.h"
#include "config.h"

R_LIB_VERSION (r_crypto);

static const struct {
	const char *name;
	ut64 bit;
} crypto_name_bytes[] = {
	{"all", UT64_MAX},
	{"rc2", R_CRYPTO_RC2},
	{"rc4", R_CRYPTO_RC4},
	{"rc6", R_CRYPTO_RC6},
	{"aes-ecb", R_CRYPTO_AES_ECB},
	{"aes-cbc", R_CRYPTO_AES_CBC},
	{"ror", R_CRYPTO_ROR},
	{"rol", R_CRYPTO_ROL},
	{"rot", R_CRYPTO_ROT},
	{"blowfish", R_CRYPTO_BLOWFISH},
	{"cps2", R_CRYPTO_CPS2},
	{"des-ecb", R_CRYPTO_DES_ECB},
	{"xor", R_CRYPTO_XOR},
	{"serpent-ecb", R_CRYPTO_SERPENT},
	{NULL, 0}
};

R_API const char *r_crypto_name(ut64 bit) {
	int i;
	for (i = 1; crypto_name_bytes[i].bit; i++) {
		if (bit & crypto_name_bytes[i].bit) {
			return crypto_name_bytes[i].name;
		}
	}
	return "";
}

static RCryptoPlugin *crypto_static_plugins[] = {
	R_CRYPTO_STATIC_PLUGINS
};

R_API RCrypto *r_crypto_init(RCrypto *cry, int hard) {
	int i;
	if (cry) {
		cry->iv = NULL;
		cry->key = NULL;
		cry->key_len = 0;
		cry->user = NULL;
		if (hard) {
			// first call initializes the output_* variables
			r_crypto_get_output (cry, NULL);
			cry->plugins = r_list_newf (NULL);
			for (i=0; crypto_static_plugins[i]; i++) {
				RCryptoPlugin *p = R_NEW0 (RCryptoPlugin);
				if (!p) {
					free (cry);
					return NULL;
				}
				memcpy (p, crypto_static_plugins[i], sizeof (RCryptoPlugin));
				r_crypto_add (cry, p);
			}
		}
	}
	return cry;
}

R_API int r_crypto_add(RCrypto *cry, RCryptoPlugin *h) {
	// add a check ?
	r_list_append (cry->plugins, h);
	return true;
}

R_API int r_crypto_del(RCrypto *cry, RCryptoPlugin *h) {
	r_list_delete_data (cry->plugins, h);
	return true;
}

R_API struct r_crypto_t *r_crypto_new() {
	RCrypto *cry = R_NEW0 (RCrypto);
	return r_crypto_init (cry, true);
}

R_API struct r_crypto_t *r_crypto_as_new(struct r_crypto_t *cry) {
	RCrypto *c = R_NEW0 (RCrypto);
	if (c) {
		r_crypto_init (c, false); // soft init
		memcpy (&c->plugins, &cry->plugins, sizeof (cry->plugins));
	}
	return c;
}

R_API struct r_crypto_t *r_crypto_free(RCrypto *cry) {
	// TODO: call the destructor function of the plugin to destroy the *user pointer if needed
	r_list_free (cry->plugins);
	free (cry->output);
	free (cry->key);
	free (cry->iv);
	free (cry);
	return NULL;
}

R_API bool r_crypto_use(RCrypto *cry, const char *algo) {
	RListIter *iter;
	RCryptoPlugin *h;
	r_list_foreach (cry->plugins, iter, h) {
		if (h && h->use && h->use (algo)) {
			cry->h = h;
			cry->key_len = h->get_key_size (cry);
			cry->key = calloc (1, cry->key_len);
			return cry->key != NULL;
		}
	}
	return false;
}

R_API bool r_crypto_set_key(RCrypto *cry, const ut8* key, int keylen, int mode, int direction) {
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!cry || !cry->h || !cry->h->set_key) {
		return false;
	}
	return cry->h->set_key (cry, key, keylen, mode, direction);
}

R_API int r_crypto_get_key_size(RCrypto *cry) {
	return (cry && cry->h && cry->h->get_key_size)?
		cry->h->get_key_size (cry): 0;
}

R_API bool r_crypto_set_iv(RCrypto *cry, const ut8 *iv, int ivlen) {
	return (cry && cry->h && cry->h->set_iv)?
		cry->h->set_iv(cry, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
R_API int r_crypto_update(RCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->update)?
		cry->h->update (cry, buf, len): 0;
}

R_API int r_crypto_final(RCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->final)?
		cry->h->final (cry, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use r_buf here
R_API int r_crypto_append(RCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf) {
		return -1;
	}
	if (cry->output_len+len > cry->output_size) {
		cry->output_size += 4096 + len;
		cry->output = realloc (cry->output, cry->output_size);
	}
	memcpy (cry->output + cry->output_len, buf, len);
	cry->output_len += len;
	return cry->output_len;
}

R_API ut8 *r_crypto_get_output(RCrypto *cry, int *size) {
	if (cry->output_size < 1) {
		return NULL;
	}
	ut8 *buf = calloc (1, cry->output_size);
	if (!buf) {
		return NULL;
	}
	if (size) {
		*size = cry->output_len;
		memcpy (buf, cry->output, *size);
	} else {
		/* initialize */
		const int size = 4096;
		cry->output = realloc (buf, size);
		if (!cry->output) {
			free (buf);
			return NULL;
		}
		cry->output_len = 0;
		cry->output_size = size;

		return NULL;
	}
	return buf;
}
