/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_crypto.h"
#include "../config.h"

R_LIB_VERSION (r_crypto);

static RCryptoPlugin *crypto_static_plugins[] = {
	R_CRYPTO_STATIC_PLUGINS
};

R_API RCrypto *r_crypto_init(RCrypto *cry, int hard) {
	RCryptoPlugin *p;
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
				p = R_NEW0 (RCryptoPlugin);
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
	// TODO: call the destructor function of the plugin to destory the *user pointer if needed
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

R_API int r_crypto_set_key(RCrypto *cry, const ut8* key, int keylen, int mode, int direction) {
	if (keylen < 0)
		keylen = strlen ((const char *)key);
	return (cry && cry->h && cry->h->set_key)?
		cry->h->set_key (cry, key, keylen, mode, direction): false;
}

R_API int r_crypto_get_key_size(RCrypto *cry) {
	return (cry && cry->h && cry->h->get_key_size)?
		cry->h->get_key_size (cry): 0;
}

R_API int r_crypto_set_iv(RCrypto *cry, const ut8 *iv) {
	return (cry && cry->h && cry->h->set_iv)?
		cry->h->set_iv(cry, iv): 0;
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
	memcpy(cry->output + cry->output_len, buf, len);
	cry->output_len += len;
	return cry->output_len;
}

R_API ut8 *r_crypto_get_output(RCrypto *cry, int *size) {
	ut8 *buf = calloc (1, cry->output_size);
	if (!buf) return NULL;
	if (size) {
		*size = cry->output_len;
		memcpy (buf, cry->output, *size);
	} else {
		/* initialize */
		cry->output_len = 0;
		cry->output_size = 4096;
		cry->output = realloc(buf, cry->output_size);
		return NULL;
	}
	return buf;
}

