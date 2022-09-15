/* radare - LGPL - Copyright 2009-2022 - pancake */

#include "r_crypto.h"
#include "r_util.h"
#include "config.h"
#include "r_util/r_assert.h"

R_LIB_VERSION (r_crypto);

static const struct {
	const char *name;
	RCryptoSelector bit;
} crypto_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "rc2", R_CRYPTO_RC2 },
	{ "rc4", R_CRYPTO_RC4 },
	{ "rc6", R_CRYPTO_RC6 },
	{ "aes-ecb", R_CRYPTO_AES_ECB },
	{ "aes-cbc", R_CRYPTO_AES_CBC },
	{ "aes-wrap", R_CRYPTO_AES_WRAP },
	{ "ror", R_CRYPTO_ROR },
	{ "rol", R_CRYPTO_ROL },
	{ "rot", R_CRYPTO_ROT },
	{ "blowfish", R_CRYPTO_BLOWFISH },
	{ "cps2", R_CRYPTO_CPS2 },
	{ "des-ecb", R_CRYPTO_DES_ECB },
	{ "xor", R_CRYPTO_XOR },
	{ "serpent-ecb", R_CRYPTO_SERPENT },
	{ "sm4-ecb", R_CRYPTO_SM4_ECB },
	{ NULL, 0 }
};

static const struct {
	const char *name;
	RCryptoSelector bit;
} codec_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "base64", R_CODEC_B64 },
	{ "base91", R_CODEC_B91 },
	{ "punycode", R_CODEC_PUNYCODE },
	{ NULL, 0 }
};

R_API const char *r_crypto_name(const RCryptoSelector bit) {
	size_t i;
	for (i = 1; crypto_name_bytes[i].bit; i++) {
		if (bit & crypto_name_bytes[i].bit) {
			return crypto_name_bytes[i].name;
		}
	}
	return "";
}

R_API const char *r_crypto_codec_name(const RCryptoSelector bit) {
	size_t i;
	for (i = 1; codec_name_bytes[i].bit; i++) {
		if (bit & codec_name_bytes[i].bit) {
			return codec_name_bytes[i].name;
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
#if 0
		cry->iv = NULL;
		cry->key = NULL;
		cry->key_len = 0;
#endif
		cry->user = NULL;
		if (hard) {
			// first call initializes the output_* variables
			// r_crypto_job_get_output (cj, NULL);
			cry->plugins = r_list_newf (NULL);
			for (i = 0; crypto_static_plugins[i]; i++) {
				RCryptoPlugin *p = R_NEW0 (RCryptoPlugin);
				if (!p) {
					free (cry);
					return NULL;
				}
				memcpy (p, crypto_static_plugins[i], sizeof (RCryptoPlugin));
				r_crypto_add (cry, p);
				// also register hash algorithms supported
			}
		}
	}
	return cry;
}

R_API bool r_crypto_add(RCrypto *cry, RCryptoPlugin *h) {
	r_return_val_if_fail (cry && cry->plugins && h, false);
	r_list_append (cry->plugins, h);
	return true;
}

R_API bool r_crypto_del(RCrypto *cry, RCryptoPlugin *h) {
	r_return_val_if_fail (cry && h, false);
	r_list_delete_data (cry->plugins, h);
	return true;
}

R_API RCrypto *r_crypto_new(void) {
	RCrypto *cry = R_NEW0 (RCrypto);
	return r_crypto_init (cry, true);
}

R_API RCrypto *r_crypto_as_new(RCrypto *cry) {
	RCrypto *c = R_NEW0 (RCrypto);
	if (c) {
		r_crypto_init (c, false); // soft init
		memcpy (&c->plugins, &cry->plugins, sizeof (cry->plugins));
	}
	return c;
}

R_API void r_crypto_job_free(RCryptoJob *cj) {
	if (cj) {
		free (cj->output);
		free (cj->key);
		free (cj->iv);
		free (cj);
	}
}

R_API void r_crypto_free(RCrypto *cry) {
	if (cry) {
#if 0
		RListIter *iter;
		RCryptoPlugin *p;
		r_list_foreach (cry->plugins, iter, p) {
			if (p->fini) {
				p->fini (cry, p);
			}
		}
#endif
		r_list_free (cry->plugins);
	}
}

R_API RCryptoJob *r_crypto_use(RCrypto *cry, const char *algo) {
	r_return_val_if_fail (cry && algo, false);
	RListIter *iter, *iter2;
	RCryptoPlugin *h;
	r_list_foreach (cry->plugins, iter, h) {
		if (h && R_STR_ISNOTEMPTY (h->implements)) {
			char *impls = strdup (h->implements);
			RList *l = r_str_split_list (impls, ",", 0);
			const char *s;
			r_list_foreach (l, iter2, s) {
				if (!strcmp (s, algo)) {
					cry->h = h;
					r_list_free (l);
					return r_crypto_job_new (cry, h);
				}
			}
			r_list_free (l);
			free (impls);
		}
		// XXX deprecate
		if (h && h->check && h->check (algo)) {
			// R_DEPRECATE cry->h = h;
			return r_crypto_job_new (cry, h);
		}
	}
	return NULL;
}

R_API bool r_crypto_job_set_key(RCryptoJob *cj, const ut8* key, int keylen, int mode, int direction) {
	r_return_val_if_fail (cj, false);
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!cj->h || !cj->h->set_key) {
		return false;
	}
	cj->key_len = keylen;
	cj->key = calloc (1, cj->key_len);
	return cj->h->set_key (cj, key, keylen, mode, direction);
}

R_API int r_crypto_job_get_key_size(RCryptoJob *cj) {
	r_return_val_if_fail (cj, false);
	return (cj->h && cj->h->get_key_size)?
		cj->h->get_key_size (cj): 0;
}

R_API bool r_crypto_job_set_iv(RCryptoJob *cj, const ut8 *iv, int ivlen) {
	r_return_val_if_fail (cj, false);
	return (cj->h && cj->h->set_iv)?
		cj->h->set_iv (cj, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
R_API bool r_crypto_job_update(RCryptoJob *cj, const ut8 *buf, int len) {
	r_return_val_if_fail (cj, 0);
	return (cj->h && cj->h->update)? cj->h->update (cj, buf, len): 0;
}

R_API RCryptoJob *r_crypto_job_new(RCrypto *cry, RCryptoPlugin *cp) {
	RCryptoJob *cj = R_NEW0 (RCryptoJob);
	if (R_UNLIKELY (cj)) {
		cj->h = cp;
		cj->c = cry;
	}
	return cj;
}

R_API bool r_crypto_job_end(RCryptoJob *cj, const ut8 *buf, int len) {
	r_return_val_if_fail (cj, 0);
	return (cj->h && cj->h->end)? cj->h->end (cj, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use r_buf here
R_API int r_crypto_job_append(RCryptoJob *cj, const ut8 *buf, int len) {
	r_return_val_if_fail (cj&& buf, -1);
	if (cj->output_len+len > cj->output_size) {
		cj->output_size += 4096 + len;
		cj->output = realloc (cj->output, cj->output_size);
	}
	memcpy (cj->output + cj->output_len, buf, len);
	cj->output_len += len;
	return cj->output_len;
}

R_API ut8 *r_crypto_job_get_output(RCryptoJob *cj, int *size) {
	r_return_val_if_fail (cj, NULL);
	if (cj->output_size < 1) {
		return NULL;
	}
	ut8 *buf = calloc (1, cj->output_size);
	if (!buf) {
		return NULL;
	}
	if (size) {
		*size = cj->output_len;
		memcpy (buf, cj->output, *size);
	} else {
		size_t newlen = 4096;
		ut8 *newbuf = realloc (buf, newlen);
		if (!newbuf) {
			free (buf);
			return NULL;
		}
		buf = newbuf;
		cj->output = newbuf;
		cj->output_len = 0;
		cj->output_size = newlen;
		return NULL;
	}
	return buf;
}
