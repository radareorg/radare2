/* radare - LGPL - Copyright 2009-2022 - pancake */

#include "r_crypto.h"
#include "r_hash.h"
#include "config.h"
#include "r_util/r_assert.h"

R_LIB_VERSION (r_crypto);

static RCryptoPlugin *crypto_static_plugins[] = {
	R_CRYPTO_STATIC_PLUGINS
};

R_API void r_crypto_init(RCrypto *cry) {
	r_return_if_fail (cry);
	int i;
	cry->user = NULL;
	cry->plugins = r_list_newf (free);
	for (i = 0; crypto_static_plugins[i]; i++) {
		RCryptoPlugin *p = R_NEW0 (RCryptoPlugin);
		if (p) {
			memcpy (p, crypto_static_plugins[i], sizeof (RCryptoPlugin));
			r_crypto_add (cry, p);
		}
	}
	// TODO register hash algorithms
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
	r_crypto_init (cry);
	return cry;
}

R_API void r_crypto_job_free(RCryptoJob *cj) {
	if (cj) {
		if (cj->h->fini) {
			cj->h->fini (cj);
		}
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
		free (cry);
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

R_API void r_crypto_list(RCrypto *cry, PrintfCallback cb_printf, int mode) {
	if (!cb_printf) {
		cb_printf = (PrintfCallback)printf;
	}
	RListIter *iter;
	RCryptoPlugin *cp;
	r_list_foreach (cry->plugins, iter, cp) {
		switch (mode) {
		case 'q':
			cb_printf ("%s\n", cp->name);
			break;
		default:
			{
				char mode = cp->type? cp->type: 'c';
				const char *license = cp->license? cp->license: "LGPL";
				const char *desc = r_str_get (cp->desc);
				const char *author = r_str_get (cp->author);
				cb_printf ("%c %12s %5s %s %s\n", mode, cp->name, license, desc, author);
			}
			break;
		}
	}
	// TODO: move all those static hashes into crypto plugins
	int i;
	for (i = 0; i < 64; i++) {
		ut64 bits = ((ut64)1) << i;
		const char *name = r_hash_name (bits);
		if R_STR_ISEMPTY (name) {
			continue;
		}
		switch (mode) {
		case 'q':
			cb_printf ("%s\n", name);
			break;
		default:
			cb_printf ("h %12s\n", name);
			break;
		}
	}
}
