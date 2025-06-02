/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_muta.h>
#include <r_hash.h>
#include <config.h>
#include <r_util/r_assert.h>

R_LIB_VERSION (r_muta);

static RMutaPlugin *muta_static_plugins[] = {
	R_MUTA_STATIC_PLUGINS
};

R_API void r_muta_init(RMuta *cry) {
	R_RETURN_IF_FAIL (cry);
	int i;
	cry->user = NULL;
	cry->plugins = r_list_newf (free);
	for (i = 0; muta_static_plugins[i]; i++) {
		RMutaPlugin *p = r_mem_dup (muta_static_plugins[i], sizeof (RMutaPlugin));
		if (p) {
			r_muta_add (cry, p);
		}
	}
}

R_API bool r_muta_add(RMuta *cry, RMutaPlugin *h) {
	R_RETURN_VAL_IF_FAIL (cry && cry->plugins && h, false);
	r_list_append (cry->plugins, h);
	return true;
}

R_API bool r_muta_del(RMuta *cry, RMutaPlugin *h) {
	R_RETURN_VAL_IF_FAIL (cry && h, false);
	r_list_delete_data (cry->plugins, h);
	return true;
}

R_API RMuta *r_muta_new(void) {
	RMuta *cry = R_NEW0 (RMuta);
	r_muta_init (cry);
	return cry;
}

R_API void r_muta_job_free(RMutaJob * R_NULLABLE cj) {
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

R_API void r_muta_free(RMuta *cry) {
	if (cry) {
#if 0
		RListIter *iter;
		RMutaPlugin *p;
		r_list_foreach (cry->plugins, iter, p) {
			if (p->fini) {
				// should be defined in the destructor pointer of the list
				p->fini (cry, p);
			}
		}
#endif
		r_list_free (cry->plugins);
		free (cry);
	}
}

R_API RMutaJob *r_muta_use(RMuta *cry, const char *algo) {
	R_RETURN_VAL_IF_FAIL (cry && algo, false);
	RListIter *iter, *iter2;
	RMutaPlugin *h;
	r_list_foreach (cry->plugins, iter, h) {
		if (h && R_STR_ISNOTEMPTY (h->implements)) {
			char *impls = strdup (h->implements);
			RList *l = r_str_split_list (impls, ",", 0);
			const char *s;
			r_list_foreach (l, iter2, s) {
				if (!strcmp (s, algo)) {
					cry->h = h;
					r_list_free (l);
					return r_muta_job_new (cry, h);
				}
			}
			r_list_free (l);
			free (impls);
		}
		// XXX deprecate
		if (h && h->check && h->check (algo)) {
			// R_DEPRECATE cry->h = h;
			return r_muta_job_new (cry, h);
		}
	}
	return NULL;
}

R_API bool r_muta_job_set_key(RMutaJob *cj, const ut8* key, int keylen, int mode, int direction) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!cj->h || !cj->h->set_key) {
		return true;
	}
	cj->key_len = keylen;
	cj->key = calloc (1, cj->key_len);
	return cj->h->set_key (cj, key, keylen, mode, direction);
}

R_API int r_muta_job_get_key_size(RMutaJob *cj) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	return (cj->h && cj->h->get_key_size)?
		cj->h->get_key_size (cj): 0;
}

R_API bool r_muta_job_set_iv(RMutaJob *cj, const ut8 *iv, int ivlen) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	RMutaJobSetIVCallback set_iv = R_UNWRAP3 (cj, h, set_iv);
	return set_iv? set_iv (cj, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
R_API bool r_muta_job_update(RMutaJob *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj, 0);
	RMutaJobUpdateCallback update = R_UNWRAP3 (cj, h, update);
	return update? update (cj, buf, len): 0;
}

R_API RMutaJob *r_muta_job_new(RMuta *cry, RMutaPlugin *cp) {
	R_RETURN_VAL_IF_FAIL (cry && cp, NULL);
	RMutaJob *cj = R_NEW0 (RMutaJob);
	cj->h = cp;
	cj->c = cry;
	return cj;
}

R_API bool r_muta_job_end(RMutaJob *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	return (cj->h && cj->h->end)? cj->h->end (cj, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use r_buf here
R_API int r_muta_job_append(RMutaJob *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, -1);
	if (cj->output_len+len > cj->output_size) {
		cj->output_size += 4096 + len;
		cj->output = realloc (cj->output, cj->output_size);
	}
	memcpy (cj->output + cj->output_len, buf, len);
	cj->output_len += len;
	return cj->output_len;
}

R_API ut8 *r_muta_job_get_output(RMutaJob *cj, int *size) {
	R_RETURN_VAL_IF_FAIL (cj, NULL);
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
		if (newbuf) {
			buf = newbuf;
			cj->output = newbuf;
			cj->output_len = 0;
			cj->output_size = newlen;
		} else {
			R_FREE (buf);
		}
	}
	return buf;
}

static inline void print_plugin_verbose(RMutaPlugin *cp, PrintfCallback cb_printf) {
	const char type = cp->type? cp->type: 'c';
	const char *desc = r_str_get (cp->meta.desc);
	cb_printf ("%c %12s  %s\n", type, cp->meta.name, desc);
}

R_API void r_muta_list(RMuta *cry, PrintfCallback R_NULLABLE cb_printf, int mode, RMutaType type) {
	R_RETURN_IF_FAIL (cry);
	if (!cb_printf) {
		cb_printf = (PrintfCallback)printf;
	}
	PJ *pj = NULL;

	if (mode == 'J') {
		pj = pj_new ();
		pj_a (pj);
	} else if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
	RListIter *iter;
	RMutaPlugin *cp;
	r_list_foreach (cry->plugins, iter, cp) {
		if (cp->type != type && type != R_CRYPTO_TYPE_ALL) {
			continue;
		}
		switch (mode) {
		case 'q':
			cb_printf ("%s\n", cp->meta.name);
			break;
		case 'J':
			pj_s (pj, cp->meta.name);
			break;
		case 'j':
			pj_o (pj);
			pj_ks (pj, "name", cp->meta.name);
			switch (cp->type) {
			case R_CRYPTO_TYPE_HASH:
				pj_ks (pj, "type", "hash");
				break;
			case R_CRYPTO_TYPE_ENCRYPT:
				pj_ks (pj, "type", "encryption");
				break;
			case R_CRYPTO_TYPE_ENCODER:
				pj_ks (pj, "type", "encoder");
				break;
			case R_CRYPTO_TYPE_SIGNATURE:
				pj_ks (pj, "type", "signature");
				break;
			default:
				R_LOG_ERROR ("Unknown algorithm type for %s", cp->meta.name);
				pj_free (pj);
				return;
			}
			r_lib_meta_pj (pj, &cp->meta);
			pj_end (pj);
			break;
		default:
			print_plugin_verbose (cp, cb_printf);
			break;
		}
	}
	// TODO: R2_600 move all those static hashes into muta plugins and remove the code below
	if (type == R_CRYPTO_TYPE_HASH || type == R_CRYPTO_TYPE_ALL) {
		int i;
		for (i = 0; i < 64; i++) {
			ut64 bits = ((ut64)1) << i;
			const char *name = r_hash_name (bits);
			if R_STR_ISEMPTY (name) {
				continue;
			}
			switch (mode) {
			case 'J':
				pj_s (pj, name);
				break;
			case 'j':
				pj_o (pj);
				pj_ks (pj, "type", "hash");
				pj_ks (pj, "name", name);
				pj_end (pj);
				break;
			case 'q':
				cb_printf ("%s\n", name);
				break;
			default:
				cb_printf ("h %12s\n", name);
				break;
			}
		}
	}
	if (mode == 'J') {
		pj_end (pj);
		char *s = pj_drain (pj);
		cb_printf ("%s\n", s);
		free (s);
	} else if (mode == 'j') {
		pj_end (pj);
		char *s = pj_drain (pj);
		cb_printf ("%s\n", s);
		free (s);
	}
}
