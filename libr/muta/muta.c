/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_muta.h>
#include <r_hash.h>
#include <config.h>
#include <r_util/r_assert.h>

R_LIB_VERSION(r_muta);

static RMutaPlugin *muta_static_plugins[] = {
	R_MUTA_STATIC_PLUGINS
};

static void r_muta_init(RMuta *muta) {
	R_RETURN_IF_FAIL (muta);
	int i;
	muta->user = NULL;
	muta->plugins = r_list_newf (free);
	for (i = 0; muta_static_plugins[i]; i++) {
		RMutaPlugin *p = r_mem_dup (muta_static_plugins[i], sizeof (RMutaPlugin));
		if (p) {
			r_muta_add (muta, p);
		}
	}
}

R_API bool r_muta_add(RMuta *muta, RMutaPlugin *h) {
	R_RETURN_VAL_IF_FAIL (muta && muta->plugins && h, false);
	r_list_append (muta->plugins, h);
	return true;
}

R_API bool r_muta_del(RMuta *muta, RMutaPlugin *h) {
	R_RETURN_VAL_IF_FAIL (muta && h, false);
	r_list_delete_data (muta->plugins, h);
	return true;
}

R_API RMuta *r_muta_new(void) {
	RMuta *muta = R_NEW0 (RMuta);
	r_muta_init (muta);
	return muta;
}

R_API void r_muta_free(RMuta *muta) {
	if (muta) {
		r_list_free (muta->plugins);
		free (muta);
	}
}

R_API RMutaPlugin *r_muta_find(RMuta *muta, const char *algo) {
	R_RETURN_VAL_IF_FAIL (muta && muta->plugins && algo, NULL);
	RListIter *iter;
	RMutaPlugin *h;
	r_list_foreach (muta->plugins, iter, h) {
		if (!h) {
			continue;
		}
		if (h->check) {
			if (h->check (algo)) {
				return h;
			}
			continue;
		}
		if (R_STR_ISNOTEMPTY (h->meta.name) && !strcmp (h->meta.name, algo)) {
			return h;
		}
		if (R_STR_ISNOTEMPTY (h->implements)) {
			char *impls = strdup (h->implements);
			RList *l = r_str_split_list (impls, ",", 0);
			const char *s;
			bool found = false;
			RListIter *it2;
			r_list_foreach (l, it2, s) {
				if (!strcmp (s, algo)) {
					found = true;
					break;
				}
			}
			r_list_free (l);
			free (impls);
			if (found) {
				return h;
			}
		}
	}
	return NULL;
}

R_API RMutaType r_muta_algo_type(RMuta *muta, const char *algo) {
	RMutaPlugin *h = r_muta_find (muta, algo);
	return h ? h->type : R_MUTA_TYPE_ALL;
}

R_API bool r_muta_algo_supports(RMuta *muta, const char *algo, RMutaType type) {
	RMutaPlugin *h = r_muta_find (muta, algo);
	return h && h->type == type;
}

R_API RMutaSession *r_muta_use(RMuta *muta, const char *algo) {
	R_RETURN_VAL_IF_FAIL (muta && algo, NULL);
	RMutaPlugin *h = r_muta_find (muta, algo);
	if (!h) {
		return NULL;
	}
	muta->h = h;
	RMutaSession *s = r_muta_session_new (muta, h);
	if (s && h->check) {
		s->subtype = strdup (algo);
	}
	return s;
}

static const char *muta_type_strings[] = {
	"hash", "base", "crypto", "sign", "charset",
};
static const char *mutatype_tostring(int type) {
	if (type < 0) {
		return "all";
	}
	if (type < R_MUTA_TYPE_LAST) {
		return muta_type_strings[type];
	}
	return "unknown";
}

static inline void print_plugin_verbose(RStrBuf *sb, RMutaPlugin *cp) {
	const char *typestr = mutatype_tostring (cp->type);
	const char *desc = r_str_get (cp->meta.desc);
	char type4[5];
	r_str_ncpy (type4, typestr, sizeof (type4));

	if (R_STR_ISNOTEMPTY (cp->implements)) {
		char *impls = strdup (cp->implements);
		RList *l = r_str_split_list (impls, ",", 0);
		bool multiple = r_list_length (l) > 1;
		r_list_free (l);
		free (impls);

		if (multiple) {
			r_strbuf_appendf (sb, "%s %12s  %s (implements: %s)\n", type4, cp->meta.name, desc, cp->implements);
		} else {
			r_strbuf_appendf (sb, "%s %12s  %s\n", type4, cp->meta.name, desc);
		}
	} else {
		r_strbuf_appendf (sb, "%s %12s  %s\n", type4, cp->meta.name, desc);
	}
}

R_API char *r_muta_list(RMuta *cry, RMutaType type, int mode) {
	R_RETURN_VAL_IF_FAIL (cry, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	PJ *pj = NULL;

	if (tolower (mode) == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
	RListIter *iter;
	RMutaPlugin *cp;
	r_list_foreach (cry->plugins, iter, cp) {
		if (cp->type != type && type != R_MUTA_TYPE_ALL) {
			continue;
		}
		switch (mode) {
		case 'q':
			r_strbuf_appendf (sb, "%s\n", cp->meta.name);
			break;
		case 'J':
			pj_s (pj, cp->meta.name);
			break;
		case 'j':
			pj_o (pj);
			pj_ks (pj, "name", cp->meta.name);
			const char *ts = mutatype_tostring (cp->type);
			pj_ks (pj, "type", ts);
			if (R_STR_ISNOTEMPTY (cp->implements)) {
				pj_ka (pj, "implements");
				char *impls = strdup (cp->implements);
				RList *l = r_str_split_list (impls, ",", 0);
				RListIter *it2;
				const char *s;
				r_list_foreach (l, it2, s) {
					pj_s (pj, s);
				}
				r_list_free (l);
				free (impls);
				pj_end (pj);
			}
			r_lib_meta_pj (pj, &cp->meta);
			pj_end (pj);
			break;
		default:
			print_plugin_verbose (sb, cp);
			break;
		}
	}
#if 1
	// TODO: R2_610 move all those static hashes into muta plugins and remove the code below
	if (type == R_MUTA_TYPE_HASH || type == R_MUTA_TYPE_ALL) {
		int i;
		for (i = 0; i < 64; i++) {
			ut64 bits = ((ut64)1) << i;
			const char *name = r_hash_name (bits);
			if (R_STR_ISEMPTY (name)) {
				continue;
			}
			// skip if already implemented by a muta plugin
			if (r_muta_find (cry, name)) {
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
				r_strbuf_appendf (sb, "%s\n", name);
				break;
			default:
				r_strbuf_appendf (sb, "hash %12s\n", name);
				break;
			}
		}
	}
#endif
	if (mode == 'j' || mode == 'J') {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_strbuf_appendf (sb, "%s\n", s);
		free (s);
	}
	return r_strbuf_drain (sb);
}

#include <r_muta/r_ed25519.h>

#include "signature/ed25519/ge.h"
#include "signature/ed25519/sc.h"

R_API void r_muta_ed25519_keypair(const ut8 *seed, ut8 *privkey, ut8 *pubkey) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA512);
	ge_p3 A;

	r_hash_do_sha512 (ctx, seed, ED25519_SEED_LENGTH);
	memcpy (privkey, ctx->digest, ED25519_PRIVKEY_LENGTH);
	r_hash_free (ctx);
	privkey[0] &= 248;
	privkey[31] &= 63;
	privkey[31] |= 64;
	ge_scalarmult_base (&A, privkey);
	ge_p3_tobytes (pubkey, &A);
}
