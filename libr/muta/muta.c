/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_muta.h>
#include <r_hash.h>
#include <config.h>
#include <r_util/r_assert.h>

R_LIB_VERSION(r_muta);

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

R_API void r_muta_free(RMuta *cry) {
	if (cry) {
		r_list_free (cry->plugins);
		free (cry);
	}
}

R_API RMutaSession *r_muta_use(RMuta *cry, const char *algo) {
	R_RETURN_VAL_IF_FAIL (cry && algo, NULL);
	RListIter *iter;
	RMutaPlugin *h;
	r_list_foreach (cry->plugins, iter, h) {
		if (!h) {
			continue;
		}
		if (h->check) {
			if (h->check (algo)) {
				cry->h = h;
				RMutaSession *s = r_muta_session_new (cry, h);
				if (s) {
					s->subtype = strdup (algo);
				}
				return s;
			}
			continue;
		}
		if (R_STR_ISNOTEMPTY (h->meta.name) && !strcmp (h->meta.name, algo)) {
			cry->h = h;
			return r_muta_session_new (cry, h);
		}
		if (R_STR_ISNOTEMPTY (h->implements)) {
			char *impls = strdup (h->implements);
			RList *l = r_str_split_list (impls, ",", 0);
			const char *s;
			bool found = false;
			r_list_foreach (l, iter, s) {
				if (!strcmp (s, algo)) {
					found = true;
					break;
				}
			}
			r_list_free (l);
			free (impls);
			if (found) {
				cry->h = h;
				return r_muta_session_new (cry, h);
			}
		}
	}
	return NULL;
}

static const char *mutatype_tostring(int type) {
	switch (type) {
	case R_MUTA_TYPE_HASH:
		return "hash";
	case R_MUTA_TYPE_CRYPTO:
		return "crypto";
	case R_MUTA_TYPE_CHARSET:
		return "charset";
	case R_MUTA_TYPE_BASE:
		return "base";
	case R_MUTA_TYPE_SIGN:
		return "sign";
	default:
		return "unknown";
	}
}

static inline void print_plugin_verbose(RStrBuf *sb, RMutaPlugin *cp) {
	const char *typestr = mutatype_tostring (cp->type);
	const char *desc = r_str_get (cp->meta.desc);
	char type4[5];
	r_str_ncpy (type4, typestr, sizeof (type4));
	r_strbuf_appendf (sb, "%s %12s  %s\n", type4, cp->meta.name, desc);
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
			r_lib_meta_pj (pj, &cp->meta);
			pj_end (pj);
			break;
		default:
			print_plugin_verbose (sb, cp);
			break;
		}
	}
	// TODO: R2_600 move all those static hashes into muta plugins and remove the code below
	if (type == R_MUTA_TYPE_HASH || type == R_MUTA_TYPE_ALL) {
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
				r_strbuf_appendf (sb, "%s\n", name);
				break;
			default:
				r_strbuf_appendf (sb, "hash %12s\n", name);
				break;
			}
		}
	}
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
