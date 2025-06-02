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

R_API RMutaSession *r_muta_use(RMuta *cry, const char *algo) {
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
					return r_muta_session_new (cry, h);
				}
			}
			r_list_free (l);
			free (impls);
		}
		// XXX deprecate
		if (h && h->check && h->check (algo)) {
			// R_DEPRECATE cry->h = h;
			return r_muta_session_new (cry, h);
		}
	}
	return NULL;
}


static inline void print_plugin_verbose(RMutaPlugin *cp, PrintfCallback cb_printf) {
	const char type = cp->type? cp->type: 'c';
	const char *desc = r_str_get (cp->meta.desc);
	cb_printf ("%c %12s  %s\n", type, cp->meta.name, desc);
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
		if (cp->type != type && type != R_MUTA_TYPE_ALL) {
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
			const char *ts = mutatype_tostring (cp->type);
			pj_ks (pj, "type", ts);
			r_lib_meta_pj (pj, &cp->meta);
			pj_end (pj);
			break;
		default:
			print_plugin_verbose (cp, cb_printf);
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
