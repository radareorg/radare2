/* radare2 - LGPL - Copyright 2009-2023 - pancake */

#include <r_lang.h>
#include <r_util.h>

R_LIB_VERSION (r_lang);

#include "p/spp.c"
#if HAVE_SYSTEM
#include "p/pipe.c"
#include "p/c.c"
#include "p/s.c"
#include "p/v.c"
#include "p/vala.c"
#include "p/rust.c"
#include "p/zig.c"
#if R2__UNIX__
#include "p/cpipe.c"
#endif
#endif
#include "p/asm.c"
#include "p/go.c"
#include "p/lib.c"
#include "p/qjs.c"
#include "p/poke.c"
#include "p/tsc.c"
#include "p/nim.c"

R_API RLang *r_lang_new(void) {
	RLang *lang = R_NEW0 (RLang);
	if (!lang) {
		return NULL;
	}
	lang->user = NULL;
	lang->langs = r_list_new ();
	if (!lang->langs) {
		r_lang_free (lang);
		return NULL;
	}
	lang->defs = r_list_new ();
	if (!lang->defs) {
		r_lang_free (lang);
		return NULL;
	}
	lang->sessions = r_list_newf (free);
	lang->defs->free = (RListFree)r_lang_def_free;
	lang->cb_printf = (PrintfCallback)printf;
#if HAVE_SYSTEM
#if R2__UNIX__
	r_lang_plugin_add (lang, &r_lang_plugin_s);
	r_lang_plugin_add (lang, &r_lang_plugin_c);
	r_lang_plugin_add (lang, &r_lang_plugin_cpipe);
#endif
	r_lang_plugin_add (lang, &r_lang_plugin_v);
	r_lang_plugin_add (lang, &r_lang_plugin_vala);
	r_lang_plugin_add (lang, &r_lang_plugin_rust);
	r_lang_plugin_add (lang, &r_lang_plugin_zig);
	r_lang_plugin_add (lang, &r_lang_plugin_pipe);
#endif
	r_lang_plugin_add (lang, &r_lang_plugin_go);
	r_lang_plugin_add (lang, &r_lang_plugin_poke);
	r_lang_plugin_add (lang, &r_lang_plugin_spp);
	r_lang_plugin_add (lang, &r_lang_plugin_lib);
	r_lang_plugin_add (lang, &r_lang_plugin_asm);
	r_lang_plugin_add (lang, &r_lang_plugin_qjs);
	r_lang_plugin_add (lang, &r_lang_plugin_tsc);
	r_lang_plugin_add (lang, &r_lang_plugin_nim);

	return lang;
}

R_API void r_lang_free(RLang *lang) {
	if (lang) {
		r_lang_undef (lang, NULL);
		r_list_free (lang->langs);
		r_list_free (lang->defs);
		r_list_free (lang->sessions);
		// TODO: remove langs plugins
		free (lang);
	}
}

// XXX: This is only used actually to pass 'core' structure
// TODO: when language bindings are done we will need an api to
// define symbols from C to the language namespace
// XXX: Depcreate!!
R_API void r_lang_set_user_ptr(RLang *lang, void *user) {
	lang->user = user;
}

R_API bool r_lang_define(RLang *lang, const char *type, const char *name, void *value) {
	RLangDef *def;
	RListIter *iter;
	r_list_foreach (lang->defs, iter, def) {
		if (!r_str_casecmp (name, def->name)) {
			def->value = value;
			return  true;
		}
	}
	def = R_NEW0 (RLangDef);
	if (!def) {
		return false;
	}
	def->type = strdup (type);
	def->name = strdup (name);
	def->value = value;
	r_list_append (lang->defs, def);
	return true;
}

R_API void r_lang_def_free(RLangDef *def) {
	free (def->name);
	free (def->type);
	free (def);
}

R_API void r_lang_undef(RLang *lang, const char *name) {
	if (name && *name) {
		RLangDef *def;
		RListIter *iter;
		/* No _safe loop necessary because we return immediately after the delete. */
		r_list_foreach (lang->defs, iter, def) {
			if (!name || !r_str_casecmp (name, def->name)) {
				r_list_delete (lang->defs, iter);
				break;
			}
		}
	} else {
		r_list_free (lang->defs);
		lang->defs = NULL;
	}
}

R_API bool r_lang_setup(RLang *lang) {
	RLangPlugin *p = R_UNWRAP3 (lang, session, plugin);
	if (p) {
		if (p->setup) {
			return p->setup (lang->session);
		}
		if (p->fini) {
			p->fini (lang->session);
		}
		if (p->init) {
			(void)p->init (lang->session);
		}
		return true;
	}
	return false;
}

R_API bool r_lang_plugin_add(RLang *lang, RLangPlugin *foo) {
	if (foo && !r_lang_get_by_name (lang, foo->meta.name)) {
		bool supported = true;
		if (foo->init) {
			// when init takes null, we just check if
			// the system is capable to use the plugin
			// otherwise we can use the session info
			// to initialize the internal plugin state
			supported = foo->init (NULL);
		}
		if (supported) {
			r_list_append (lang->langs, foo);
			return true;
		}
	}
	return false;
}

R_API bool r_lang_plugin_remove(RLang *lang, RLangPlugin *plugin) {
	return true;
}

/* TODO: deprecate all list methods */
R_API void r_lang_list(RLang *lang, int mode) {
	RListIter *iter;
	RLangPlugin *h;
	if (!lang) {
		return;
	}
	PJ *pj = NULL;
	RTable *table = NULL;
	if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	} else if (mode == ',') {
		table = r_table_new ("langs");
		RTableColumnType *typeString = r_table_type ("string");
		r_table_add_column (table, typeString, "name", 0);
		r_table_add_column (table, typeString, "license", 0);
		r_table_add_column (table, typeString, "desc", 0);
	}
	r_list_foreach (lang->langs, iter, h) {
		const char *license = h->meta.license
			? h->meta.license : "???";
		if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", r_str_get (h->meta.name));
			pj_ks (pj, "license", license);
			pj_ks (pj, "description", r_str_get (h->meta.desc));
			pj_end (pj);
		} else if (mode == 'q') {
			lang->cb_printf ("%s\n", h->meta.name);
		} else if (mode == ',') {
			r_table_add_row (table,
				r_str_get (h->meta.name),
				r_str_get (h->meta.license),
				r_str_get (h->meta.desc), 0);
		} else {
			lang->cb_printf ("%-8s %6s  %s\n",
				h->meta.name, license, h->meta.desc);
		}
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		lang->cb_printf ("%s\n", s);
		free (s);
	} else if (table) {
		char *s = r_table_tostring (table);
		lang->cb_printf ("%s\n", s);
		free (s);
		r_table_free (table);
	}
}

R_API RLangPlugin *r_lang_get_by_extension(RLang *lang, const char *ext) {
	RListIter *iter;
	RLangPlugin *h;
	const char *p = r_str_lchr (ext, '.');
	if (p) {
		ext = p + 1;
	}
	r_list_foreach (lang->langs, iter, h) {
		if (!r_str_casecmp (h->ext, ext)) {
			return h;
		}
	}
	return NULL;
}

R_API RLangPlugin *r_lang_get_by_name(RLang *lang, const char *name) {
	RListIter *iter;
	RLangPlugin *h;
	r_list_foreach (lang->langs, iter, h) {
		if (!r_str_casecmp (h->meta.name, name)) {
			return h;
		}
		if (h->alias && !r_str_casecmp (h->alias, name)) {
			return h;
		}
	}
	return NULL;
}

R_API RLangSession *r_lang_session(RLang *lang, RLangPlugin *h) {
	r_return_val_if_fail (lang && h, NULL);
	RLangSession *session = R_NEW0 (RLangSession);
	if (session) {
		session->lang = lang;
		session->plugin = h;
		if (h->init) {
			// session->plugin_data = h->init (session);
			if (!h->init (session)) {
				R_LOG_ERROR ("Cannot initialize plugin for this rlang session");
				free (session);
				return NULL;
			}
		}
	}
	return session;
}

R_API bool r_lang_unuse(RLang *lang) {
	RLangSession *s = lang->session;
	if (s) {
		// TODO: call fini and remove it from the sessions list
		r_list_delete_data (lang->sessions, s);
		RLangPlugin *plugin = s->plugin;
		if (plugin->fini) {
			plugin->fini (s);
		}
		free (s);
		lang->session = NULL;
		return true;
	}
	return false;
}

R_API bool r_lang_use_plugin(RLang *lang, RLangPlugin *h) {
	r_return_val_if_fail (lang && h, false);
	RListIter *iter;
	RLangSession *s = NULL;
	r_list_foreach (lang->sessions, iter, s) {
		if (h == s->plugin) {
			lang->session = s;
			return true;
		}
	}
	s = r_lang_session (lang, h);
	if (s) {
		lang->session = s;
		r_list_append (lang->sessions, s);
		return true;
	}
	return false;
}

R_API bool r_lang_use(RLang *lang, const char *name) {
	r_return_val_if_fail (lang && name, false);
	RLangPlugin *h = r_lang_get_by_name (lang, name);
	return h? r_lang_use_plugin (lang, h): false;
}

// TODO: store in r_lang and use it from the plugin?
R_API bool r_lang_set_argv(RLang *lang, int argc, char **argv) {
	r_return_val_if_fail (lang && argc >= 0, false);
	RLangPlugin *p = R_UNWRAP3 (lang, session, plugin);
	if (p && p->set_argv) {
		return p->set_argv (lang->session, argc, argv);
	}
	return false;
}

R_API bool r_lang_run(RLang *lang, const char *code, int len) {
	r_return_val_if_fail (lang && code, false);
	RLangPlugin *p = R_UNWRAP3 (lang, session, plugin);
	if (p && p->run) {
		return p->run (lang->session, code, len);
	}
	return false;
}

R_API bool r_lang_run_string(RLang *lang, const char *code) {
	r_return_val_if_fail (lang && code, false);
	return r_lang_run (lang, code, strlen (code));
}

R_API bool r_lang_run_file(RLang *lang, const char *file) {
	r_return_val_if_fail (lang && file, false);
	bool ret = false;
	RLangPlugin *p = R_UNWRAP3 (lang, session, plugin);
	if (p) {
		if (p->run_file) {
			ret = p->run_file (lang->session, file);
		} else {
			if (p->run) {
				size_t len;
				char *code = r_file_slurp (file, &len);
				if (!code) {
					R_LOG_ERROR ("Could not open '%s'", file);
					return 0;
				}
				ret = lang->session->plugin->run (lang->session, code, (int)len);
				free (code);
			}
		}
	}
	return ret;
}

/* TODO: deprecate or make it more modular .. reading from stdin in a lib?!? wtf */
R_API bool r_lang_prompt(RLang *lang) {
	r_return_val_if_fail (lang, false);
	char buf[1024];
	const char *p;

	if (!lang || !lang->session) {
		return false;
	}

	RLangSession *s = lang->session;
	RLangPlugin *plugin = R_UNWRAP2 (s, plugin);
	if (plugin && plugin->prompt && plugin->prompt (s)) {
		return true;
	}
	/* init line */
	RLine *line = r_line_singleton ();
	RLineHistory hist = line->history;
	RLineHistory histnull = {0};
	RLineCompletion oc = line->completion;
	RLineCompletion ocnull = {0};
	char *prompt = strdup (line->prompt);
	line->completion = ocnull;
	line->history = histnull;

	/* foo */
	for (;;) {
		r_cons_flush ();
		snprintf (buf, sizeof (buf)-1, "%s> ", plugin->meta.name);
		r_line_set_prompt (buf);
#if 0
		printf ("%s> ", lang->cur->name);
		fflush (stdout);
		fgets (buf, sizeof (buf), stdin);
		if (feof (stdin)) break;
		r_str_trim_tail (buf);
#endif
		p = r_line_readline ();
		if (!p) {
			break;
		}
		r_line_hist_add (p);
		strncpy (buf, p, sizeof (buf) - 1);
		if (*buf == '!') {
			if (buf[1]) {
				r_sandbox_system (buf + 1, 1);
			} else {
				char *foo, *code = NULL;
				do {
					foo = r_cons_editor (NULL, code);
					r_lang_run (lang, foo, 0);
					free (code);
					code = foo;
				} while (r_cons_yesno ('y', "Edit again? (Y/n)"));
				free (foo);
			}
			continue;
		}
		if (!memcmp (buf, ". ", 2)) {
			char *file = r_file_abspath (buf+2);
			if (file) {
				r_lang_run_file (lang, file);
				free (file);
			}
			continue;
		}
		if (!strcmp (buf, "q")) {
			free (prompt);
			return true;
		}
		if (!strcmp (buf, "?")) {
			RLangDef *def;
			RListIter *iter;
			eprintf("  ?	- show this help message\n"
					"  !	- run $EDITOR\n"
					"  !command - run system command\n"
					"  . file   - interpret file\n"
					"  q	- quit prompt\n");
			eprintf ("%s example:\n", plugin->meta.name);
			if (plugin->help) {
				eprintf ("%s", *plugin->help);
			}
			if (!r_list_empty (lang->defs)) {
				eprintf ("variables:\n");
			}
			r_list_foreach (lang->defs, iter, def) {
				eprintf ("  %s %s\n", def->type, def->name);
			}
		} else {
			r_lang_run (lang, buf, strlen (buf));
		}
	}
	// XXX: leaking history
	r_line_set_prompt (prompt);
	line->completion = oc;
	line->history = hist;
	clearerr (stdin);
	printf ("\n");
	free (prompt);
	return true;
}
