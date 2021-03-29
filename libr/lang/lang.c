/* radare2 - LGPL - Copyright 2009-2021 - pancake */

#include <r_lang.h>
#include <r_util.h>

R_LIB_VERSION(r_lang);

#include "p/pipe.c"  // hardcoded
#include "p/vala.c"  // hardcoded
#include "p/rust.c"  // hardcoded
#include "p/zig.c"   // hardcoded
#include "p/spp.c"   // hardcoded
#include "p/c.c"     // hardcoded
#include "p/v.c"     // hardcoded
#include "p/lib.c"
#if __UNIX__
#include "p/cpipe.c" // hardcoded
#endif

static RLang *__lang = NULL;

R_API void r_lang_plugin_free (RLangPlugin *p) {
	if (p && p->fini) {
		p->fini (__lang);
	}
}

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
	lang->langs->free = (RListFree)r_lang_plugin_free;
	lang->defs = r_list_new ();
	if (!lang->defs) {
		r_lang_free (lang);
		return NULL;
	}
	lang->defs->free = (RListFree)r_lang_def_free;
	lang->cb_printf = (PrintfCallback)printf;
#if __UNIX__
	r_lang_add (lang, &r_lang_plugin_c);
	r_lang_add (lang, &r_lang_plugin_cpipe);
#endif
	r_lang_add (lang, &r_lang_plugin_vala);
	r_lang_add (lang, &r_lang_plugin_rust);
	r_lang_add (lang, &r_lang_plugin_zig);
	r_lang_add (lang, &r_lang_plugin_v);
	r_lang_add (lang, &r_lang_plugin_spp);
	r_lang_add (lang, &r_lang_plugin_pipe);
	r_lang_add (lang, &r_lang_plugin_lib);

	return lang;
}

R_API void r_lang_free(RLang *lang) {
	if (lang) {
		__lang = NULL;
		r_lang_undef (lang, NULL);
		r_list_free (lang->langs);
		r_list_free (lang->defs);
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

R_API void r_lang_def_free (RLangDef *def) {
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
	if (lang && lang->cur && lang->cur->setup) {
		return lang->cur->setup (lang);
	}
	return false;
}

R_API bool r_lang_add(RLang *lang, RLangPlugin *foo) {
	if (foo && (!r_lang_get_by_name (lang, foo->name))) {
		if (foo->init) {
			foo->init (lang);
		}
		r_list_append (lang->langs, foo);
		return true;
	}
	return false;
}

/* TODO: deprecate all list methods */
R_API bool r_lang_list(RLang *lang) {
	RListIter *iter;
	RLangPlugin *h;
	if (!lang) {
		return false;
	}
	r_list_foreach (lang->langs, iter, h) {
		const char *license = h->license
			? h->license : "???";
		lang->cb_printf ("%s: (%s) %s\n",
			h->name, license, h->desc);
	}
	return true;
}

R_API RLangPlugin *r_lang_get_by_extension (RLang *lang, const char *ext) {
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

R_API RLangPlugin *r_lang_get_by_name (RLang *lang, const char *name) {
	RListIter *iter;
	RLangPlugin *h;
	r_list_foreach (lang->langs, iter, h) {
		if (!r_str_casecmp (h->name, name)) {
			return h;
		}
		if (h->alias && !r_str_casecmp (h->alias, name)) {
			return h;
		}
	}
	return NULL;
}

R_API bool r_lang_use(RLang *lang, const char *name) {
	RLangPlugin *h = r_lang_get_by_name (lang, name);
	if (h) {
		lang->cur = h;
		return true;
	}
	return false;
}

// TODO: store in r_lang and use it from the plugin?
R_API bool r_lang_set_argv(RLang *lang, int argc, char **argv) {
	if (lang->cur && lang->cur->set_argv) {
		return lang->cur->set_argv (lang, argc, argv);
	}
	return false;
}

R_API bool r_lang_run(RLang *lang, const char *code, int len) {
	if (lang->cur && lang->cur->run) {
		return lang->cur->run (lang, code, len);
	}
	return false;
}

R_API bool r_lang_run_string(RLang *lang, const char *code) {
	return r_lang_run (lang, code, strlen (code));
}

R_API bool r_lang_run_file(RLang *lang, const char *file) {
	bool ret = false;
	if (lang->cur) {
		if (!lang->cur->run_file) {
			if (lang->cur->run) {
				size_t len;
				char *code = r_file_slurp (file, &len);
				if (!code) {
					eprintf ("Could not open '%s'.\n", file);
					return 0;
				}
				ret = lang->cur->run (lang, code, (int)len);
				free (code);
			}
		} else {
			ret = lang->cur->run_file (lang, file);
		}
	}
	return ret;
}

/* TODO: deprecate or make it more modular .. reading from stdin in a lib?!? wtf */
R_API bool r_lang_prompt(RLang *lang) {
	char buf[1024];
	const char *p;

	if (!lang || !lang->cur) {
		return false;
	}

	if (lang->cur->prompt) {
		if (lang->cur->prompt (lang)) {
			return true;
		}
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
		snprintf (buf, sizeof (buf)-1, "%s> ", lang->cur->name);
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
			eprintf("  ?        - show this help message\n"
				"  !        - run $EDITOR\n"
				"  !command - run system command\n"
				"  . file   - interpret file\n"
				"  q        - quit prompt\n");
			eprintf ("%s example:\n", lang->cur->name);
			if (lang->cur->help) {
				eprintf ("%s", *lang->cur->help);
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
