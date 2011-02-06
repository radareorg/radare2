/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_lang.h>
#include <r_util.h>

#include "p/vala.c" // hardcoded

R_API RLang *r_lang_new() {
	RLang *lang = R_NEW (RLang);
	if (lang) {
		lang->user = NULL;
		lang->langs = r_list_new ();
		lang->langs->free = (RListFree)r_lang_plugin_free;
		lang->defs = r_list_new ();
		lang->defs->free = (RListFree)r_lang_def_free;
	}
	return lang;
}

R_API void *r_lang_free(RLang *lang) {
	r_lang_undef (lang, NULL);
	r_list_free (lang->langs);
	r_list_free (lang->defs);
	// TODO: remove langs plugins
	free (lang);
	return NULL;
}

// XXX: This is only used actually to pass 'core' structure
// TODO: when language bindings are done we will need an api to
// define symbols from C to the language namespace
// XXX: Depcreate!!
R_API void r_lang_set_user_ptr(RLang *lang, void *user) {
	lang->user = user;
}

R_API int r_lang_define(RLang *lang, const char *type, const char *name, void *value) {
	RLangDef *def;
	RListIter *iter;
	r_list_foreach (lang->defs, iter, def) {
		if (!strcmp (name, def->name)) {
			def->value = value;
			return  R_TRUE;
		}
	}
	def = R_NEW (RLangDef);
	if (def != NULL) {
		def->type = strdup (type);
		def->name = strdup (name);
		def->value = value;
		r_list_append (lang->defs, def);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API void r_lang_def_free (RLangDef *def) {
	free (def->name);
	free (def->type);
	free (def);
}

R_API void r_lang_undef(RLang *lang, const char *name) {
	if (name != NULL && *name) {
		RLangDef *def;
		RListIter *iter;
		r_list_foreach (lang->defs, iter, def) {
			if (!strcmp (name, def->name)) {
				r_list_delete (lang->defs, iter);
				break;
			}
		}
	} else r_list_destroy (lang->defs);
}

R_API int r_lang_setup(RLang *lang) {
	if (lang->cur && lang->cur->setup)
		return lang->cur->setup (lang);
	return R_FALSE;
}

R_API void r_lang_plugin_free (RLang *lang, RLangPlugin *p) {
	if (p && p->fini)
		p->fini (lang->user);
}

R_API int r_lang_add(RLang *lang, RLangPlugin *foo) {
	if (foo) {
		if (foo->init)
			foo->init (lang->user);
		r_list_append (lang->langs, foo);
	}
	return R_TRUE;
}

/* TODO: deprecate all list methods */
R_API int r_lang_list(RLang *lang) {
	RListIter *iter;
	RLangPlugin *h;
	r_list_foreach (lang->langs, iter, h) {
		printf (" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_lang_use(RLang *lang, const char *name) {
	RListIter *iter;
	RLangPlugin *h;
	r_list_foreach (lang->langs, iter, h) {
		if (!strcmp (h->name, name)) {
			lang->cur = h;
			return R_TRUE;
		}
	}
	lang->cur = NULL;
	return R_FALSE;
}

// TODO: store in r_lang and use it from the plugin?
R_API int r_lang_set_argv(RLang *lang, int argc, char **argv) {
	if (lang->cur && lang->cur->set_argv)
		return lang->cur->set_argv (lang, argc, argv);
	return R_FALSE;
}

R_API int r_lang_run(RLang *lang, const char *code, int len) { 
	if (lang->cur && lang->cur->run)
		return lang->cur->run (lang, code, len);
	return R_FALSE;
}

R_API int r_lang_run_string(RLang *lang, const char *code) {
	return r_lang_run (lang, code, strlen (code));
}

R_API int r_lang_run_file(RLang *lang, const char *file) { 
	int len, ret = R_FALSE;
	if (lang->cur) {
		if (lang->cur->run_file == NULL) {
			if (lang->cur->run != NULL) {
				char *code = r_file_slurp (file, &len);
				ret = lang->cur->run (lang, code, len);
				free (code);
			}
		} else ret = lang->cur->run_file (lang, file);
	}
	return ret;
}

/* TODO: deprecate or make it more modular .. reading from stdin in a lib?!? wtf */
R_API int r_lang_prompt(RLang *lang) {
	char buf[1024];

	if (lang->cur == NULL)
		return R_FALSE;

	if (lang->cur->prompt)
		if (lang->cur->prompt(lang) == R_TRUE)
			return R_TRUE;
	for (;;) {
		printf ("%s> ", lang->cur->name);
		fflush (stdout);
		fgets (buf, sizeof (buf)-1, stdin);
		if (feof (stdin)) break;
		buf[strlen (buf)-1]='\0';
		if (!strcmp (buf, "q"))
			return R_TRUE;
		if (!strcmp (buf, "?")) {
			if (lang->cur) {
				printf ("Help for %s scripting prompt:\n", lang->cur->name);
				if (lang->cur->help)
					printf ("%s", *lang->cur->help);
			} else printf ("no selected r_lang plugin\n");
			printf ("  ?    - show this help message\n"
				"  q    - quit\n");
		} else r_lang_run (lang, buf, strlen (buf));
	}
	clearerr (stdin);
	printf ("\n");
	return R_TRUE;
}
