/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_lang.h>
#include <r_util.h>

R_API RLang *r_lang_new() {
	RLang *lang;
	
	lang = R_NEW (RLang);
	if (lang) {
		lang->user = NULL;
		INIT_LIST_HEAD (&lang->langs);
		INIT_LIST_HEAD (&lang->defs);
	}
	return lang;
}

R_API void *r_lang_free(RLang *lang) {
	r_lang_undef (lang);
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
	int ret = R_FALSE;
	RLangDef *def = NULL;
	struct list_head *pos;
	list_for_each_prev (pos, &lang->defs) {
		def = list_entry (pos, RLangDef, list);
		if (!strcmp (name, def->name)) {
			def->value = value;
			ret = R_TRUE;
			break;
		}
	}
	if (!ret) {
		def = R_NEW (RLangDef);
		if (def != NULL) {
			def->type = strdup (type);
			def->name = strdup (name);
			def->value = value;
			list_add_tail (&(def->list), &lang->defs);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API void r_lang_undef(RLang *lang) {
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &lang->defs) {
		RLangDef *def = list_entry (pos, RLangDef, list);
		list_del (&def->list);
		free (def->name);
		free (def->type);
		free (def);
	}
}

R_API int r_lang_setup(RLang *lang) {
	int ret = R_FALSE;
	if (lang->cur && lang->cur->setup)
		ret = lang->cur->setup (lang);
	return ret;
}

R_API int r_lang_add(RLang *lang, struct r_lang_plugin_t *foo) {
	if (foo->init)
		foo->init (lang->user);
	list_add_tail (&(foo->list), &(lang->langs));
	return R_TRUE;
}

/* TODO: deprecate all list methods */
R_API int r_lang_list(RLang *lang) {
	struct list_head *pos;
	list_for_each_prev (pos, &lang->langs) {
		RLangPlugin *h = list_entry (pos, RLangPlugin, list);
		printf (" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_lang_use(RLang *lang, const char *name) {
	struct list_head *pos;
	list_for_each_prev(pos, &lang->langs) {
		struct r_lang_plugin_t *h = list_entry (pos, struct r_lang_plugin_t, list);
		if (!strcmp (h->name, name)) {
			lang->cur = h;
			return R_TRUE;
		}
	}
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
				char *code = r_file_slurp(file, &len);
				ret = lang->cur->run(lang, code, len);
				free(code);
			}
		} else ret = lang->cur->run_file(lang, file);
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
			if (lang->cur->help)
				printf ("%s", *lang->cur->help);
		} else r_lang_run (lang, buf, strlen(buf));
	}
	clearerr (stdin);
	printf ("\n");
	return R_TRUE;
}
