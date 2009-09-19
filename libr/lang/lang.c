/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_lang.h>
#include <r_util.h>

R_API struct r_lang_t *r_lang_init(struct r_lang_t *lang)
{
	if (lang) {
		lang->user = NULL;
		INIT_LIST_HEAD(&lang->langs);
		INIT_LIST_HEAD(&lang->defs);
	}
	return lang;
}

R_API struct r_lang_t *r_lang_new()
{
	struct r_lang_t *lang = MALLOC_STRUCT(struct r_lang_t);
	return r_lang_init(lang);
}

R_API void *r_lang_free(struct r_lang_t *lang)
{
	r_lang_undef(lang);
	// TODO: remove langs plugins
	free(lang);
	return NULL;
}

// XXX: This is only used actually to pass 'core' structure
// TODO: when language bindings are done we will need an api to
// define symbols from C to the language namespace
// XXX: Depcreate!!
R_API void r_lang_set_user_ptr(struct r_lang_t *lang, void *user)
{
	lang->user = user;
}

R_API int r_lang_define(struct r_lang_t *lang, const char *type, const char *name, void *value)
{
	int ret = R_FALSE;
	struct r_lang_def_t *def;
	struct list_head *pos;
	list_for_each_prev(pos, &lang->langs) {
		def = list_entry(pos, struct r_lang_def_t, list);
		if (!strcmp(name, def->name)) {
			def->value = value;
			ret = R_TRUE;
			break;
		}
	}
	if (!ret) {
		def = MALLOC_STRUCT(struct r_lang_def_t);
		if (def != NULL) {
			def->type = strdup(type);
			def->name = strdup(name);
			def->value = value;
			list_add_tail(&(def->list), &lang->defs);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API void r_lang_undef(struct r_lang_t *lang)
{
	struct r_lang_def_t *def;
	struct list_head *pos, *n;
	list_for_each_safe(pos, n, &lang->langs) {
		def = list_entry(pos, struct r_lang_def_t, list);
		list_del(&def->list);
		free(def->name);
		free(def->type);
		free(def);
	}
}

R_API int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo)
{
	if (foo->init)
		foo->init(lang->user);
	list_add_tail(&(foo->list), &(lang->langs));
	return R_TRUE;
}

/* TODO: deprecate all list methods */
R_API int r_lang_list(struct r_lang_t *lang)
{
	struct list_head *pos;
	list_for_each_prev(pos, &lang->langs) {
		struct r_lang_handle_t *h = list_entry(pos, struct r_lang_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_lang_use(struct r_lang_t *lang, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &lang->langs) {
		struct r_lang_handle_t *h = list_entry(pos, struct r_lang_handle_t, list);
		if (!strcmp(h->name, name)) {
			lang->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// TODO: store in r_lang and use it from the plugin?
R_API int r_lang_set_argv(struct r_lang_t *lang, int argc, char **argv)
{
	if (lang->cur && lang->cur->set_argv)
		return lang->cur->set_argv(lang, argc, argv);
	return R_FALSE;
}

R_API int r_lang_run(struct r_lang_t *lang, const char *code, int len)
{ 
	if (lang->cur && lang->cur->run)
		return lang->cur->run(lang, code, len);
	return R_FALSE;
}

R_API int r_lang_run_file(struct r_lang_t *lang, const char *file)
{ 
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
R_API int r_lang_prompt(struct r_lang_t *lang)
{
	char buf[1024];

	if (lang->cur == NULL)
		return R_FALSE;

	if (lang->cur->prompt)
		if (lang->cur->prompt(lang) == R_TRUE)
			return R_TRUE;

	while(1) {
		printf("%s> ", lang->cur->name);
		fflush(stdout);
		fgets(buf, 1023, stdin);
		if (feof(stdin)) break;
		buf[strlen(buf)-1]='\0';
		if (!strcmp(buf, "q"))
			return R_TRUE;
		if (!strcmp(buf, "?")) {
			if (lang->cur->help)
				printf(*lang->cur->help);
		} else r_lang_run(lang, buf, strlen(buf));
	}
	return R_TRUE;
}
