/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_lang.h>
#include <r_util.h>

int r_lang_init(struct r_lang_t *lang)
{
	lang->user = NULL;
	INIT_LIST_HEAD(&lang->langs);
	return R_TRUE;
}

void r_lang_set_user_ptr(struct r_lang_t *lang, void *user)
{
	lang->user = user;
}

int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo)
{
	if (foo->init)
		foo->init(lang->user);
	list_add_tail(&(foo->list), &(lang->langs));
	return R_TRUE;
}

int r_lang_list(struct r_lang_t *lang)
{
	struct list_head *pos;
	list_for_each_prev(pos, &lang->langs) {
		struct r_lang_handle_t *h = list_entry(pos, struct r_lang_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_lang_set(struct r_lang_t *lang, const char *name)
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

int r_lang_set_argv(struct r_lang_t *lang, int argc, char **argv)
{
	if (lang->cur && lang->cur->set_argv)
		return lang->cur->set_argv(lang->user, argc, argv);
	return R_FALSE;
}

int r_lang_run(struct r_lang_t *lang, const char *code, int len)
{ 
	if (lang->cur && lang->cur->run)
		return lang->cur->run(lang->user, code, len);
	return R_FALSE;
}

int r_lang_run_file(struct r_lang_t *lang, const char *file)
{ 
	int len, ret = R_FALSE;
	if (lang->cur) {
		if (lang->cur->run_file == NULL) {
			if (lang->cur->run != NULL) {
				char *code = r_file_slurp(file, &len);
				ret = lang->cur->run(lang->user, code, len);
				free(code);
			}
		} else ret = lang->cur->run_file(lang->user, file);
	}
	return ret;
}

int r_lang_prompt(struct r_lang_t *lang)
{
	char buf[1024];

	if (lang->cur == NULL)
		return R_FALSE;

	if (lang->cur->prompt)
		if (lang->cur->prompt(lang->user) == R_TRUE)
			return R_TRUE;

	while(1) {
		printf("%s> ", lang->cur->name);
		fflush(stdout);
		fgets(buf, 1023, stdin);
		if (feof(stdin)) break;
		buf[strlen(buf)-1]='\0';
		if (!strcmp(buf, "q"))
			return R_TRUE;
		if (!strcmp(buf, "?"))
			printf(*lang->cur->help);
		else r_lang_run(lang, buf, strlen(buf));
	}
	return R_TRUE;
}
