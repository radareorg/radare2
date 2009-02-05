/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_lang.h>

int r_lang_init(struct r_lang_t *lang)
{
	INIT_LIST_HEAD(&lang->langs);
	return R_TRUE;
}

int r_lang_add(struct r_lang_t *lang, struct r_lang_handle_t *foo)
{
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

//int r_lang_set_args
//int r_lang_set_code(struct r_lang_t *lang, const char *code, int len)
int r_lang_run(struct r_lang_t *lang, const char *code, int len)
{ 
	if (lang->cur) {
		//lang->cur->run(code, len);
		return R_TRUE;
	}
	return R_FALSE;
}
