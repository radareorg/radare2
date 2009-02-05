/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

/* XXX move to debug_init() ?? */
int r_debug_handle_init(struct r_debug_t *dbg)
{
	INIT_LIST_HEAD(&dbg->handlers);
	return R_TRUE;
}

int r_debug_handle_set(struct r_debug_t *dbg, const char *str)
{
	struct list_head *pos;
	list_for_each_prev(pos, &dbg->handlers) {
		struct r_debug_handle_t *h = list_entry(pos, struct r_debug_handle_t, list);
		if (!strcmp(str, h->name)) {
			dbg->h = h;
			return R_TRUE;
		}
	}
	
	return R_FALSE;
}

int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo)
{
	list_add_tail(&(foo->list), &(dbg->handlers));
	return R_TRUE;
}
