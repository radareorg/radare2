/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_util.h>

R_API struct r_cache_t *r_cache_new()
{
	RCache *a;
	
	a = R_NEW (RCache);
	if (a)
		INIT_LIST_HEAD(&a->items);
	return a;
}

R_API void r_cache_free(struct r_cache_t *a)
{
	free(a);
}

R_API char *r_cache_get(struct r_cache_t *c, ut64 addr)
{
	struct list_head *pos;
	list_for_each_prev(pos, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr == addr)
			return h->str;
	}
	return NULL;
}

R_API int r_cache_set(struct r_cache_t *c, ut64 addr, char *str)
{
	struct r_cache_item_t *a = R_NEW(struct r_cache_item_t);
	a->addr = addr;
	a->str = strdup(str);
	list_add_tail(&(a->list), &(c->items));
	return R_TRUE;
}

R_API int r_cache_validate(struct r_cache_t *c, ut64 start, ut64 end)
{
	int ret = R_FALSE;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr <start || h->addr > end) {
			free(h->str);
			list_del(&h->list);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API int r_cache_invalidate(struct r_cache_t *c, ut64 start, ut64 end)
{
	int ret = R_FALSE;
	struct list_head *pos, *n;
	list_for_each_safe(pos, n, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr >=start && h->addr <= end) {
			free(h->str);
			list_del(&h->list);
			ret = R_TRUE;
		}
	}
	return ret;
}
