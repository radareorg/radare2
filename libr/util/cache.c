/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_util.h>

void r_cache_init(struct r_cache_t *c)
{
	INIT_LIST_HEAD(&c->items);
}

struct r_cache_t *r_cache_new()
{
	struct r_cache_t *a = MALLOC_STRUCT(struct r_cache_t);
	r_cache_init(a);
	return a;
}

void r_cache_free(struct r_cache_t *a)
{
	free(a);
}

char *r_cache_get(struct r_cache_t *c, u64 addr)
{
	struct list_head *pos;
	list_for_each_prev(pos, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr == addr)
			return h->str;
	}
	return NULL;
}

int r_cache_set(struct r_cache_t *c, u64 addr, char *str)
{
	struct r_cache_item_t *a = MALLOC_STRUCT(struct r_cache_item_t);
	a->addr = addr;
	a->str = strdup(str);
	list_add_tail(&(a->list), &(c->items));
	return R_TRUE;
}

int r_cache_validate(struct r_cache_t *c, u64 from, u64 to)
{
	int ret = R_FALSE;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr <from || h->addr > to) {
			free(h->str);
			list_del(&h->list);
			ret = R_TRUE;
		}
	}
	return ret;
}

int r_cache_invalidate(struct r_cache_t *c, u64 from, u64 to)
{
	int ret = R_FALSE;
	struct list_head *pos, *n;
	list_for_each_safe(pos, n, &c->items) {
		struct r_cache_item_t *h = list_entry(pos, struct r_cache_item_t, list);
		if (h->addr >=from && h->addr <= to) {
			free(h->str);
			list_del(&h->list);
			ret = R_TRUE;
		}
	}
	return ret;
}
