/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_meta.h"

struct r_meta_t *r_meta_new()
{
	struct r_meta_t *m = MALLOC_STRUCT(struct r_meta_t);
	r_meta_init(m);
	return m;
}

void r_meta_free(struct r_meta_t *m)
{
	free(m);
}

int r_meta_init(struct r_meta_t *m)
{
	INIT_LIST_HEAD(&m->data);
	INIT_LIST_HEAD(&m->comments);
	INIT_LIST_HEAD(&m->xrefs);
	return R_TRUE;
}

/* snippet from data.c */
/* XXX: we should add a 4th arg to define next or prev */
u64 r_meta_prev(struct r_meta_t *m, u64 off, int type)
{
	struct list_head *pos;
	u64 ret = 0;

	list_for_each(pos, &m->data) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		if (d->type == type) {
			if (d->from < off && d->to > off)
				ret = d->from;
		}
	}
	return ret;
}

//int data_get_fun_for(u64 addr, u64 *from, u64 *to)
int r_meta_get_bounds(struct r_meta_t *m, u64 addr, int type, u64 *from, u64 *to)
{
	struct list_head *pos;
	int n_functions = 0;
	int n_xrefs = 0;
	int n_dxrefs = 0;
	struct r_meta_item_t *rd = NULL;
	u64 lastfrom = 0LL;

	list_for_each(pos, &m->data) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		if (d->type == type) {
			if (d->from < addr && d->from > lastfrom)
				rd = d;
		}
	}
	if (rd) {
		*from = rd->from;
		*to = rd->to;
		return 1;
	}
	return 0;
}
