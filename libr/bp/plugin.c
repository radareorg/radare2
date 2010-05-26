/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_bp.h>

R_API int r_bp_plugin_del(struct r_bp_t *bp, const char *name)
{
#warning TODO: r_bp_plugin_del
	return R_FALSE;
}

R_API int r_bp_plugin_add(struct r_bp_t *bp, struct r_bp_plugin_t *foo)
{
	struct list_head *pos;
	if (bp == NULL) {
		eprintf("Cannot add plugin because dbg->bp is null and/or handle is null\n");
		return R_FALSE;
	}
	/* avoid dupped plugins */
	list_for_each_prev (pos, &bp->bps) {
		struct r_bp_plugin_t *h = list_entry (pos, struct r_bp_plugin_t, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	bp->nbps++;
	list_add_tail (&(foo->list), &(bp->plugins));
	return R_TRUE;
}

R_API int r_bp_use(struct r_bp_t *bp, const char *name)
{
	struct list_head *pos;
	list_for_each_prev (pos, &bp->plugins) {
		struct r_bp_plugin_t *h = list_entry(pos, struct r_bp_plugin_t, list);
		if (!strcmp (h->name, name)) {
			bp->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// TODO: deprecate
R_API void r_bp_plugin_list(struct r_bp_t *bp) {
	struct r_bp_plugin_t *b;
	struct list_head *pos;
	list_for_each (pos, &bp->plugins) {
		b = list_entry(pos, struct r_bp_plugin_t, list);
		printf ("bp %c %s\n", 
			(bp->cur && !strcmp (bp->cur->name, b->name))?'*':'-',
			b->name);
	}
}
