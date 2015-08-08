/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>

R_API int r_bp_plugin_del(RBreakpoint *bp, const char *name) {
//TODO: r_bp_plugin_del
	return R_FALSE;
}

R_API int r_bp_plugin_add(RBreakpoint *bp, RBreakpointPlugin *foo) {
	RListIter *iter;
	RBreakpointPlugin *h;
	if (bp == NULL) {
		eprintf ("Cannot add plugin because dbg->bp is null and/or plugin is null\n");
		return R_FALSE;
	}
	/* avoid dupped plugins */
	r_list_foreach (bp->bps, iter, h) {
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	bp->nbps++;
	r_list_append (bp->plugins, foo);
	return R_TRUE;
}

R_API int r_bp_use(RBreakpoint *bp, const char *name, int bits) {
	RListIter *iter;
	bp->bits = bits;
	RBreakpointPlugin *h;
	r_list_foreach (bp->plugins, iter, h) {
		if (!strcmp (h->name, name)) {
			bp->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// TODO: deprecate
R_API void r_bp_plugin_list(RBreakpoint *bp) {
	RListIter *iter;
	RBreakpointPlugin *b;
	r_list_foreach (bp->plugins, iter, b) {
		bp->cb_printf ("bp %c %s\n", 
			(bp->cur && !strcmp (bp->cur->name, b->name))?'*':'-',
			b->name);
	}
}
