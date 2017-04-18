/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>

R_API int r_bp_plugin_del(RBreakpoint *bp, const char *name) {
	RListIter *iter;
	RBreakpointPlugin *h;
	if (name && *name) {
		r_list_foreach (bp->plugins, iter, h) {
			if (!strcmp (h->name, name)) {
				if (bp->cur == h) {
					bp->cur = NULL;
				}
				r_list_delete (bp->plugins, iter);
				bp->nbps--;
				return true;
			}
		}
	}
	return false;
}

R_API int r_bp_plugin_add(RBreakpoint *bp, RBreakpointPlugin *foo) {
	RListIter *iter;
	RBreakpointPlugin *h;
	if (!bp) {
		eprintf ("Cannot add plugin because dbg->bp is null and/or plugin is null\n");
		return false;
	}
	/* avoid dupped plugins */
	r_list_foreach (bp->bps, iter, h) {
		if (!strcmp (h->name, foo->name)) {
			return false;
		}
	}
	bp->nbps++;
	r_list_append (bp->plugins, foo);
	return true;
}

R_API int r_bp_use(RBreakpoint *bp, const char *name, int bits) {
	RListIter *iter;
	bp->bits = bits;
	RBreakpointPlugin *h;
	r_list_foreach (bp->plugins, iter, h) {
		if (!strcmp (h->name, name)) {
			bp->cur = h;
			return true;
		}
	}
	return false;
}

// TODO: deprecate
R_API void r_bp_plugin_list(RBreakpoint *bp) {
	RListIter *iter;
	RBreakpointPlugin *b;
	r_list_foreach (bp->plugins, iter, b) {
		bp->cb_printf ("bp %c %s\n",
			(bp->cur && !strcmp (bp->cur->name, b->name))? '*': '-',
			b->name);
	}
}
