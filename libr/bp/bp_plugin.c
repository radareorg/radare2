/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>

R_API int r_bp_plugin_del(RBreakpoint *bp, const char *name) {
	RListIter *iter;
	RBreakpointPlugin *h;
	if (name && *name) {
		r_list_foreach (bp->plugins, iter, h) {
			if (!strcmp (h->meta.name, name)) {
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
		R_LOG_ERROR ("Cannot add plugin because dbg->bp is null and/or plugin is null");
		return false;
	}
	/* avoid dupped plugins */
	r_list_foreach (bp->bps, iter, h) {
		if (!strcmp (h->meta.name, foo->meta.name)) {
			return false;
		}
	}
	bp->nbps++;
	r_list_append (bp->plugins, foo);
	return true;
}

R_API int r_bp_plugin_remove(RBreakpoint *bp, RBreakpointPlugin *plugin) {
	// R2_590 TODO
	return true;
}

R_API int r_bp_use(RBreakpoint *bp, const char *name, int bits) {
	RListIter *iter;
	bp->bits = bits;
	RBreakpointPlugin *h;
	r_list_foreach (bp->plugins, iter, h) {
		if (!strcmp (h->meta.name, name)) {
			bp->cur = h;
			return true;
		}
	}
	return false;
}

R_API char *r_bp_plugin_list(RBreakpoint *bp) {
	RListIter *iter;
	RBreakpointPlugin *b;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (bp->plugins, iter, b) {
		r_strbuf_appendf (sb, "bp %c %s\n",
			(bp->cur && !strcmp (bp->cur->meta.name, b->meta.name))? '*': '-',
			b->meta.name);
	}
	return r_strbuf_drain (sb);
}
