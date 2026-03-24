/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>

R_API bool r_bp_plugin_del(RBreakpoint *bp, const char *name) {
	R_RETURN_VAL_IF_FAIL (bp && name, false);
	RBreakpointPlugin *h = r_libstore_find_name (bp->libstore, name);
	if (h) {
		if (bp->cur == h) {
			bp->cur = NULL;
		}
		r_list_delete_data (bp->libstore->plugins, h);
		return true;
	}
	return false;
}

R_API bool r_bp_plugin_remove(RBreakpoint *bp, RBreakpointPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (bp && plugin, false);
	return r_bp_plugin_del (bp, plugin->meta.name);
}

R_API bool r_bp_use(RBreakpoint *bp, const char *name, int bits) {
	R_RETURN_VAL_IF_FAIL (bp && name, false);
	bp->bits = bits;
	RBreakpointPlugin *h = r_libstore_find_name (bp->libstore, name);
	if (h) {
		bp->cur = h;
		return true;
	}
	return false;
}

R_API char *r_bp_plugin_list(RBreakpoint *bp) {
	R_RETURN_VAL_IF_FAIL (bp, NULL);
	RListIter *iter;
	RBreakpointPlugin *b;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (bp->libstore->plugins, iter, b) {
		r_strbuf_appendf (sb, "bp %c %s\n",
			(bp->cur && !strcmp (bp->cur->meta.name, b->meta.name))? '*': '-',
			b->meta.name);
	}
	return r_strbuf_drain (sb);
}
