/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>
#include "../config.h"

/* plugin pointers */
extern RDebugHandle r_debug_plugin_native;
extern RDebugHandle r_debug_plugin_gdb;

static RDebugHandle *debug_static_plugins[] = 
	{ R_DEBUG_STATIC_PLUGINS };

R_API int r_debug_handle_init(RDebug *dbg) {
	int i;
	dbg->reg_profile = NULL;
	INIT_LIST_HEAD(&dbg->handlers);
	for (i=0; debug_static_plugins[i]; i++)
		r_debug_handle_add (dbg, debug_static_plugins[i]);
	return R_TRUE;
}

R_API int r_debug_use(RDebug *dbg, const char *str) {
	struct list_head *pos;
	list_for_each_prev (pos, &dbg->handlers) {
		RDebugHandle *h = list_entry (pos, RDebugHandle, list);
		if (!strcmp (str, h->name)) {
			dbg->h = h;
			if (h->reg_profile) {
				free (dbg->reg_profile);
				dbg->reg_profile = dbg->h->reg_profile ();
				r_reg_set_profile_string (dbg->reg, dbg->reg_profile);
			}
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_debug_handle_list(RDebug *dbg) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &dbg->handlers) {
		RDebugHandle *h = list_entry(pos, RDebugHandle, list);
		eprintf ("dbg %d %s %s\n", count, h->name, ((h==dbg->h)?"*":""));
		count++;
	}
	return R_FALSE;
}

R_API int r_debug_handle_add(RDebug *dbg, RDebugHandle *foo) {
	list_add_tail(&(foo->list), &(dbg->handlers));
	return R_TRUE;
}
