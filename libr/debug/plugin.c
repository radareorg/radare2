/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>
#include "../config.h"

/* plugin pointers */
extern RDebugPlugin r_debug_plugin_native;
extern RDebugPlugin r_debug_plugin_gdb;

static RDebugPlugin *debug_static_plugins[] = 
	{ R_DEBUG_STATIC_PLUGINS };

R_API int r_debug_plugin_init(RDebug *dbg) {
	RDebugPlugin *static_plugin;
	int i;

	dbg->reg_profile = NULL;
	INIT_LIST_HEAD(&dbg->plugins);
	for (i=0; debug_static_plugins[i]; i++) {
		static_plugin = R_NEW (RDebugPlugin);
		memcpy (static_plugin, debug_static_plugins[i], sizeof (RDebugPlugin));
		r_debug_plugin_add (dbg, static_plugin);
	}
	return R_TRUE;
}

R_API int r_debug_use(RDebug *dbg, const char *str) {
	struct list_head *pos;
	list_for_each_prev (pos, &dbg->plugins) {
		RDebugPlugin *h = list_entry (pos, RDebugPlugin, list);
		if (!strcmp (str, h->name)) {
			dbg->h = h;
			if (h->reg_profile) {
				free (dbg->reg_profile);
				dbg->reg_profile = dbg->h->reg_profile ();
				dbg->anal->reg = dbg->reg;
				r_reg_set_profile_string (dbg->reg, dbg->reg_profile);
			}
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_debug_plugin_list(RDebug *dbg) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &dbg->plugins) {
		RDebugPlugin *h = list_entry(pos, RDebugPlugin, list);
		eprintf ("dbg %d %s %s\n", count, h->name, ((h==dbg->h)?"*":""));
		count++;
	}
	return R_FALSE;
}

R_API int r_debug_plugin_add(RDebug *dbg, RDebugPlugin *foo) {
	list_add_tail(&(foo->list), &(dbg->plugins));
	return R_TRUE;
}
