/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

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

	INIT_LIST_HEAD (&dbg->plugins);
	for (i=0; debug_static_plugins[i]; i++) {
		static_plugin = R_NEW (RDebugPlugin);
		memcpy (static_plugin, debug_static_plugins[i], sizeof (RDebugPlugin));
		r_debug_plugin_add (dbg, static_plugin);
	}
	return R_TRUE;
}

R_API int r_debug_use(RDebug *dbg, const char *str) {
	struct list_head *pos;
	if (str)
	list_for_each_prev (pos, &dbg->plugins) {
		RDebugPlugin *h = list_entry (pos, RDebugPlugin, list);
		if (h->name && !strcmp (str, h->name)) {
			dbg->h = h;
			dbg->bp->breakpoint = dbg->h->breakpoint;
			dbg->bp->user = dbg;
		}
	}
	if (dbg->h && dbg->h->reg_profile) {
		char *p = dbg->h->reg_profile ();
		if (p == NULL) {
			eprintf ("Cannot retrieve reg profile from debug plugin\n");
		} else {
			free (dbg->reg->reg_profile_str);
			dbg->reg->reg_profile_str = p;
			if (dbg->anal)
				dbg->anal->reg = dbg->reg;
			if (dbg->h->init)
				dbg->h->init (dbg);
			r_reg_set_profile_string (dbg->reg, p);
		}
	}
	return (dbg->h != NULL);
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
	list_add_tail (&(foo->list), &(dbg->plugins));
	return R_TRUE;
}
