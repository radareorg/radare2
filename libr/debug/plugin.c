/* radare - LGPL - Copyright 2009-2014 pancake */

#include <r_debug.h>
#include "../config.h"

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
			if (dbg->anal && dbg->anal->cur)
				r_debug_set_arch (dbg, dbg->anal->cur->arch, dbg->bits);
			dbg->bp->breakpoint = dbg->h->breakpoint;
			dbg->bp->user = dbg;
		}
	}
	if (dbg->h && dbg->h->reg_profile) {
		char *p = dbg->h->reg_profile (dbg);
		if (p == NULL) {
			eprintf ("Cannot retrieve reg profile from debug plugin (%s)\n", dbg->h->name);
		} else {
			r_reg_set_profile_string (dbg->reg, p);
			if (dbg->anal)
				dbg->anal->reg = dbg->reg;
			if (dbg->h->init)
				dbg->h->init (dbg);
			r_reg_set_profile_string (dbg->reg, p);
			free (p);
		}
	}
	return (dbg->h != NULL);
}

R_API int r_debug_plugin_list(RDebug *dbg) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &dbg->plugins) {
		RDebugPlugin *h = list_entry(pos, RDebugPlugin, list);
		eprintf ("dbg %d %s %s (%s)\n", count,
			h->name, ((h==dbg->h)?"*":""), h->license);
		count++;
	}
	return R_FALSE;
}

R_API int r_debug_plugin_add(RDebug *dbg, RDebugPlugin *foo) {
	if (!foo->name) return R_FALSE;
	list_add_tail (&(foo->list), &(dbg->plugins));
	return R_TRUE;
}
