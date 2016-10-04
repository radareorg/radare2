/* radare - LGPL - Copyright 2009-2014 pancake */

#include <r_debug.h>
#include "../config.h"

static RDebugPlugin *debug_static_plugins[] =
	{ R_DEBUG_STATIC_PLUGINS };

R_API void r_debug_plugin_init(RDebug *dbg) {
	RDebugPlugin *static_plugin;
	int i;

	INIT_LIST_HEAD (&dbg->plugins);
	for (i=0; debug_static_plugins[i]; i++) {
		static_plugin = R_NEW (RDebugPlugin);
		memcpy (static_plugin, debug_static_plugins[i], sizeof (RDebugPlugin));
		r_debug_plugin_add (dbg, static_plugin);
	}
}

R_API bool r_debug_use(RDebug *dbg, const char *str) {
	struct list_head *pos;
	if (str) {
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
	}
	if (dbg->h && dbg->h->reg_profile) {
		char *p = dbg->h->reg_profile (dbg);
		if (p) {
			r_reg_set_profile_string (dbg->reg, p);
			if (dbg->anal) {
				//r_reg_free (dbg->anal->reg);
				dbg->anal->reg = dbg->reg;
			}
			if (dbg->h->init)
				dbg->h->init (dbg);
			r_reg_set_profile_string (dbg->reg, p);
			free (p);
		} else {
			eprintf ("Cannot retrieve reg profile from debug plugin (%s)\n", dbg->h->name);
		}
	}
	return (dbg->h != NULL);
}

R_API int r_debug_plugin_list(RDebug *dbg, int mode) {
	char spaces[16];
	int count = 0;
	struct list_head *pos;
	memset (spaces, ' ', 15);
	spaces[15] = 0;
	list_for_each_prev (pos, &dbg->plugins) {
		RDebugPlugin *h = list_entry(pos, RDebugPlugin, list);
		int sp = 8-strlen (h->name);
		spaces[sp] = 0;
		if (mode == 'q') {
			dbg->cb_printf ("%s\n", h->name);
		} else {
			dbg->cb_printf ("%d  %s  %s %s%s\n",
					count, (h == dbg->h)? "dbg": "---",
					h->name, spaces, h->license);
		}
		spaces[sp] = ' ';
		count++;
	}
	return false;
}

R_API bool r_debug_plugin_add(RDebug *dbg, RDebugPlugin *foo) {
	if (!dbg || !foo || !foo->name) return false;
	list_add_tail (&(foo->list), &(dbg->plugins));
	return true;
}
