/* radare - LGPL - Copyright 2009-2017 pancake */

#include <r_debug.h>
#include <config.h>

R_GENERATE_VEC_IMPL_FOR(DebugPluginData, RDebugPluginData);

static RDebugPlugin *debug_static_plugins[] = {
	R_DEBUG_STATIC_PLUGINS
};

R_API void r_debug_init_debug_plugins(RDebug *dbg) {
	int i;
	dbg->plugins = RVecDebugPluginData_new ();
	for (i = 0; debug_static_plugins[i]; i++) {
		r_debug_plugin_add (dbg, debug_static_plugins[i]);
	}
}

R_API bool r_debug_use(RDebug *dbg, const char *str) {
	RDebugPluginData *dpd = NULL;
	if (dbg && str) {
		R_VEC_FOREACH (dbg->plugins, dpd) {
			if (dpd->plugin.meta.name && !strcmp (str, dpd->plugin.meta.name)) {
				dbg->h = &dpd->plugin;
				if (dbg->anal && dbg->anal->cur) {
					r_debug_set_arch (dbg, dbg->anal->cur->arch, dbg->bits);
				}
				dbg->bp->breakpoint = dbg->h->breakpoint;
				dbg->bp->user = dbg;
			}
		}
	}
	if (dbg && dbg->h && dbg->h->reg_profile) {
		char *p = dbg->h->reg_profile (dbg);
		if (p) {
			r_reg_set_profile_string (dbg->reg, p);
			if (dbg->anal && dbg->reg != dbg->anal->reg) {
				r_reg_free (dbg->anal->reg);
				dbg->anal->reg = dbg->reg;
			}
			if (dbg->h->init) {
				// TODO pass in plugin data instead of looking it up again
				dbg->h->init (dbg);
			}
			r_reg_set_profile_string (dbg->reg, p);
			free (p);
		} else {
			R_LOG_ERROR ("Cannot retrieve reg profile from debug plugin (%s)", dbg->h->meta.name);
		}
	}
	return (dbg && dbg->h);
}

R_API bool r_debug_plugin_list(RDebug *dbg, int mode) {
	char spaces[16];
	int count = 0;
	memset (spaces, ' ', 15);
	spaces[15] = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = dbg->pj;
		if (!pj) {
			return false;
		}
		pj_a (pj);
	}

	RDebugPluginData *dpd;
	R_VEC_FOREACH (dbg->plugins, dpd) {
		int sp = 8 - strlen (dpd->plugin.meta.name);
		spaces[sp] = 0;
		if (mode == 'q') {
			dbg->cb_printf ("%s\n", dpd->plugin.meta.name);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", dpd->plugin.meta.name);
			pj_ks (pj, "license", dpd->plugin.meta.license);
			pj_end (pj);
		} else {
			dbg->cb_printf ("%d  %s  %s %s%s\n",
					count, (&dpd->plugin == dbg->h)? "dbg": "---",
					dpd->plugin.meta.name, spaces, dpd->plugin.meta.license);
		}
		spaces[sp] = ' ';
		count++;
	}
	if (mode == 'j') {
		pj_end (pj);
		dbg->cb_printf ("%s\n", pj_string (pj));
	}
	return true;
}

R_API bool r_debug_plugin_add(RDebug *dbg, RDebugPlugin *plugin) {
	if (!dbg || !plugin || !plugin->meta.name) {
		return false;
	}

	RDebugPluginData *dpd = RVecDebugPluginData_emplace_back (dbg->plugins);
	if (!dpd) {
		return false;
	}

	memcpy (&dpd->plugin, plugin, sizeof (RDebugPlugin));
	dpd->plugin_data = NULL;
	return true;
}

static inline int find_debug_plugin_by_name(RDebugPluginData *dpd, void *p) {
	RDebugPlugin *plugin = p;
	return strcmp (dpd->plugin.meta.name, plugin->meta.name);
}

static inline void debug_plugin_fini(RDebugPluginData *dpd, void *user) {
	R_FREE (dpd->plugin_data);
}

R_API bool r_debug_plugin_remove(RDebug *dbg, RDebugPlugin *plugin) {
	if (!dbg || !plugin) {
		return false;
	}

	RDebugPluginData *dpd = RVecDebugPluginData_find (dbg->plugins, plugin, find_debug_plugin_by_name);
	if (!dpd) {
		return false;
	}

	// TODO pass in plugin data instead of looking it up again inside fini function
	if (dpd->plugin.fini && !dpd->plugin.fini (dbg)) {
		return false;
	}

	RVecDebugPluginData_pop_back (dbg->plugins, debug_plugin_fini, NULL);
	return true;
}

R_API bool r_debug_plugin_set_reg_profile(RDebug *dbg, const char *profile) {
	char *str = r_file_slurp (profile, NULL);
	if (!str) {
		R_LOG_ERROR ("r_debug_plugin_set_reg_profile: Cannot find '%s'", profile);
		return false;
	}
	if (dbg && dbg->h && dbg->h->set_reg_profile) {
		return dbg->h->set_reg_profile (str);
	}
	free (str);
	return false;
}
