/* radare - LGPL - Copyright 2009-2017 pancake */

#include <r_debug.h>
#include <config.h>

R_VEC_TYPE(RVecDebugPluginSession, RDebugPluginSession);

static RDebugPlugin *debug_static_plugins[] = {
	R_DEBUG_STATIC_PLUGINS
};

static inline void debug_plugin_session_fini(RDebugPluginSession *ds, void *user) {
	RDebug *dbg = user;
	if (ds->plugin.fini_plugin && !ds->plugin.fini_plugin (dbg, ds)) {
		R_LOG_DEBUG ("Failed to finalize debug plugin");
	}
	R_FREE (ds->plugin_data);
}

R_API void r_debug_init_plugins(RDebug *dbg) {
	int i;
	dbg->plugins = RVecDebugPluginSession_new (debug_plugin_session_fini, dbg);
	for (i = 0; debug_static_plugins[i]; i++) {
		r_debug_plugin_add (dbg, debug_static_plugins[i]);
	}
}

R_API void r_debug_fini_plugins(RDebug *dbg) {
	RVecDebugPluginSession_free (dbg->plugins);
}

static inline int find_plugin_by_name(const RDebugPluginSession *ds, const void *name) {
	return strcmp (ds->plugin.meta.name, name);
}

R_API bool r_debug_use(RDebug *dbg, const char *str) {
	RDebugPluginSession *ds = NULL;
	if (dbg && R_STR_ISNOTEMPTY (str)) {
		ds = RVecDebugPluginSession_find (dbg->plugins, (void*)str, find_plugin_by_name);
		if (ds) {
			dbg->current = ds;
			if (dbg->anal && dbg->anal->cur) {
				const char *arch = dbg->anal->config->arch;
				r_debug_set_arch (dbg, arch, dbg->bits);
			}
			dbg->bp->breakpoint = dbg->current->plugin.breakpoint;
			dbg->bp->user = dbg;
		}
	}
	if (dbg && dbg->current && dbg->current->plugin.reg_profile) {
		char *p = dbg->current->plugin.reg_profile (dbg);
		if (p) {
			r_reg_set_profile_string (dbg->reg, p);
			if (dbg->anal && dbg->reg != dbg->anal->reg) {
				r_reg_free (dbg->anal->reg);
				dbg->anal->reg = dbg->reg;
			}
			if (dbg->current->plugin.init_debugger) {
				dbg->current->plugin.init_debugger (dbg);
			}
			r_reg_set_profile_string (dbg->reg, p);
			free (p);
		} else {
			R_LOG_ERROR ("Cannot retrieve reg profile from debug plugin (%s)", dbg->current->plugin.meta.name);
		}
	}
	return (dbg && dbg->current);
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

	RDebugPluginSession *ds;
	R_VEC_FOREACH (dbg->plugins, ds) {
		int sp = 8 - strlen (ds->plugin.meta.name);
		spaces[sp] = 0;
		if (mode == 'q') {
			dbg->cb_printf ("%s\n", ds->plugin.meta.name);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", ds->plugin.meta.name);
			pj_ks (pj, "license", ds->plugin.meta.license);
			pj_end (pj);
		} else {
			dbg->cb_printf ("%d  %s  %s %s%s\n",
					count, (ds == dbg->current)? "dbg": "---",
					ds->plugin.meta.name, spaces, ds->plugin.meta.license);
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
	r_return_val_if_fail (dbg && plugin, false);
	if (!plugin->meta.name) {
		return false;
	}

	RDebugPluginSession *ds = RVecDebugPluginSession_emplace_back (dbg->plugins);
	if (!ds) {
		return false;
	}

	memcpy (&ds->plugin, plugin, sizeof (RDebugPlugin));
	ds->plugin_data = NULL;

	if (ds->plugin.init_plugin && !ds->plugin.init_plugin (dbg, ds)) {
		R_LOG_DEBUG ("Failed to initialize debug plugin");
		return false;
	}

	return true;
}

R_API bool r_debug_plugin_remove(RDebug *dbg, RDebugPlugin *plugin) {
	if (!dbg || !plugin) {
		return false;
	}

	RDebugPluginSession *ds = RVecDebugPluginSession_find (dbg->plugins,
		(void*)plugin->meta.name, find_plugin_by_name);
	if (!ds) {
		return false;
	}

	RVecDebugPluginSession_pop_back (dbg->plugins);
	return true;
}

R_API bool r_debug_plugin_set_reg_profile(RDebug *dbg, const char *profile) {
	char *str = r_file_slurp (profile, NULL);
	if (!str) {
		R_LOG_ERROR ("r_debug_plugin_set_reg_profile: Cannot find '%s'", profile);
		return false;
	}
	if (dbg && dbg->current && dbg->current->plugin.set_reg_profile) {
		return dbg->current->plugin.set_reg_profile (dbg, str);
	}
	free (str);
	return false;
}
