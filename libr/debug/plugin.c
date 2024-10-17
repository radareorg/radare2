/* radare - LGPL - Copyright 2009-2024 pancake */

#include <r_debug.h>
#include <config.h>

static inline void debug_plugin_session_fini(RDebugPluginSession *ds) {
	if (ds->plugin && ds->plugin->fini_plugin && !ds->plugin->fini_plugin (ds->dbg, ds)) {
		R_LOG_DEBUG ("Failed to finalize debug plugin");
	}
	R_FREE (ds->plugin_data);
}

R_VEC_TYPE_WITH_FINI(RVecDebugPluginSession, RDebugPluginSession, debug_plugin_session_fini);

static RDebugPlugin *debug_static_plugins[] = {
	R_DEBUG_STATIC_PLUGINS
};

R_API void r_debug_init_plugins(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	int i;
	dbg->plugins = RVecDebugPluginSession_new ();
	for (i = 0; debug_static_plugins[i]; i++) {
		r_debug_plugin_add (dbg, debug_static_plugins[i]);
	}
}

R_API void r_debug_fini_plugins(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	RVecDebugPluginSession_free (dbg->plugins);
}

static inline int find_plugin_by_name(const RDebugPluginSession *ds, const void *name) {
	return ds->plugin && strcmp (ds->plugin->meta.name, name);
}

R_API bool r_debug_use(RDebug *dbg, const char *str) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (R_STR_ISNOTEMPTY (str)) {
		RDebugPluginSession *ds = RVecDebugPluginSession_find (dbg->plugins, (void*)str, find_plugin_by_name);
		if (!ds) {
			ds = RVecDebugPluginSession_find (dbg->plugins, (void*)"esil", find_plugin_by_name);
			if (!ds) {
				ds = RVecDebugPluginSession_find (dbg->plugins, (void*)"null", find_plugin_by_name);
			}
		}
		if (ds) {
			dbg->current = ds;
			if (dbg->anal && dbg->anal->cur) {
				const char *arch = dbg->anal->config->arch;
				r_debug_set_arch (dbg, arch, dbg->bits);
			}
			dbg->bp->breakpoint = dbg->current->plugin->breakpoint;
			dbg->bp->user = dbg;
		}
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->reg_profile) {
		char *p = plugin->reg_profile (dbg);
		if (p) {
			if (!r_reg_set_profile_string (dbg->reg, p)) {
				R_LOG_ERROR ("Cannot set the register profile once");
			} else {
				if (dbg->anal && dbg->reg != dbg->anal->reg) {
					r_reg_free (dbg->anal->reg);
					dbg->anal->reg = dbg->reg;
				}
				if (plugin && plugin->init_debugger) {
					plugin->init_debugger (dbg);
				}
				r_reg_set_profile_string (dbg->reg, p);
			}
			free (p);
		} else {
			R_LOG_ERROR ("Cannot retrieve reg profile from debug plugin (%s)", plugin->meta.name);
		}
	}
	return dbg->current;
}

R_API bool r_debug_plugin_list(RDebug *dbg, int mode) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	char spaces[16];
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
		RPluginMeta meta = ds->plugin->meta;
		int sp = 8 - strlen (meta.name);
		memset (spaces, ' ', sp);
		spaces[sp] = 0;
		if (mode == 'q') {
			dbg->cb_printf ("%s\n", meta.name);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", meta.name);
			pj_ks (pj, "license", meta.license);
			pj_ks (pj, "author", meta.author);
			pj_ks (pj, "desc", meta.desc);
			if (meta.version) {
				pj_ks (pj, "version", meta.version);
			}
			pj_end (pj);
		} else {
			dbg->cb_printf ("%s %s %s%s\n",
				(ds == dbg->current)? "o": "-",
				meta.name, spaces, meta.desc);
		}
		spaces[sp] = ' ';
	}
	if (mode == 'j') {
		pj_end (pj);
		dbg->cb_printf ("%s\n", pj_string (pj));
	}
	return true;
}

R_API bool r_debug_plugin_add(RDebug *dbg, RDebugPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (dbg && plugin, false);
	if (!plugin->meta.name) {
		return false;
	}
	RDebugPluginSession *ds = RVecDebugPluginSession_emplace_back (dbg->plugins);
	if (!ds) {
		return false;
	}
	ds->dbg = dbg;
	ds->plugin = plugin;
	// memcpy (&ds->plugin, plugin, sizeof (RDebugPlugin));
	ds->plugin_data = NULL;

	if (ds->plugin && ds->plugin->init_plugin && !ds->plugin->init_plugin (dbg, ds)) {
		R_LOG_DEBUG ("Failed to initialize debug plugin");
		return false;
	}

	return true;
}

R_API bool r_debug_plugin_remove(RDebug *dbg, RDebugPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (dbg && plugin, false);
	RDebugPluginSession *ds = RVecDebugPluginSession_find (dbg->plugins,
		(void*)plugin->meta.name, find_plugin_by_name);
	if (ds) {
		RVecDebugPluginSession_pop_back (dbg->plugins);
		return true;
	}
	return false;
}

R_API bool r_debug_plugin_set_reg_profile(RDebug *dbg, const char *profile) {
	R_RETURN_VAL_IF_FAIL (dbg && profile, false);
	char *str = r_file_slurp (profile, NULL);
	if (!str) {
		R_LOG_ERROR ("r_debug_plugin_set_reg_profile: Cannot find '%s'", profile);
		return false;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (plugin && plugin->set_reg_profile) {
		return plugin->set_reg_profile (dbg, str);
	}
	free (str);
	return false;
}
