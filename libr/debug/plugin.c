/* radare - LGPL - Copyright 2009-2025 pancake */

#include <r_debug.h>
#include <config.h>

static void debug_plugin_session_free(RDebugPluginSession *ds) {
	if (!ds) {
		return;
	}
	if (ds->plugin && ds->plugin->fini_plugin && !ds->plugin->fini_plugin (ds->dbg, ds)) {
		R_LOG_DEBUG ("Failed to finalize debug plugin");
	}
	R_FREE (ds->plugin_data);
	free (ds);
}

static RDebugPlugin *debug_static_plugins[] = {
	R_DEBUG_STATIC_PLUGINS
};

R_IPI void r_debug_plugins_init(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	r_libstore_new (&dbg->libstore, dbg, debug_static_plugins, (RListFree)debug_plugin_session_free, NULL, (RLibPluginAddCb)r_debug_plugin_add, (RLibPluginAddCb)r_debug_plugin_remove);
}

R_IPI void r_debug_plugins_fini(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	r_libstore_free (dbg->libstore);
	dbg->libstore = NULL;
}

static int debug_plugin_session_cmp_name(const void *a, const void *b) {
	const RDebugPluginSession *ds = a;
	const char *name = b;
	return (ds && ds->plugin && ds->plugin->meta.name && name)? strcmp (ds->plugin->meta.name, name): 1;
}

R_API bool r_debug_use(RDebug *dbg, const char *str) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	const char *aname = R_UNWRAP4 (dbg, anal, config, arch);
	if (R_STR_ISNOTEMPTY (str)) {
		RDebugPluginSession *ds = r_libstore_find (dbg->libstore, str, debug_plugin_session_cmp_name);
		if (!ds) {
			ds = r_libstore_find (dbg->libstore, "esil", debug_plugin_session_cmp_name);
			if (!ds) {
				ds = r_libstore_find (dbg->libstore, "null", debug_plugin_session_cmp_name);
			}
		}
		if (ds) {
			dbg->current = ds;
			if (aname) {
				r_debug_set_arch (dbg, aname, dbg->bits);
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
			R_LOG_ERROR ("No regprofile from debug plugin (%s) for (%s)",
				plugin->meta.name, aname? aname: "?");
			// r_sys_breakpoint ();
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

	RListIter *iter;
	RDebugPluginSession *ds;
	r_list_foreach (dbg->libstore->plugins, iter, ds) {
		RPluginMeta meta = ds->plugin->meta;
		const int sp = 8 - strlen (meta.name);
		if (sp > 0) {
			memset (spaces, ' ', sp);
			spaces[sp] = 0;
		}
		if (mode == 'q') {
			dbg->cb_printf ("%s\n", meta.name);
		} else if (mode == 'j') {
			pj_o (pj);
			r_lib_meta_pj (pj, &meta);
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
	RDebugPluginSession *ds = R_NEW0 (RDebugPluginSession);
	if (!ds) {
		return false;
	}
	ds->dbg = dbg;
	ds->plugin = plugin;
	ds->plugin_data = NULL;

	if (ds->plugin && ds->plugin->init_plugin && !ds->plugin->init_plugin (dbg, ds)) {
		R_LOG_DEBUG ("Failed to initialize debug plugin");
		debug_plugin_session_free (ds);
		return false;
	}
	return r_list_append (dbg->libstore->plugins, ds) != NULL;
}

R_API bool r_debug_plugin_remove(RDebug *dbg, RDebugPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (dbg && plugin, false);
	RListIter *iter;
	RDebugPluginSession *ds;
	r_list_foreach (dbg->libstore->plugins, iter, ds) {
		if (ds->plugin && !strcmp (ds->plugin->meta.name, plugin->meta.name)) {
			if (dbg->current == ds) {
				dbg->current = NULL;
			}
			r_list_delete (dbg->libstore->plugins, iter);
			return true;
		}
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
