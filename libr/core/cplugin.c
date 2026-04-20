/* radare - LGPL - Copyright 2010-2026 - pancake */

#include "../config.h"
#include "../include/r_core.h"
#include "../xps/r2plugins.h"

static RCorePlugin *cmd_static_plugins[] = {
	R_CORE_STATIC_PLUGINS
};

static void core_plugin_session_free(RCorePluginSession *cps) {
	if (cps) {
		if (cps->plugin && cps->plugin->fini) {
			cps->plugin->fini (cps);
		}
		free (cps);
	}
}

R_IPI void r_core_plugins_fini(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
	r_libstore_free (cmd->libstore);
	cmd->libstore = NULL;
}

R_API bool r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (cmd && plugin, false);
	RCorePluginSession *ctx = R_NEW0 (RCorePluginSession);
	ctx->core = cmd->data;
	ctx->plugin = plugin;
	if (plugin->init && !plugin->init (ctx)) {
		free (ctx);
		return false;
	}
	r_list_append (cmd->libstore->plugins, ctx);
	REventPlugin ep = {
		.name = plugin->meta.name,
		.type = R_LIB_TYPE_CORE,
	};
	r_event_send (ctx->core->ev, R_EVENT_PLUGIN_LOAD, &ep);
	return true;
}

R_API bool r_core_plugin_remove(RCmd *cmd, RCorePlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (cmd, false);
	const char *name = plugin->meta.name;
	RListIter *iter, *iter2;
	RCorePluginSession *cps;
	bool res = false;
	r_list_foreach_safe (cmd->libstore->plugins, iter, iter2, cps) {
		if (cps && !strcmp (name, cps->plugin->meta.name)) {
			r_list_delete (cmd->libstore->plugins, iter);
			res = true;
			break;
		}
	}
	if (res) {
		RCore *core = cmd->data;
		REventPlugin ep = {
			.name = plugin->meta.name,
			.type = R_LIB_TYPE_CORE,
		};
		r_event_send (core->ev, R_EVENT_PLUGIN_UNLOAD, &ep);
	}
	return res;
}

R_IPI void r_core_plugins_init(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
	r_libstore_new (&cmd->libstore, cmd, NULL, (RListFree)core_plugin_session_free, NULL, (RLibPluginAddCb)r_core_plugin_add, (RLibPluginAddCb)r_core_plugin_remove);
	if (cmd->libstore) {
		cmd->libstore->static_plugins = cmd_static_plugins;
	}
}

R_IPI void r_core_plugins_load(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd && cmd->libstore);
	r_libstore_load (cmd->libstore);
}

R_API bool r_core_plugin_check(RCmd *cmd, const char *a0) {
	R_RETURN_VAL_IF_FAIL (cmd && a0, false);
	RListIter *iter;
	RCorePluginSession *cps;
	r_list_foreach (cmd->libstore->plugins, iter, cps) {
		return cps->plugin->call (NULL, a0);
	}
	return false;
}
