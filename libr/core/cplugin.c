/* radare - LGPL - Copyright 2010-2026 - pancake */

#include "../config.h"
#include "../include/r_core.h"
#include "../xps/r2plugins.h"

#if !defined(R_CORE_STATIC_PLUGINS)
#define R_CORE_STATIC_PLUGINS 0
#endif

static RCorePlugin *cmd_static_plugins[] = {
	R_CORE_STATIC_PLUGINS
};

static void core_plugin_session_free(RCorePluginSession *cps) {
	if (!cps) {
		return;
	}
	RCorePlugin *plugin = cps->plugin;
	if (cps->command_registered) {
		r_cmd_unregister (cps->core->rcmd, plugin->command);
	}
	if (plugin->fini) {
		plugin->fini (cps);
	}
	free (cps);
}

R_IPI void r_core_plugins_fini(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
	r_libstore_free (cmd->libstore);
	cmd->libstore = NULL;
}

R_API bool r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (cmd && plugin, false);
	if (!!plugin->command != !!plugin->call_ctx) {
		return false;
	}
	RCorePluginSession *ctx = R_NEW0 (RCorePluginSession);
	ctx->core = cmd->data;
	ctx->plugin = plugin;
	if (plugin->init && !plugin->init (ctx)) {
		free (ctx);
		return false;
	}
	if (plugin->call_ctx && !r_cmd_register (cmd, plugin->command, plugin->call_ctx, ctx)) {
		if (plugin->fini) {
			plugin->fini (ctx);
		}
		free (ctx);
		return false;
	}
	ctx->command_registered = plugin->call_ctx != NULL;
	r_list_append (cmd->libstore->plugins, ctx);
	REventPlugin ep = {
		.name = plugin->meta.name,
		.type = R_LIB_TYPE_CORE,
	};
	r_event_send (ctx->core->ev, R_EVENT_PLUGIN_LOAD, &ep);
	return true;
}

R_API bool r_core_plugin_remove(RCmd *cmd, RCorePlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (cmd && plugin, false);
	const char *name = plugin->meta.name;
	RListIter *iter, *iter2;
	RCorePluginSession *cps;
	r_list_foreach_safe (cmd->libstore->plugins, iter, iter2, cps) {
		RCorePlugin *candidate = cps->plugin;
		if (strcmp (name, candidate->meta.name)) {
			continue;
		}
		if (cps->command_registered && !r_cmd_unregister (cmd, candidate->command)) {
			return false;
		}
		cps->command_registered = false;
		r_list_delete (cmd->libstore->plugins, iter);
		RCore *core = cmd->data;
		REventPlugin ep = {
			.name = name,
			.type = R_LIB_TYPE_CORE,
		};
		r_event_send (core->ev, R_EVENT_PLUGIN_UNLOAD, &ep);
		return true;
	}
	return false;
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
		if (cps->plugin->call && cps->plugin->call (cps, a0)) {
			return true;
		}
	}
	return false;
}
