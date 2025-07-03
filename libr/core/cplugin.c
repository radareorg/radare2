/* radare - LGPL - Copyright 2010-2025 - pancake */

#include <config.h>
#include <r_core.h>

static RCorePlugin *cmd_static_plugins[] = {
	R_CORE_STATIC_PLUGINS
};

R_API void r_core_plugin_fini(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
#if 0
	if (cmd->plist) {
		RListIter *iter;
		RCorePlugin *plugin;
		r_list_foreach (cmd->plist, iter, plugin) {
			if (plugin && plugin->fini) {
				plugin->fini (cmd, NULL);
			}
		}
		r_list_free (cmd->plist);
		cmd->plist = NULL;
	}
#endif
	RListIter *iter;
	RCorePluginSession *cps;
	r_list_foreach (cmd->lcmds, iter, cps) {
		RCorePlugin *plugin = cps->plugin;
		if (plugin->fini && plugin->fini (cps)) {
			break;
		}
	}
}

R_API bool r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (cmd && plugin, false);
	RCorePluginSession *ctx = R_NEW0 (RCorePluginSession);
	ctx->core = cmd->data;
	ctx->plugin = plugin;
	if (plugin->init) {
		if (!plugin->init (ctx)) {
			free (ctx);
			return false;
		}
	}
	r_list_append (cmd->lcmds, ctx);
	r_list_append (cmd->plist, plugin);
	return true;
}

R_API bool r_core_plugin_remove(RCmd *cmd, RCorePlugin *plugin) {
	if (!cmd) {
		return false;
	}
	const char *name = plugin->meta.name;
	RListIter *iter, *iter2;
	RCorePlugin *p;
	r_list_foreach_safe (cmd->plist, iter, iter2, p) {
		if (p && !strcmp (name, p->meta.name)) {
			r_list_delete (cmd->plist, iter);
			return true;
		}
	}

	return false;
}

R_API bool r_core_plugin_init(RCmd *cmd) {
	R_RETURN_VAL_IF_FAIL (cmd, false);
	size_t i;
	cmd->plist = r_list_newf (NULL); // memleak or dblfree
	for (i = 0; cmd_static_plugins[i]; i++) {
		if (!r_core_plugin_add (cmd, cmd_static_plugins[i])) {
			R_LOG_ERROR ("loading cmd plugin");
			return false;
		}
	}
	return true;
}

R_API bool r_core_plugin_check(RCmd *cmd, const char *a0) {
	R_RETURN_VAL_IF_FAIL (cmd && a0, false);
	RListIter *iter;
	RCorePlugin *cp;
	r_list_foreach (cmd->plist, iter, cp) {
		return cp->call (NULL, a0);
	}
	return false;
}
