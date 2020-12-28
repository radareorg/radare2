/* radare - LGPL - Copyright 2010-2020 - pancake */

/* covardly copied from r_cmd */

#include <config.h>
#include <r_core.h>
#include <r_cmd.h>
#include <r_list.h>
#include <stdio.h>

static RCorePlugin *cmd_static_plugins[] = {
	R_CORE_STATIC_PLUGINS
};

R_API bool r_core_plugin_fini(RCmd *cmd) {
	RListIter *iter;
	RCorePlugin *plugin;
	if (!cmd->plist) {
		return false;
	}
	r_list_foreach (cmd->plist, iter, plugin) {
		if (plugin && plugin->fini) {
			plugin->fini (cmd, NULL);
		}
	}
	/* empty the list */
	r_list_free (cmd->plist);
	cmd->plist = NULL;
	return true;
}

R_API bool r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin) {
	r_return_val_if_fail (cmd && plugin, false);
	if (plugin->init && !plugin->init (cmd, NULL)) {
		return false;
	}
	r_list_append (cmd->plist, plugin);
	return true;
}

R_API bool r_core_plugin_init(RCmd *cmd) {
	size_t i;
	cmd->plist = r_list_newf (NULL); // memleak or dblfree
	for (i = 0; cmd_static_plugins[i]; i++) {
		if (!r_core_plugin_add (cmd, cmd_static_plugins[i])) {
			eprintf ("Error loading cmd plugin\n");
			return false;
		}
	}
	return true;
}

R_API bool r_core_plugin_check(RCmd *cmd, const char *a0) {
	RListIter *iter;
	RCorePlugin *cp;
	r_list_foreach (cmd->plist, iter, cp) {
		if (cp->call (NULL, a0)) {
			return true;
		}
	}
	return false;
}
