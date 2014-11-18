/* radare - LGPL - Copyright 2010-2014 - pancake */

/* covardly copied from r_cmd */

#include "../config.h"
#include <r_core.h>
#include <r_cmd.h>
#include <r_list.h>
#include <stdio.h>

static RCorePlugin *cmd_static_plugins[] = { R_CORE_STATIC_PLUGINS };

R_API int r_core_plugin_deinit(RCmd *cmd) {
	RListIter *iter;
	RCorePlugin *plugin;
	if (!cmd->plist)
		return R_FALSE;
	r_list_foreach (cmd->plist, iter, plugin) {
		if (plugin && plugin->deinit) {
			plugin->deinit (cmd, NULL);
		}
	}
	/* empty the list */
	r_list_free (cmd->plist);
	cmd->plist = NULL;
	return R_TRUE;
}

R_API int r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin) {
	if (plugin->init)
		if (!plugin->init (cmd, NULL))
			return R_FALSE;
	r_list_append (cmd->plist, plugin);
	return R_TRUE;
}

R_API int r_core_plugin_init(RCmd *cmd) {
	int i;
	cmd->plist = r_list_newf (NULL); // memleak or dblfree
	for (i=0; cmd_static_plugins[i]; i++) {
		if (!r_core_plugin_add (cmd, cmd_static_plugins[i])) {
			eprintf ("Error loading cmd plugin\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

R_API int r_core_plugin_check(RCmd *cmd, const char *a0) {
	RListIter *iter;
	RCorePlugin *cp;
	r_list_foreach (cmd->plist, iter, cp) {
		if (cp->call (NULL, a0))
			return R_TRUE;
	}
	return R_FALSE;
}

#if 0
// TODO: must return an r_iter ator
R_API int r_cmd_plugin_list(struct r_cmd_t *cmd) {
	int n = 0;
	struct list_head *pos;
	cmd->printf ("IO plugins:\n");
	list_for_each_prev(pos, &cmd->plist) {
		struct r_cmd_list_t *il = list_entry(pos, struct r_cmd_list_t, list);
		cmd->printf(" - %s\n", il->plugin->name);
		n++;
	}
	return n;
}
#endif
