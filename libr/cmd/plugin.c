/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

/* covardly copied from r_cmd */

#include "../config.h"
#include <r_cmd.h>
#include <r_list.h>
#include <stdio.h>

static struct r_cmd_plugin_t *cmd_static_plugins[] = 
	{ R_CMD_STATIC_PLUGINS };

R_API int r_cmd_plugin_add(struct r_cmd_t *cmd, struct r_cmd_plugin_t *plugin) {
	r_list_append (cmd->plist, plugin);
	return R_TRUE;
}

R_API int r_cmd_plugin_init(struct r_cmd_t *cmd) {
	int i;
	RCmdPlugin *static_plugin;

	cmd->plist = r_list_new ();
	for (i=0; cmd_static_plugins[i]; i++) {
		static_plugin = R_NEW (RCmdPlugin);
		memcpy (static_plugin, cmd_static_plugins[i], sizeof (RCmdPlugin));
		if (!r_cmd_plugin_add (cmd, static_plugin)) {
			eprintf ("Error loading cmd plugin\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

R_API int r_cmd_plugin_check(struct r_cmd_t *cmd, const char *a0) {
	RListIter *iter;
	RCmdPlugin *cp;

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
