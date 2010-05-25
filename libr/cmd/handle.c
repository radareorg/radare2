/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

/* covardly copied from r_cmd */

#include "../config.h"
#include <r_cmd.h>
#include <r_list.h>
#include <stdio.h>

static struct r_cmd_plugin_t *cmd_static_plugins[] = 
	{ R_CMD_STATIC_PLUGINS };

R_API int r_cmd_handle_add(struct r_cmd_t *cmd, struct r_cmd_plugin_t *plugin) {
	r_list_append (cmd->plist, plugin);
	return R_TRUE;
}

R_API int r_cmd_handle_init(struct r_cmd_t *cmd) {
	int i;
	cmd->plist = r_list_new ();
	for (i=0; cmd_static_plugins[i]; i++)
		if (!r_cmd_handle_add (cmd, cmd_static_plugins[i])) {
			eprintf ("Error loading cmd plugin\n");
			return R_FALSE;
		}
	return R_TRUE;
}

R_API int r_cmd_handle_check(struct r_cmd_t *cmd, const char *a0) {
	RListIter *iter;
	RCmdPlugin *cp;
	
	iter = r_list_iterator (cmd->plist);
	while (r_list_iter_next (iter)) {
		cp = (RCmdPlugin*) r_list_iter_get (iter);
		if (cp->call (NULL, a0))
			return R_TRUE;
	}
	return R_FALSE;
}

#if 0
// TODO: must return an r_iter ator
R_API int r_cmd_handle_list(struct r_cmd_t *cmd) {
	int n = 0;
	struct list_head *pos;
	cmd->printf ("IO handlers:\n");
	list_for_each_prev(pos, &cmd->plist) {
		struct r_cmd_list_t *il = list_entry(pos, struct r_cmd_list_t, list);
		cmd->printf(" - %s\n", il->plugin->name);
		n++;
	}
	return n;
}
#endif
