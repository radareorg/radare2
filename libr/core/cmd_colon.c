/* radare - LGPL - Copyright 2019 - pancake */

#include <r_core.h>

static int cmd_colon(void *_core, const char *cmd) {
	// RCore *core = (RCore*)_core;
	if (*cmd == '{') {
		// parse json here, and retrieve arguments
		return 1;
	}
	if (!*cmd) {
		return 1;
	}
	if (*cmd == '?') {
		eprintf ("Usage: :<command> <arguments\n");
		eprintf ("Usage: :{json-goes-here}\n");
		eprintf ("See: T command to save/replay/. long commands\n");
		eprintf ("See: e http.colon=true\n");
		return 1;
	}
	const char *space = strchr (cmd, ' ');
	if (space) {
		int len = space - cmd;
		char *action = r_str_ndup (cmd, len);
		r_cons_printf ("-> %s\n", action);
		free (action);
		return 1;
	}
	eprintf ("Invalid command\n");
	// Use hashtable
	return 0;
}
