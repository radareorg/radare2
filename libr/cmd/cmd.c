/* radare - LGPL - Copyright 2009-2012 - pancake */

#include <r_cmd.h>
#include <r_util.h>

R_LIB_VERSION (r_cmd);

R_API void r_cmd_alias_init(RCmd *cmd) {
	cmd->aliases.count = 0;
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
}

R_API RCmd *r_cmd_new () {
	int i;
	RCmd *cmd = R_NEW (RCmd);
	if (cmd) {
		cmd->lcmds = r_list_new ();
		for (i=0;i<255;i++)
			cmd->cmds[i] = NULL;
		cmd->nullcallback = cmd->data = NULL;
	}
	r_cmd_plugin_init (cmd);
	r_cmd_macro_init (&cmd->macro);
	r_cmd_alias_init (cmd);
	return cmd;
}

R_API RCmd *r_cmd_free(RCmd *cmd) {
	int i;
	if (!cmd) return NULL;
	r_cmd_alias_free (cmd);
	r_list_free (cmd->plist);
	r_list_free (cmd->lcmds);
	for (i=0;i<255;i++)
		if (cmd->cmds[i])
			R_FREE (cmd->cmds[i]);
	free (cmd);
	return NULL;
}

R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz) {
	if (sz) *sz = cmd->aliases.count;
	return cmd->aliases.keys;
}

R_API void r_cmd_alias_free (RCmd *cmd) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		free (cmd->aliases.keys[i]);
		free (cmd->aliases.values[i]);
	}
	cmd->aliases.count = 0;
	free (cmd->aliases.keys);
	free (cmd->aliases.values);
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
}

R_API int r_cmd_alias_del (RCmd *cmd, const char *k) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i])) {
			free (cmd->aliases.values[i]);
			cmd->aliases.values[i] = NULL;
			cmd->aliases.count--;
			if (cmd->aliases.count>0) {
				if (i>0) {
					free (cmd->aliases.keys[i]);
					cmd->aliases.keys[i] = cmd->aliases.keys[0];
					free (cmd->aliases.values[i]);
					cmd->aliases.values[i] = cmd->aliases.values[0];
				}
				memcpy (cmd->aliases.values,
					cmd->aliases.values+1,
					cmd->aliases.count*sizeof (void*));
				memcpy (cmd->aliases.keys,
					cmd->aliases.keys+1,
					cmd->aliases.count*sizeof (void*));
			}
			return 1;
		}
	}
	return 0;
}

R_API int r_cmd_alias_set (RCmd *cmd, const char *k, const char *v) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i])) {
			free (cmd->aliases.values[i]);
			cmd->aliases.values[i] = strdup (v);
			return 1;
		}
	}
	// new
	i = cmd->aliases.count++;
	cmd->aliases.keys = (char **)realloc (cmd->aliases.keys,
		sizeof (char**)*cmd->aliases.count);
	cmd->aliases.values = (char **)realloc (cmd->aliases.values,
		sizeof (char**)*cmd->aliases.count);
	cmd->aliases.keys[i] = strdup (k);
	cmd->aliases.values[i] = strdup (v);
	return 0;
}

R_API char *r_cmd_alias_get (RCmd *cmd, const char *k) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i]))
			return cmd->aliases.values[i];
	}
	return NULL;
}

R_API int r_cmd_set_data(RCmd *cmd, void *data) {
	cmd->data = data;
	return 1;
}

R_API int r_cmd_add_long(RCmd *cmd, const char *lcmd, const char *scmd, const char *desc) {
	RCmdLongItem *item = R_NEW (RCmdLongItem);
	if (item == NULL)
		return R_FALSE;
	strncpy (item->cmd, lcmd, sizeof (item->cmd)-1);
	strncpy (item->cmd_short, scmd, sizeof (item->cmd_short)-1);
	item->cmd_len = strlen (lcmd);
	strncpy (item->desc, desc, sizeof (item->desc)-1);
	r_list_append (cmd->lcmds, item);
	return R_TRUE;
}

R_API int r_cmd_add(RCmd *c, const char *cmd, const char *desc, r_cmd_callback(cb)) {
	struct r_cmd_item_t *item;
	int idx = (ut8)cmd[0];

	item = c->cmds[idx];
	if (item == NULL) {
		item = R_NEW (RCmdItem);
		c->cmds[idx] = item;
	}
	strncpy (item->cmd, cmd, sizeof (item->cmd)-1);
	strncpy (item->desc, desc, sizeof (item->desc)-1);
	item->callback = cb;
	return R_TRUE;
}

R_API int r_cmd_del(RCmd *cmd, const char *command) {
	int idx = (ut8)command[0];
	free(cmd->cmds[idx]);
	cmd->cmds[idx] = NULL;
	return 0;
}

R_API int r_cmd_call(RCmd *cmd, const char *input) {
	struct r_cmd_item_t *c;
	int ret = -1;
	RListIter *iter;
	RCmdPlugin *cp;

	if (!input || !*input) {
		if (cmd->nullcallback != NULL)
			ret = cmd->nullcallback (cmd->data);
	} else {
		r_list_foreach (cmd->plist, iter, cp) {
			if (cp->call (cmd->data, input))
				return R_TRUE;
		}
		c = cmd->cmds[(ut8)input[0]];
		if (c && c->callback)
			ret = c->callback (cmd->data, input+1);
		else ret = -1;
	}
	return ret;
}

R_API int r_cmd_call_long(RCmd *cmd, const char *input) {
	char *inp;
	RListIter *iter;
	RCmdLongItem *c;
	int ret, inplen = strlen (input)+1;

	r_list_foreach (cmd->lcmds, iter, c) {
		if (inplen>=c->cmd_len && !r_str_cmp (input, c->cmd, c->cmd_len)) {
			int lcmd = strlen (c->cmd_short);
			int linp = strlen (input+c->cmd_len);
			/// SLOW malloc on most situations. use stack
			inp = malloc (lcmd+linp+2); // TODO: use static buffer with R_CMD_MAXLEN
			if (inp == NULL)
				return -1;
			memcpy (inp, c->cmd_short, lcmd);
			memcpy (inp+lcmd, input+c->cmd_len, linp+1);
			ret = r_cmd_call (cmd, inp);
			free (inp);
			return ret;
		}
	}
	return -1;
}
