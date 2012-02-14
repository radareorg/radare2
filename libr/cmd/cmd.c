/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_cmd.h>
#include <r_util.h>

R_API RCmd *r_cmd_new () {
	int i;
	RCmd *cmd = R_NEW (RCmd);
	if (cmd) {
		INIT_LIST_HEAD (&cmd->lcmds);
		for (i=0;i<255;i++)
			cmd->cmds[i] = NULL;
		cmd->nullcallback =
		cmd->data = NULL;
	}
	r_cmd_plugin_init (cmd);
	r_cmd_macro_init (&cmd->macro);
	return cmd;
}

R_API RCmd *r_cmd_free(RCmd *cmd) {
	if (!cmd) return NULL;
	r_list_free(cmd->plist);
	free (cmd);
	return NULL;
}

R_API int r_cmd_set_data(struct r_cmd_t *cmd, void *data) {
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
	list_add (&(item->list), &(cmd->lcmds));
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

R_API int r_cmd_del(struct r_cmd_t *cmd, const char *command) {
	int idx = (ut8)command[0];
	free(cmd->cmds[idx]);
	cmd->cmds[idx] = NULL;
	return 0;
}

R_API int r_cmd_call(struct r_cmd_t *cmd, const char *input) {
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

R_API int r_cmd_call_long(struct r_cmd_t *cmd, const char *input) {
	char *inp;
	struct list_head *pos;
	int ret, inplen = strlen (input)+1;

	list_for_each_prev (pos, &cmd->lcmds) {
		RCmdLongItem *c = list_entry (pos, struct r_cmd_long_item_t, list);
		if (inplen>=c->cmd_len && !r_str_cmp (input, c->cmd, c->cmd_len)) {
			int lcmd = strlen (c->cmd_short);
			int linp = strlen (input+c->cmd_len);
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

#if 0
// XXX: make it work :P
static char *argv[]= { "foo", "bar", "cow", "muu" };
char **r_cmd_args(struct r_cmd_t *cmd, int *argc)
{
	*argc = 4;
	//argv = argv_test;
	return argv;
}
#endif
