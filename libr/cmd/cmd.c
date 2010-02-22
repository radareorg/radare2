/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_cmd.h>
#include <r_util.h>

R_API RCommand *r_cmd_init(struct r_cmd_t *cmd) {
	int i;
	if (cmd) {
		INIT_LIST_HEAD (&cmd->lcmds);
		for (i=0;i<255;i++)
			cmd->cmds[i] = NULL;
		cmd->data = NULL;
	}
	return cmd;
}

R_API RCommand *r_cmd_new () {
	return r_cmd_init (MALLOC_STRUCT (RCommand));
}

R_API int r_cmd_set_data(struct r_cmd_t *cmd, void *data) {
	cmd->data = data;
	return 1;
}

R_API int r_cmd_add_long(RCommand *cmd, const char *lcmd, const char *scmd, const char *desc) {
	RCommandLongItem *item = R_NEW (RCommandLongItem);
	if (item == NULL)
		return R_FALSE;
	strncpy (item->cmd, lcmd, sizeof (item->cmd));
	strncpy (item->cmd_short, scmd, sizeof (item->cmd_short));
	item->cmd_len = strlen (lcmd);
	strncpy (item->desc, desc, sizeof (item->desc));
	list_add (&(item->list), &(cmd->lcmds));
	return R_TRUE;
}

R_API int r_cmd_add(RCommand *c, const char *cmd, const char *desc, r_cmd_callback(cb)) {
	struct r_cmd_item_t *item;
	int idx = (ut8)cmd[0];

	item = c->cmds[idx];
	if (item == NULL) {
		item = MALLOC_STRUCT (RCommandItem);
		c->cmds[idx] = item;
	}
	strncpy (item->cmd, cmd, 63);
	strncpy (item->desc, desc, 127);
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
	if (input == NULL || input[0] == '\0') {
		if (cmd->nullcallback != NULL)
			cmd->nullcallback(cmd->data);
	} else {
		c = cmd->cmds[(ut8)input[0]];
		if (c != NULL && c->callback!=NULL)
			ret = c->callback(cmd->data, input+1);
		else ret = -1;
	}
	return ret;
}

R_API int r_cmd_call_long(struct r_cmd_t *cmd, const char *input) {
	char *inp;
	struct list_head *pos;
	int inplen = strlen(input)+1;

	list_for_each_prev (pos, &cmd->lcmds) {
		RCommandLongItem *c = list_entry (pos, struct r_cmd_long_item_t, list);
		if (inplen>=c->cmd_len && !r_str_cmp (input, c->cmd, c->cmd_len)) {
			inp = alloca(inplen);
			strcpy (inp, c->cmd_short);
			strcat (inp, input+c->cmd_len);
			return r_cmd_call (cmd, inp);
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
