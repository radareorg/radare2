/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_cmd.h>
#include <r_util.h>

int r_cmd_set_data(struct r_cmd_t *cmd, void *data)
{
	cmd->data = data;
	return 1;
}

int r_cmd_add_long(struct r_cmd_t *cmd, const char *longcmd, const char *shortcmd, const char *desc)
{
	struct r_cmd_long_item_t *item;
	item = MALLOC_STRUCT(struct r_cmd_long_item_t);
	if (item == NULL)
		return -1;
	strncpy(item->cmd, longcmd, sizeof(item->cmd));
	strncpy(item->cmd_short, shortcmd, sizeof(item->cmd_short));
	item->cmd_len = strlen(longcmd);
	strncpy(item->desc, desc, sizeof(item->desc));
	list_add(&(item->list), &(cmd->lcmds));
	return 1;
}

int r_cmd_add(struct r_cmd_t *cmd, const char *command, const char *description, r_cmd_callback(callback))
{
	struct r_cmd_item_t *item;
	int idx = (u8)command[0];

	item = cmd->cmds[idx];
	if (item == NULL) {
		item = MALLOC_STRUCT(struct r_cmd_item_t);
		cmd->cmds[idx] = item;
	}
	strncpy(item->cmd, command, 63);
	strncpy(item->desc, description, 127);
	item->callback = callback;
	return 1;
}

int r_cmd_del(struct r_cmd_t *cmd, const char *command)
{
	int idx = (u8)command[0];
	free(cmd->cmds[idx]);
	cmd->cmds[idx] = NULL;
	return 0;
}

int r_cmd_call(struct r_cmd_t *cmd, const char *input)
{
	struct r_cmd_item_t *c;
	int ret = -1;
	if (input == NULL || input[0] == '\0') {
		if (cmd->nullcallback != NULL)
			cmd->nullcallback(cmd->data);
	} else  {
		c = cmd->cmds[(u8)input[0]];
		if (c != NULL && c->callback!=NULL)
			ret = c->callback(cmd->data, input+1);
	}
	return ret;
}

int r_cmd_call_long(struct r_cmd_t *cmd, const char *input)
{
	char *inp;
	struct list_head *pos;
	int inplen = strlen(input)+1;

	list_for_each_prev(pos, &cmd->lcmds) {
		struct r_cmd_long_item_t *c = list_entry(pos, struct r_cmd_long_item_t, list);
		if ( inplen >= c->cmd_len && !r_str_cmp(input, c->cmd, c->cmd_len)) {
			inp = alloca(inplen);
			strcpy(inp, c->cmd_short);
			strcat(inp, input+c->cmd_len);
			return r_cmd_call(cmd, inp);
		}
	}
	return -1;
}

int r_cmd_init(struct r_cmd_t *cmd)
{
	int i;
	INIT_LIST_HEAD(&cmd->lcmds);
	for(i=0;i<255;i++)
		cmd->cmds[i] = NULL;
	cmd->data = NULL;
	return 0;
}

// XXX: make it work :P
static char *argv[]= { "foo", "bar", "cow", "muu" };
char **r_cmd_args(struct r_cmd_t *cmd, int *argc)
{
	*argc = 4;
	//argv = argv_test;
	return argv;
}
