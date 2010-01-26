#ifndef _INCLUDE_R_CMD_H_
#define _INCLUDE_R_CMD_H_

#include <r_types.h>
#include "list.h"

#define r_cmd_callback(x) int (*x)(void *data, const char *input)
#define r_cmd_nullcallback(x) int (*x)(void *data);

typedef struct r_cmd_item_t {
	char cmd[64];
	char desc[128];
	r_cmd_callback(callback);
} RCommandItem;

typedef struct r_cmd_long_item_t {
	char cmd[64]; /* long command */
	int cmd_len;
	char cmd_short[32]; /* short command */
	char desc[128];
	struct list_head list;
} RCommandLongItem;

typedef struct r_cmd_t {
	void *data;
	r_cmd_nullcallback(nullcallback);
	struct list_head lcmds;
	struct r_cmd_item_t *cmds[255];
} RCommand;

#ifdef R_API
R_API RCommand *r_cmd_new();
R_API RCommand * r_cmd_init(struct r_cmd_t *cmd);
R_API int r_cmd_set_data(struct r_cmd_t *cmd, void *data);
R_API int r_cmd_add(struct r_cmd_t *cmd, const char *command, const char *desc, r_cmd_callback(callback));
R_API int r_cmd_add_long(struct r_cmd_t *cmd, const char *longcmd, const char *shortcmd, const char *desc);
R_API int r_cmd_del(struct r_cmd_t *cmd, const char *command);
R_API int r_cmd_call(struct r_cmd_t *cmd, const char *command);
R_API int r_cmd_call_long(struct r_cmd_t *cmd, const char *input);
R_API char **r_cmd_args(struct r_cmd_t *cmd, int *argc);
#endif
#endif
