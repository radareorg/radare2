#ifndef _INCLUDE_R_CMD_H_
#define _INCLUDE_R_CMD_H_

#include <r_types.h>
#include <r_util.h>
#include "list.h"

#define MACRO_LIMIT 4096
#define MACRO_LABELS 20

#define r_cmd_callback(x) int (*x)(void *data, const char *input)
#define r_cmd_nullcallback(x) int (*x)(void *data);

typedef struct r_cmd_macro_label_t {
	char name[80];
	char *ptr;
} RCmdMacroLabel;

typedef struct r_cmd_macro_item_t {
	char *name;
	char *args;
	char *code;
	int nargs;
	struct list_head list;
} RCmdMacroItem;

typedef struct r_cmd_macro_t {
	int counter;
	ut64 *brk_value;
	ut64 _brk_value;
	int brk;
	int (*cmd)(void *user, const char *cmd);
	int (*printf)(const char str, ...);
	void *user;
	RNum *num;
	int labels_n;
	RCmdMacroLabel labels[MACRO_LABELS];
	struct list_head macros;
} RCmdMacro;

typedef int (*RCmdCallback)(void *user, const char *cmd);

typedef struct r_cmd_item_t {
	char cmd[64];
	char desc[128];
	r_cmd_callback (callback);
} RCmdItem;

typedef struct r_cmd_long_item_t {
	char cmd[64]; /* long command */
	int cmd_len;
	char cmd_short[32]; /* short command */
	char desc[128];
	struct list_head list;
} RCmdLongItem;

typedef struct r_cmd_t {
	void *data;
	r_cmd_nullcallback (nullcallback);
	struct list_head lcmds;
	RCmdItem *cmds[UT8_MAX];
	RCmdMacro macro;
	RList *plist;
} RCmd;

typedef struct r_cmd_handle_t {
	char *name;
	RCmdCallback call;
} RCmdHandle;

#ifdef R_API

R_API void r_cmd_macro_init(struct r_cmd_macro_t *mac);
R_API int r_cmd_macro_add(struct r_cmd_macro_t *mac, const char *name);
R_API int r_cmd_macro_rm(struct r_cmd_macro_t *mac, const char *_name);
R_API int r_cmd_macro_list(struct r_cmd_macro_t *mac);
R_API int r_cmd_macro_call(struct r_cmd_macro_t *mac, const char *name);
R_API int r_cmd_macro_break(struct r_cmd_macro_t *mac, const char *value);

R_API RCmd *r_cmd_new();
R_API RCmd *r_cmd_free(RCmd *cmd);
R_API int r_cmd_set_data(struct r_cmd_t *cmd, void *data);
R_API int r_cmd_add(struct r_cmd_t *cmd, const char *command, const char *desc, r_cmd_callback(callback));
R_API int r_cmd_add_long(struct r_cmd_t *cmd, const char *longcmd, const char *shortcmd, const char *desc);
R_API int r_cmd_del(struct r_cmd_t *cmd, const char *command);
R_API int r_cmd_call(struct r_cmd_t *cmd, const char *command);
R_API int r_cmd_call_long(struct r_cmd_t *cmd, const char *input);
R_API char **r_cmd_args(struct r_cmd_t *cmd, int *argc);

R_API int r_cmd_handle_init(struct r_cmd_t *cmd);
R_API int r_cmd_handle_add(struct r_cmd_t *cmd, struct r_cmd_handle_t *plugin);
R_API int r_cmd_handle_check(struct r_cmd_t *cmd, const char *a0);

/* plugins */
extern struct r_cmd_handle_t r_cmd_plugin_dummy;

/* r_cmd_macro */
R_API void r_cmd_macro_init(struct r_cmd_macro_t *mac);
R_API int r_cmd_macro_add(struct r_cmd_macro_t *mac, const char *name);
R_API int r_cmd_macro_rm(struct r_cmd_macro_t *mac, const char *_name);
R_API int r_cmd_macro_list(struct r_cmd_macro_t *mac);
R_API int r_cmd_macro_call(struct r_cmd_macro_t *mac, const char *name);
R_API int r_cmd_macro_break(struct r_cmd_macro_t *mac, const char *value);

#endif
#endif
