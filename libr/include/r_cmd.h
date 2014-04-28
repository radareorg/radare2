#ifndef R2_CMD_H
#define R2_CMD_H

#include <r_types.h>
#include <r_util.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

//R_LIB_VERSION_HEADER (r_cmd);

#define MACRO_LIMIT 1024
#define MACRO_LABELS 20
#define R_CMD_MAXLEN 4096

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
	int codelen;
	int nargs;
} RCmdMacroItem;

typedef struct r_cmd_macro_t {
	int counter;
	ut64 *brk_value;
	ut64 _brk_value;
	int brk;
	int (*cmd)(void *user, const char *cmd);
	PrintfCallback printf;
	void *user;
	RNum *num;
	int labels_n;
	RCmdMacroLabel labels[MACRO_LABELS];
	RList *macros;
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
} RCmdLongItem;

typedef struct r_cmd_alias_t {
	int count;
	char **keys;
	char **values;
} RCmdAlias;

typedef struct r_cmd_t {
	void *data;
	r_cmd_nullcallback (nullcallback);
	RCmdItem *cmds[UT8_MAX];
	RCmdMacro macro;
	RList *lcmds;
	RList *plist;
	RCmdAlias aliases;
} RCmd;

typedef struct r_core_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	RCmdCallback call;
	RCmdCallback init;
	RCmdCallback deinit;
} RCorePlugin;

#ifdef R_API
R_API int r_core_plugin_init(RCmd *cmd);
R_API int r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin);
R_API int r_core_plugin_check(RCmd *cmd, const char *a0);
R_API int r_core_plugin_deinit(RCmd *cmd);

/* review api */
R_API RCmd *r_cmd_new();
R_API RCmd *r_cmd_free(RCmd *cmd);
R_API int r_cmd_set_data(RCmd *cmd, void *data);
R_API int r_cmd_add(RCmd *cmd, const char *command, const char *desc, r_cmd_callback(callback));
R_API int r_cmd_add_long(RCmd *cmd, const char *longcmd, const char *shortcmd, const char *desc);
R_API int r_core_del(RCmd *cmd, const char *command);
R_API int r_cmd_call(RCmd *cmd, const char *command);
R_API int r_cmd_call_long(RCmd *cmd, const char *input);
R_API char **r_cmd_args(RCmd *cmd, int *argc);

/* r_cmd_macro */
R_API void r_cmd_macro_init(RCmdMacro *mac);
R_API int r_cmd_macro_add(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_rm(RCmdMacro *mac, const char *_name);
R_API void r_cmd_macro_list(RCmdMacro *mac);
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value);

R_API int r_cmd_alias_del (RCmd *cmd, const char *k);
R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz);
R_API int r_cmd_alias_set (RCmd *cmd, const char *k, const char *v);
R_API char *r_cmd_alias_get (RCmd *cmd, const char *k);
R_API void r_cmd_alias_free (RCmd *cmd);

#ifdef __cplusplus
}
#endif

#endif
#endif
