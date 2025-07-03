#ifndef R2_CMD_H
#define R2_CMD_H

#include <r_util.h>
#include <r_bind.h>
#include <sdb/ht_pp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_core_t RCore;

#define MACRO_LIMIT 1024
#define MACRO_LABELS 20
#define R_CMD_MAXLEN 4096

typedef enum r_cmd_status_t {
	R_CMD_STATUS_OK = 0, // command handler exited in the right way
	R_CMD_STATUS_WRONG_ARGS, // command handler could not handle the arguments passed to it
	R_CMD_STATUS_ERROR, // command handler had issues while running (e.g. allocation error, etc.)
	R_CMD_STATUS_INVALID, // command could not be executed (e.g. shell level error, not existing command, bad expression, etc.)
	R_CMD_STATUS_EXIT, // command handler asks to exit the prompt loop
} RCmdStatus;

typedef int (*RCmdCb) (void *user, const char *input);
typedef RCmdStatus (*RCmdArgvCb) (RCore *core, int argc, const char **argv);
typedef int (*RCmdNullCb) (void *user);

typedef struct r_cmd_parsed_args_t {
	int argc;
	char **argv;
	bool has_space_after_cmd;
} RCmdParsedArgs;

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
	int macro_level;
	RCoreCmd cmd;
	void *user;
	RNum *num;
	int labels_n;
	RCmdMacroLabel labels[MACRO_LABELS];
	RList *macros;
} RCmdMacro;

typedef struct r_cmd_item_t {
	char cmd[64];
	RCmdCb callback;
} RCmdItem;

typedef HtPP *RCmdAlias;

typedef struct r_cmd_alias_val_t {
	ut8 *data; // The actual value buffer
	int sz; // Buffer size
	bool is_str; // Is the buffer string-safe? (i.e. strlen(v) == sz-1. dont strlen if this isnt set)
	bool is_data; // Is the buffer data or a command? (if false, is_str must be true - commands can't be raw)
} RCmdAliasVal;


typedef struct r_cmd_t {
	void *data; // maybe its user?
	RCmdNullCb nullcallback;
	RCmdItem *cmds[UT8_MAX];
	RCmdMacro macro;
	RList *lcmds;
	RList *plist;
	RCmdAlias aliases;
	void *language; // used to store TSLanguage *
	HtUP *ts_symbols_ht;
	// RCmdDesc *root_cmd_desc;
	HtPP *ht_cmds;
} RCmd;

// TODO: remove this once transitioned to RCmdDesc
typedef struct r_cmd_descriptor_t {
	const char *cmd;
	const char **help_msg;
	const char **help_detail;
	const char **help_detail2;
	struct r_cmd_descriptor_t *sub[127];
} RCmdDescriptor;

#ifdef R_API
R_API RCmd *r_cmd_new(void);
R_API RCmd *r_cmd_free(RCmd *cmd);
R_API int r_cmd_call(RCmd *cmd, const char *command);
R_API void r_cmd_set_data(RCmd *cmd, void *data);
R_API bool r_cmd_add(RCmd *cmd, const char *command, RCmdCb callback);

/* r_cmd_macro */
R_API RCmdMacroItem *r_cmd_macro_item_new(void);
R_API void r_cmd_macro_item_free(RCmdMacroItem *item);
R_API void r_cmd_macro_init(RCmdMacro *mac);
R_API bool r_cmd_macro_add(RCmdMacro *mac, const char *name);
R_API bool r_cmd_macro_rm(RCmdMacro *mac, const char *_name);
R_API char *r_cmd_macro_list(RCmdMacro *mac, int mode);
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value);

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k);
R_API const char **r_cmd_alias_keys(RCmd *cmd);
R_API bool r_cmd_alias_set_cmd(RCmd *cmd, const char *k, const char *v);
R_API int r_cmd_alias_set_str(RCmd *cmd, const char *k, const char *v);
R_API int r_cmd_alias_set_raw(RCmd *cmd, const char *k, const ut8 *v, int sz);
R_API RCmdAliasVal *r_cmd_alias_get(RCmd *cmd, const char *k);
R_API bool r_cmd_alias_append_str(RCmd *cmd, const char *k, const char *a);
R_API bool r_cmd_alias_append_raw(RCmd *cmd, const char *k, const ut8 *a, int sz);
R_API char *r_cmd_alias_val_strdup(RCmdAliasVal *v);
R_API char *r_cmd_alias_val_strdup_b64(RCmdAliasVal *v);
R_API void r_cmd_alias_free(RCmd *cmd);
R_API void r_cmd_macro_fini(RCmdMacro *mac);

#ifdef __cplusplus
}
#endif

#endif
#endif
