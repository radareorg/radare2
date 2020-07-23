#ifndef R2_CMD_H
#define R2_CMD_H

#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

//R_LIB_VERSION_HEADER (r_cmd);

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
typedef RCmdStatus (*RCmdArgvCb) (void *user, int argc, const char **argv);
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
// 	int (*cmd)(void *user, const char *cmd);
	RCoreCmd cmd;
	PrintfCallback cb_printf;
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

typedef struct r_cmd_alias_t {
	int count;
	char **keys;
	char **values;
	int *remote;
} RCmdAlias;

typedef struct r_cmd_desc_example_t {
	const char *example;
	const char *comment;
} RCmdDescExample;

typedef struct r_cmd_desc_help_t {
	const char *usage;
	const char *summary;
	const char *group_summary;
	const char *args_str;
	const char *description;
	const RCmdDescExample *examples;
} RCmdDescHelp;

typedef enum {
	// for old handlers that parse their own input and accept a single string
	R_CMD_DESC_TYPE_OLDINPUT,
	// for handlers that accept argc/argv
	R_CMD_DESC_TYPE_ARGV,
} RCmdDescType;

typedef struct r_cmd_desc_t {
	RCmdDescType type;
	char *name;
	struct r_cmd_desc_t *parent;
	int n_children;
	RPVector children;
	const RCmdDescHelp *help;

	union {
		struct {
			RCmdCb cb;
		} oldinput_data;
		struct {
			RCmdArgvCb cb;
		} argv_data;
	} d;
} RCmdDesc;

typedef struct r_cmd_t {
	void *data;
	RCmdNullCb nullcallback;
	RCmdItem *cmds[UT8_MAX];
	RCmdMacro macro;
	RList *lcmds;
	RList *plist;
	RCmdAlias aliases;
	void *language; // used to store TSLanguage *
	HtUP *ts_symbols_ht;
	RCmdDesc *root_cmd_desc;
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

// TODO: move into r_core.h
typedef struct r_core_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	const char *author;
	const char *version;
	RCmdCb call; // returns true if command was handled, false otherwise.
	RCmdCb init;
	RCmdCb fini;
} RCorePlugin;

#ifdef R_API
R_API int r_core_plugin_init(RCmd *cmd);
R_API int r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin);
R_API int r_core_plugin_check(RCmd *cmd, const char *a0);
R_API int r_core_plugin_fini(RCmd *cmd);

R_API RCmd *r_cmd_new(void);
R_API RCmd *r_cmd_free(RCmd *cmd);
R_API int r_cmd_set_data(RCmd *cmd, void *data);
R_API int r_cmd_add(RCmd *cmd, const char *command, RCmdCb callback);
R_API int r_core_del(RCmd *cmd, const char *command);
R_API int r_cmd_call(RCmd *cmd, const char *command);
R_API RCmdStatus r_cmd_call_parsed_args(RCmd *cmd, RCmdParsedArgs *args);
R_API RCmdDesc *r_cmd_get_root(RCmd *cmd);
R_API RCmdDesc *r_cmd_get_desc(RCmd *cmd, const char *cmd_identifier);
R_API char *r_cmd_get_help(RCmd *cmd, RCmdParsedArgs *args, bool use_color);

/* RCmdDescriptor */
R_API RCmdDesc *r_cmd_desc_argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help);
R_API RCmdDesc *r_cmd_desc_oldinput_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdCb cb, const RCmdDescHelp *help);
R_API RCmdDesc *r_cmd_desc_parent(RCmdDesc *cd);
R_API bool r_cmd_desc_remove(RCmd *cmd, RCmdDesc *cd);

#define r_cmd_desc_children_foreach(root, it_cd) r_pvector_foreach (&root->children, it_cd)

/* RCmdParsedArgs */
R_API RCmdParsedArgs *r_cmd_parsed_args_new(const char *cmd, int n_args, char **args);
R_API RCmdParsedArgs *r_cmd_parsed_args_newcmd(const char *cmd);
R_API RCmdParsedArgs *r_cmd_parsed_args_newargs(int n_args, char **args);
R_API void r_cmd_parsed_args_free(RCmdParsedArgs *args);
R_API bool r_cmd_parsed_args_setargs(RCmdParsedArgs *arg, int n_args, char **args);
R_API bool r_cmd_parsed_args_setcmd(RCmdParsedArgs *arg, const char *cmd);
R_API char *r_cmd_parsed_args_argstr(RCmdParsedArgs *arg);
R_API char *r_cmd_parsed_args_execstr(RCmdParsedArgs *arg);
R_API const char *r_cmd_parsed_args_cmd(RCmdParsedArgs *arg);

#define r_cmd_parsed_args_foreach_arg(args, i, arg) for ((i) = 1; (i) < (args->argc) && ((arg) = (args)->argv[i]); (i)++)

/* r_cmd_macro */
R_API RCmdMacroItem *r_cmd_macro_item_new(void);
R_API void r_cmd_macro_item_free(RCmdMacroItem *item);
R_API void r_cmd_macro_init(RCmdMacro *mac);
R_API int r_cmd_macro_add(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_rm(RCmdMacro *mac, const char *_name);
R_API void r_cmd_macro_list(RCmdMacro *mac);
R_API void r_cmd_macro_meta(RCmdMacro *mac);
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value);

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k);
R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz);
R_API int r_cmd_alias_set(RCmd *cmd, const char *k, const char *v, int remote);
R_API char *r_cmd_alias_get(RCmd *cmd, const char *k, int remote);
R_API void r_cmd_alias_free(RCmd *cmd);
R_API void r_cmd_macro_fini(RCmdMacro *mac);

#ifdef __cplusplus
}
#endif

#endif
#endif
