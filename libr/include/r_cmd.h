#ifndef R2_CMD_H
#define R2_CMD_H

#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_core_t RCore;

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

/**
 * Define how the command looks like in the help.
 */
typedef struct r_cmd_desc_help_t {
	/**
	 * Short-sentence explaining what the command does.
	 * This is shown, for example, when the list of sub-commands is printed
	 * and each sub-command has a very short description on the right,
	 * explaining what it does.
	 */
	const char *summary;
	/**
	 * Long description of what the command does. It can be as long as you
	 * want and it should explain well how the command behaves.
	 * This is shown, for example, when `??` is appended on command or `?`
	 * is appended and the command has no children to show. In that case,
	 * the short summary is extended with this longer description.
	 *
	 * Optional.
	 */
	const char *description;
	/**
	 * String used to identify the arguments. This usually comes together
	 * with the summary.
	 * TODO: explain how to differentiate between required and optional arguments
	 */
	const char *args_str;
	/**
	 * String that overrides the name+args_str usually used to describe the
	 * command.
	 *
	 * Optional.
	 */
	const char *usage;
	/**
	 * String to use as sub-commands suggestions instead of the
	 * auto-generated one (e.g. [abcd] or [?] that you can see near command
	 * names when doing `w?`). If not provided, the options will be
	 * auto-generated.
	 *
	 * Optional.
	 */
	const char *options;
	/**
	 * List of examples used to better explain how to use the command. This
	 * is shown together with the long description.
	 *
	 * Optional.
	 */
	const RCmdDescExample *examples;
} RCmdDescHelp;

typedef enum {
	// for old handlers that parse their own input and accept a single string
	R_CMD_DESC_TYPE_OLDINPUT = 0,
	// for handlers that accept argc/argv
	R_CMD_DESC_TYPE_ARGV,
	// for cmd descriptors that are just used to group together related
	// sub-commands. Do not use this if the command can be used by itself or
	// if it's necessary to show its help, because this descriptor is not
	// stored in the hashtable and cannot be retrieved except by listing the
	// children of its parent.
	R_CMD_DESC_TYPE_INNER,
	// for cmd descriptors that are parent of other sub-commands but that
	// may also have a sub-command with the same name. For example, `wc` is
	// both the parent of `wci`, `wc*`, etc. but there is also `wc` as a
	// sub-command.
	R_CMD_DESC_TYPE_GROUP,
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
		struct {
			struct r_cmd_desc_t *exec_cd;
		} group_data;
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

#define DEFINE_CMD_ARGV_DESC_DETAIL(core, name, c_name, parent, handler, help) \
	RCmdDesc *c_name##_cd = r_cmd_desc_argv_new (core->rcmd, parent, #name, handler, help); \
	r_warn_if_fail (c_name##_cd)
#define DEFINE_CMD_ARGV_DESC_SPECIAL(core, name, c_name, parent) \
	DEFINE_CMD_ARGV_DESC_DETAIL (core, name, c_name, parent, c_name##_handler, &c_name##_help)
#define DEFINE_CMD_ARGV_DESC_INNER(core, name, c_name, parent) \
	RCmdDesc *c_name##_cd = r_cmd_desc_inner_new (core->rcmd, parent, #name, &c_name##_help); \
	r_warn_if_fail (c_name##_cd)
#define DEFINE_CMD_ARGV_GROUP_WITH_CHILD(core, name, parent)                                    \
	RCmdDesc *name##_cd = r_cmd_desc_group_new (core->rcmd, parent, #name, name##_handler, &name##_help, &name##_group_help); \
	r_warn_if_fail (name##_cd)
#define DEFINE_CMD_ARGV_DESC(core, name, parent) \
	DEFINE_CMD_ARGV_DESC_SPECIAL (core, name, name, parent)
#define DEFINE_CMD_OLDINPUT_DESC(core, name, parent) \
	RCmdDesc *name##_cd = r_cmd_desc_oldinput_new (core->rcmd, parent, #name, name##_handler_old, &name##_help); \
	r_warn_if_fail (name##_cd)

#ifdef R_API
R_API bool r_core_plugin_init(RCmd *cmd);
R_API bool r_core_plugin_add(RCmd *cmd, RCorePlugin *plugin);
R_API bool r_core_plugin_check(RCmd *cmd, const char *a0);
R_API bool r_core_plugin_fini(RCmd *cmd);

R_API RCmd *r_cmd_new(void);
R_API RCmd *r_cmd_free(RCmd *cmd);
R_API void r_cmd_set_data(RCmd *cmd, void *data);
R_API bool r_cmd_add(RCmd *cmd, const char *command, RCmdCb callback);
R_API bool r_core_del(RCmd *cmd, const char *command);
R_API int r_cmd_call(RCmd *cmd, const char *command);
R_API RCmdStatus r_cmd_call_parsed_args(RCmd *cmd, RCmdParsedArgs *args);
R_API RCmdDesc *r_cmd_get_root(RCmd *cmd);
R_API RCmdDesc *r_cmd_get_desc(RCmd *cmd, const char *cmd_identifier);
R_API char *r_cmd_get_help(RCmd *cmd, RCmdParsedArgs *args, bool use_color);

static inline RCmdStatus r_cmd_int2status(int v) {
	if (v == -2) {
		return R_CMD_STATUS_EXIT;
	} else if (v < 0) {
		return R_CMD_STATUS_ERROR;
	} else {
		return R_CMD_STATUS_OK;
	}
}

static inline int r_cmd_status2int(RCmdStatus s) {
	switch (s) {
	case R_CMD_STATUS_OK:
		return 0;
	case R_CMD_STATUS_ERROR:
	case R_CMD_STATUS_WRONG_ARGS:
	case R_CMD_STATUS_INVALID:
		return -1;
	case R_CMD_STATUS_EXIT:
	default:
		return -2;
	}
}

/* RCmdDescriptor */
R_API RCmdDesc *r_cmd_desc_argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help);
R_API RCmdDesc *r_cmd_desc_inner_new(RCmd *cmd, RCmdDesc *parent, const char *name, const RCmdDescHelp *help);
R_API RCmdDesc *r_cmd_desc_group_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help, const RCmdDescHelp *group_help);
R_API RCmdDesc *r_cmd_desc_oldinput_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdCb cb, const RCmdDescHelp *help);
R_API RCmdDesc *r_cmd_desc_parent(RCmdDesc *cd);
R_API bool r_cmd_desc_has_handler(RCmdDesc *cd);
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
R_API bool r_cmd_macro_add(RCmdMacro *mac, const char *name);
R_API bool r_cmd_macro_rm(RCmdMacro *mac, const char *_name);
R_API void r_cmd_macro_list(RCmdMacro *mac);
R_API void r_cmd_macro_meta(RCmdMacro *mac);
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name);
R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value);

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k);
R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz);
R_API int r_cmd_alias_set(RCmd *cmd, const char *k, const char *v, int remote);
R_API const char *r_cmd_alias_get(RCmd *cmd, const char *k, int remote);
R_API void r_cmd_alias_free(RCmd *cmd);
R_API void r_cmd_macro_fini(RCmdMacro *mac);

#ifdef __cplusplus
}
#endif

#endif
#endif
