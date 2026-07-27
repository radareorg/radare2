#ifndef R2_CMD_H
#define R2_CMD_H

#include <r_util.h>
#include <r_bind.h>
#include <sdb/ht_pp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_core_t RCore;
typedef struct r_cons_t RCons;
typedef struct r_libstore_t RLibStore;
typedef struct r_cmd_t RCmd;

R_VEC_TYPE (RVecRStrs, RStrs);

#define MACRO_LIMIT 1024
#define MACRO_LABELS 20
#define R_CMD_MAXLEN 4096

typedef int (*RCmdCb) (void *user, const char *input);
// typedef RCmdStatus (*RCmdArgvCb) (RCore *core, int argc, const char **argv);
typedef int (*RCmdNullCb) (void *user);

typedef enum {
	R_CMD_ACTION_CONTINUE,
	R_CMD_ACTION_ABORT,
	R_CMD_ACTION_QUIT,
	R_CMD_ACTION_UNHANDLED
} RCmdAction;

typedef struct r_cmd_result_t {
	RCmdAction action;
	bool has_value;
	st64 status;
	ut64 value;
} RCmdResult;

typedef struct r_cmd_context_t {
	struct r_cmd_context_t *parent;
	RCmd *cmd;
	RCons *cons;
	void *user;
	void *handler_user;
	int remaining_depth; // nested core command budget
	char *args_storage; // private: owned buffer backing args, do not use
	RVecRStrs args; // arguments after the matched name and subcmd
	RStrs subcmd; // registered-name remainder ending at the command token; subcmd.b starts the raw NUL-terminated tail
	bool verbatim; // whole-command quoting requests the exact tail in subcmd.b
} RCmdContext;

typedef RCmdResult (*RCmdCtxCb) (RCmdContext *ctx);

/* True when the command token requests help: "agD?", "agDj?", "prjs?" */
static inline bool r_cmd_ctx_help(RCmdContext *ctx) {
	return r_strs_lastch (ctx->subcmd) == '?';
}

/* Returns a trailing output mode before any '?', such as 'j' for "agDj?". */
static inline char r_cmd_ctx_mode(RCmdContext *ctx, const char *modes) {
	RStrs s = ctx->subcmd;
	if (r_strs_lastch (s) == '?') {
		s.b--;
	}
	const char last = r_strs_lastch (s);
	return (last && strchr (modes, last))? last: 0;
}

typedef bool (*RCmdForeachCb) (RStrs name, void *user);

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


struct r_cmd_t {
	void *data; // maybe its user?
	RCons *cons; // borrowed by new command contexts
	RCons *(*get_cons)(void *data); // optional execution-console resolver
	RCmdNullCb nullcallback;
	RCmdItem *cmds[UT8_MAX];
	RCmdMacro macro;
	RLibStore *libstore;
	RCmdAlias aliases;
	void *language; // used to store TSLanguage *
	HtUP *ts_symbols_ht;
	// RCmdDesc *root_cmd_desc;
	RTrie *handlers;
	void *priv;
};

#ifdef R_API
R_API RCmd *r_cmd_new(void *data);
/* The owner must stop new API entries before free; active dispatch and unregister operations are drained. */
R_API void r_cmd_free(RCmd *cmd);
R_API int r_cmd_call(RCmd *cmd, const char *command);
R_API void r_cmd_set_data(RCmd *cmd, void *data);
R_API bool r_cmd_add(RCmd *cmd, const char *command, RCmdCb callback);
/* New handlers are keyed by their complete command prefix; name is copied and handler_user is borrowed until unregistration completes. */
R_API bool r_cmd_register(RCmd *cmd, const char *name, RCmdCtxCb callback, void *handler_user);
/* Removes the exact name after active callbacks finish; registered callbacks cannot unregister commands. */
R_API bool r_cmd_unregister(RCmd *cmd, const char *name);
/* Removes a prefix after active callbacks finish; registered callbacks cannot unregister commands. */
R_API size_t r_cmd_unregister_prefix(RCmd *cmd, const char *prefix);
/* Visits matching names in lexical order; name is transient and false stops. */
R_API bool r_cmd_foreach_prefix(const RCmd *cmd, const char *prefix, RCmdForeachCb callback, void *user);

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
/* Returns borrowed keys; callers must prevent concurrent alias mutation while using them. */
R_API const char **r_cmd_alias_keys(RCmd *cmd);
R_API bool r_cmd_alias_set_cmd(RCmd *cmd, const char *k, const char *v);
R_API int r_cmd_alias_set_str(RCmd *cmd, const char *k, const char *v);
R_API int r_cmd_alias_set_raw(RCmd *cmd, const char *k, const ut8 *v, int sz);
/* Returns a borrowed value; callers must prevent concurrent alias mutation while using it. */
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
