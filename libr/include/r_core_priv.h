/* radare - LGPL - Copyright 2024-2026 - pancake */

#include "r_core.h"

#ifndef R2_CORE_PRIV_H
#define R2_CORE_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	bool (*root)(RCore *core, RPanelsRoot *root);
	void (*save)(RCore *core, const char *name);
	bool (*load)(RCore *core, const char *name);
} RCorePanels;

typedef struct {
	void (*cb)(const RAGraph *graph, void *user);
	void *user;
} RCoreGraphCapture;

typedef struct r_core_priv_t {
#if R2__UNIX__ && !__wasi__
	bool signals_enabled;
#if HAVE_SIGACTION
	struct sigaction old_usr1, old_usr2;
#else
	void (*old_usr1)(int);
	void (*old_usr2)(int);
#endif
#endif
	// arch cache
	int old_bits;
	char *old_arch;
	// rtr
	RSocket *s;
	RThread *httpthread;
	RThread *rapthread;
	const char *listenport;
	char *errmsg_tmpfile; // fifo that replaces stderr after ===errmsg
	int errmsg_fd;
	int errmsg_stderr; // original stderr, restored by ===-errmsg
	bool regnums;
	bool tags_loaded;
	bool autocomplete_loaded;
	RDebugSession *debug_replay_session;
	HtUP *debug_replay;
	RList *cmdqueue;
	RThreadLock *cmdqueue_lock;
	// disasm cache
	ut64 goaddr;
	char *section;
	const RCorePanels *panels;
	RCoreGraphCapture *graph_capture; // borrowed while capturing graph output
} RCorePriv;

R_IPI bool isVisualDisasm(RCore *core);
R_IPI int r_core_vmark_select(RCore *core, bool delete_mark);
typedef int (*RCoreVisualDefineReadCallback)(RCore *core, const char **lines);
R_IPI void r_core_visual_define_input(RCore *core, const char *args, int distance, RCoreVisualDefineReadCallback readchar);
R_IPI R_OWNED char * R_NULLABLE r_core_get_radare2rc(void);
typedef enum {
	R_CMD_ARGS_DEFAULT = 0,
	R_CMD_ARGS_ATTACHED = 1, // Parse arguments immediately after the registered prefix.
	R_CMD_ARGS_VERBATIM = 2, // Skip decoding; subcmd.b borrows the untouched argument tail.
} RCmdArgFlags;

R_IPI bool r_cmd_register_args(RCmd *cmd, const char *name, RCmdCtxCb callback, void *user, RCmdArgFlags flags);

typedef enum {
	R_CMD_ROW_ARGS_MASK = 3, // RCmdArgFlags bits
	R_CMD_ROW_SETS_VALUE = 4, // run owns $?: successful calls leave it untouched
} RCmdRowFlags;

// One command of a statically allocated table, reached through ctx->handler_user
typedef struct r_cmd_row_t {
	const char *name; // complete command name: "ytf"
	bool (*run)(RCmdContext *ctx);
	const char *usage; // argument synopsis printed after the name on usage errors
	const char * const *help; // printed on "name?"; NULL matches name in the table help
	ut8 min_args;
	ut8 max_args; // UT8_MAX for no limit
	ut8 flags; // RCmdRowFlags
} RCmdRow;

typedef struct r_cmd_table_t {
	const char * const *help;
	const RCmdRow *rows;
	size_t count;
} RCmdTable;

// One trie entry dispatches every row starting with key; rows are matched by longest name
R_IPI bool r_cmd_register_table(RCmd *cmd, const char *key, const RCmdTable *table);
R_IPI RCmdResult r_cmd_call_result(RCmd *cmd, RCmdContext *parent, const char *input, bool raw);
R_IPI int r_cmd_call_context(RCmd *cmd, RCmdContext *parent, const char *input, bool raw);

#ifdef __cplusplus
}
#endif

#endif
