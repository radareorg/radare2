/* radare - MIT - Copyright 2024-2026 - pancake */

// R2R db/cmd/newprj

#define R_LOG_ORIGIN "prj"

#include <r_core.h>
#include "newprj/newprj.h"
#include "newprj/format.inc.c"
#include "newprj/maps.inc.c"
#include "newprj/save.inc.c"
#include "newprj/load.inc.c"

static RCoreHelpMessage help_msg_prj = {
	"Usage:", "prj [action] [file]", "Manage project files",
	"prj save", " [file]", "save current state into a project file",
	"prj info", " [file]", "show information about the project file",
	"prj load", " [file]", "merge project information into the current session",
	"prj open", " [file]", "close current session and open the project from scratch",
	"prj diff", " [file]", "print commands for differences from file to current session",
	"prj r2", " [file]", "print an r2 script for parsing purposes",
	NULL
};

static RCmdResult prj_load(RCmdContext *ctx, const char *file, int mode) {
	char *out = r_core_newprj_load (ctx->user, file, mode);
	if (!out) {
		return (RCmdResult) { .status = 1 };
	}
	r_cons_print (ctx->cons, out);
	free (out);
	return (RCmdResult) { 0 };
}

static RCmdResult prj_save(RCmdContext *ctx, const char *file) {
	RCore *core = ctx->user;
	const bool exists = r_file_exists (file);
	if (exists && r_config_get_b (core->config, "scr.interactive")
			&& !r_cons_yesno (ctx->cons, 'y', "Overwrite project file (Y/n)")) {
		R_LOG_ERROR ("File exists");
		return (RCmdResult) { .status = 1 };
	}
	if (exists) {
		r_file_rm (file);
	}
	return (RCmdResult) { .status = r_core_newprj_save (core, file)? 0: 1 };
}

static RCmdResult prj_open(RCmdContext *ctx, const char *file) {
	RCore *core = ctx->user;
	if (!r_file_exists (file)) {
		R_LOG_ERROR ("Cannot find project file: %s", file);
		return (RCmdResult) { .status = 1 };
	}
	if (r_config_get_b (core->config, "scr.interactive")
			&& !r_cons_yesno (ctx->cons, 'n', "Opening a project discards the current session (files, flags, anal, config). Continue? (y/N)")) {
		R_LOG_INFO ("Aborted");
		return (RCmdResult) { .status = 1 };
	}
	r_core_cmd0 (core, "o--");
	r_config_set (core->config, "prj.name", "");
	return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD | R_CORE_NEWPRJ_MODE_RIO);
}

static void prj_help(RCmdContext *ctx) {
	RCore *core = ctx->user;
	r_cons_cmd_help (ctx->cons, help_msg_prj, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static bool prj_action_help(RCmdContext *ctx, RStrs action) {
	const size_t len = r_strs_len (action);
	if (!len || action.b[-1] != '?') {
		return false;
	}
	char *cmd = r_str_newf ("prj %.*s", (int)(len - 1), action.a);
	RCore *core = ctx->user;
	int matches = cmd? r_cons_cmd_help_match (ctx->cons, help_msg_prj,
		core->print->flags & R_PRINT_FLAGS_COLOR, cmd, 0, true): 0;
	free (cmd);
	return matches > 0;
}

static RCmdResult prj_invalid(RCmdContext *ctx) {
	prj_help (ctx);
	return (RCmdResult) { .status = 2 };
}

static RCmdResult prj_callback(RCmdContext *ctx, RStrs input) {
	(void)input;
	const size_t argc = RVecRStrs_length (&ctx->args);
	const char suffix = r_strs_at (ctx->suffix, 0);
	RStrs *args = R_VEC_START_ITER (&ctx->args);
	const bool help = (!argc && (!suffix || isspace ((ut8)suffix)
		|| (suffix == '?' && !r_strs_at (ctx->suffix, 1))))
		|| (argc == 1 && r_strs_equals_str (args[0], "?"));
	if (help) {
		prj_help (ctx);
		return (RCmdResult) { 0 };
	}
	if (argc == 1 && prj_action_help (ctx, args[0])) {
		return (RCmdResult) { 0 };
	}
	if (argc != 2) {
		return prj_invalid (ctx);
	}
	const char *file = args[1].a;
	if (r_strs_equals_str (args[0], "save")) {
		return prj_save (ctx, file);
	}
	if (r_strs_equals_str (args[0], "load")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD);
	}
	if (r_strs_equals_str (args[0], "open")) {
		return prj_open (ctx, file);
	}
	if (r_strs_equals_str (args[0], "info")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOG);
	}
	if (r_strs_equals_str (args[0], "diff")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_DIFF);
	}
	if (r_strs_equals_str (args[0], "r2")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_SCRIPT);
	}
	return prj_invalid (ctx);
}

static bool plugin_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (!core) {
		return true;
	}
	RCmd *cmd = core->rcmd;
	if (!r_cmd_register (cmd, "prj", prj_callback, NULL)) {
		return false;
	}
	cps->data = cmd;
	return true;
}

static bool plugin_fini(RCorePluginSession *cps) {
	if (cps->data) {
		r_cmd_unregister (cps->data, "prj");
	}
	return true;
}

RCorePlugin r_core_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Experimental binary projects",
		.author = "pancake",
		.license = "MIT",
	},
	.init = plugin_init,
	.fini = plugin_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_prj,
	.version = R2_VERSION
};
#endif
