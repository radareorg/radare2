/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_CORE_CMD_PDC_INC_C
#define R_CORE_CMD_PDC_INC_C

static RCoreHelpMessage help_msg_pdc = {
	"Usage: pdc[acjlot*]", "", "experimental, unreliable and hacky pseudo-decompiler",
	"pdc", "", "pseudo decompile function in current offset",
	"pdc*", "", "emit decompiled lines as CCu comment commands",
	"pdca", "", "side by side comparing assembly and pseudo",
	"pdcc", "", "pseudo-decompile with C helpers around",
	"pdcl", "", "linear pseudo-decompilation scrolling across functions",
	"pdco", "", "show associated offset next to pseudecompiled output",
	"pdcj", "", "in json format for codemeta annotations (used by frontends like iaito)",
	"pdct", "", "dump the structuring region AST (decompiler debug)",
	NULL
};

static inline bool pdc_names_pseudo(const char *decompiler) {
	return R_STR_ISEMPTY (decompiler) || strstr (decompiler, "pdc") || r_str_startswith (r_str_trim_head_ro (decompiler), "pd:c");
}

static RCmdResult pdc_router_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *rest = ctx->subcmd.a;
	const char *decompiler = r_config_get (core->config, "cmd.pdc");
	const bool pseudo = pdc_names_pseudo (decompiler);
	if (pseudo && r_cmdctx_help (ctx)) {
		if (r_strs_len (ctx->subcmd) == 2) {
			char subhelp[5] = "pdc";
			subhelp[3] = r_cmdctx_mode (ctx, "acjlot*");
			if (subhelp[3] && r_cons_cmd_help_match (ctx->cons, help_msg_pdc, subhelp, 0, true) > 0) {
				return (RCmdResult) { 0 };
			}
		}
		r_cons_cmd_help (ctx->cons, help_msg_pdc);
		return (RCmdResult) { 0 };
	}
	if (pseudo) {
		return (RCmdResult) { .status = r_core_cmdf (core, "pd:c%s", rest) != 0 };
	}
	RConfigHold *hc = r_config_hold_new (core->config);
	r_config_hold (hc, "asm.addr.relto", "asm.addr.base", NULL);
	r_config_set (core->config, "asm.addr.relto", "");
	r_config_set_i (core->config, "asm.addr.base", 16);
	if (strstr (decompiler, "!*") || strstr (decompiler, "#!")) {
		if (!strcmp (rest, "*")) {
			rest = " -r2";
		} else if (!strcmp (rest, "=")) {
			rest = " -a";
		}
	}
	const bool failed = r_core_cmdf (core, "%s%s", decompiler, rest) != 0;
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	return (RCmdResult) { .status = failed };
}

static bool r_core_cmd_pdc_init(RCmd *cmd) {
	return r_cmd_register (cmd, "pdc", pdc_router_callback, NULL);
}

#endif
