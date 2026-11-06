/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_CORE_CMD_PDC_INC_C
#define R_CORE_CMD_PDC_INC_C

static inline bool pdc_names_pseudo(const char *decompiler) {
	return !*decompiler || !strcmp (decompiler, "pdc") || !strcmp (decompiler, "pd:c");
}

static RCmdResult pdc_router_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *rest = ctx->subcmd.a;
	const char *configured = r_str_trim_head_ro (r_config_get (core->config, "cmd.pdc"));
	if (pdc_names_pseudo (configured)) {
		return (RCmdResult) { .status = r_core_cmdf (core, "pd:c%s", rest) != 0 };
	}
	char *decompiler = strdup (configured);
	RConfigHold *hc = r_config_hold_new (core->config);
	r_config_hold (hc, "asm.addr.relto", "asm.addr.base", "cmd.pdc", NULL);
	r_config_set (core->config, "asm.addr.relto", "");
	r_config_set_i (core->config, "asm.addr.base", 16);
	// a pdc reached from the configured command must land on pseudo, not back here
	r_config_set (core->config, "cmd.pdc", "");
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
	free (decompiler);
	return (RCmdResult) { .status = failed };
}

static bool r_core_cmd_pdc_init(RCmd *cmd) {
	return r_cmd_register (cmd, "pdc", pdc_router_callback, NULL);
}

#endif
