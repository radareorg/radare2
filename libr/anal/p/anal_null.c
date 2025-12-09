/* radare - LGPL - Copyright 2023-2025 - pancake */

#include <r_anal.h>
#include <r_core.h>

static bool nullcmd(RAnal *anal, const char *cmd) {
	if (r_str_startswith (cmd, "null")) {
		if (cmd[4] == '?') {
			RCore *core = anal->coreb.core;
			r_cons_println (core->cons, "| a:null    do nothing");
		}
		return true;
	}
	return false;
}

RAnalPlugin r_anal_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "Fallback/Null analysis plugin",
		.license = "LGPL3",
	},
	.cmd = nullcmd
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_null,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
