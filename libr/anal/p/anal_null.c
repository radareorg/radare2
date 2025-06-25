/* radare - LGPL - Copyright 2023 - pancake */

#include <r_anal.h>

static bool nullcmd(RAnal *anal, const char *cmd) {
	if (r_str_startswith (cmd, "null")) {
		R_LOG_INFO ("nothing to see");
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
	.version = R2_VERSION
};
#endif
