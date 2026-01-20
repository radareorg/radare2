/* radare - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>

static char *drcovcmd(RAnal *anal, const char *cmd) {
	if (!r_str_startswith (cmd, "drcov")) {
		return NULL;
	}
	if (cmd[5] == '?') {
		return strdup ("| a:drcov [file]  apply DRCOV coverage");
	}
	if (cmd[5] == '\0') {
		return strdup ("");
	}
	if (cmd[5] == ' ') {
		const char *path = r_str_trim_head_ro (cmd + 6);
		if (R_STR_ISEMPTY (path)) {
			return strdup ("drcov: missing file");
		}
		int loaded = r_anal_drcov_apply (anal, path);
		if (loaded < 0) {
			return strdup ("drcov: failed");
		}
		return r_str_newf ("drcov: %d entries", loaded);
	}
	return NULL;
}

RAnalPlugin r_anal_plugin_drcov = {
	.meta = {
		.name = "drcov",
		.desc = "DRCOV coverage import",
		.license = "LGPL3",
	},
	.cmd = drcovcmd
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_drcov,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
