/* radare - Copyright 2025 - pancake */

#define R_LOG_ORIGIN "jmptbl.arm64"

#include <r_core.h>

static bool eligible(RAnal *anal) {
	const bool is_arm = sarch && r_str_startswith (sarch, "arm");
	return is_arm && anal->config->bits == 64;
}

// PLUGIN Definition Info
RAnalPlugin r_anal_plugin_a2f = {
	.meta = {
		.name = "jmptbl.arm64",
		.desc = "Jump Table For ARM64",
		.license = "MIT",
	},
	.opflow = opflow,
	.eligible = eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_a2f,
	.version = R2_VERSION
};
#endif
