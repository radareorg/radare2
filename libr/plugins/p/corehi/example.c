/* radare - Copyright 2026 - pancake */

#define R_LOG_ORIGIN "core.hello"

#include <r_core.h>

static bool hello_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (r_str_startswith (input, "hi")) {
		r_cons_println (core->cons, "HIHIHI");
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_corehi = {
	.meta = {
		.name = "corehi",
		.desc = "sample third party core plugin",
		.author = "pancake",
		.license = "MIT",
	},
	.call = hello_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_corehi,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
