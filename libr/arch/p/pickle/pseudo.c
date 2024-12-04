/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_asm.h>

static bool parse(RAsmPluginSession *aps, const char *data, char *str) {
	// Intentationally left blank
	// because it's not yet implemented
	return false;
}

RAsmPlugin r_asm_plugin_pickle = {
	.meta = {
		.name = "pickle",
		.desc = "Pickle pseudo syntax",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pickle,
	.version = R2_VERSION
};
#endif
