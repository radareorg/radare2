/* radare - LGPL - Copyright 2024 - pancake */

#include <r_asm.h>

static char *parse(RAsmPluginSession *aps, const char *data) {
	// Intentationally left blank
	// because it's not yet implemented
	return NULL;
}

RAsmPlugin r_asm_plugin_java = {
	.meta = {
		.name = "java",
		.desc = "Java pseudocode",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_java,
	.version = R2_VERSION
};
#endif
