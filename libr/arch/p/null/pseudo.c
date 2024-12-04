/* radare - LGPL - Copyright 2024 - pancake */

#include <r_asm.h>

RAsmPlugin r_asm_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "pseudo nothing",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	}
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_null,
	.version = R2_VERSION
};
#endif
