/* radare - LGPL - Copyright 2016-2017 pancake */

#include <r_io.h>
#include <r_debug.h>

RDebugPlugin r_debug_plugin_null = {
	.meta = {
		.name = "null",
		.author = "pancake",
		.desc = "null debug plugin (does nothing)",
		.license = "MIT",
	},
	.arch = "any",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_null,
	.version = R2_VERSION
};
#endif
