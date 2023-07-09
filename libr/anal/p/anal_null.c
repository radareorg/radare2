/* radare - LGPL - Copyright 2023 - pancake */

#include <r_anal.h>

RAnalPlugin r_anal_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "Fallback/Null analysis plugin",
		.license = "LGPL3",
	}
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_null,
	.version = R2_VERSION
};
#endif
