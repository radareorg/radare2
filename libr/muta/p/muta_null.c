/* radare - LGPL - Copyright 2025 - pancake */

#include <r_muta.h>

RMutaPlugin r_muta_plugin_null = {
	.type = R_MUTA_TYPE_HASH,
	.meta = {
		.name = "null",
		.desc = "mutate nothing",
		.author = "pancake",
		.license = "MIT",
	}
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_null,
	.version = R2_VERSION
};
#endif
