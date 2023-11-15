/* radare2 - LGPL - Copyright 2023 - pancake */

#define R_LOG_ORIGIN "esil.null"

#include <r_lib.h>
#include <r_anal.h>

static void *r_esil_null_init(REsil *esil) {
	return NULL;
}

static void r_esil_null_fini(REsil *esil, void *user) {
	// do nothing
}

REsilPlugin r_esil_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "null esil plugin",
		.license = "MIT",
	},
	.init = r_esil_null_init,
	.fini = r_esil_null_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ESIL,
	.data = &r_esil_plugin_null,
	.version = R2_VERSION
};
#endif
