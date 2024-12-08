/* radare - LGPL - Copyright 2019-2024 - deroad */

#include <r_lib.h>
#include <r_asm.h>

static char* get_fcn_name(RAnal *anal, ut32 fcn_id) {
	const char *s = anal->binb.get_name (anal->binb.bin, 'f', fcn_id, false);
	return s? strdup (s): NULL;
}

static char *subvar(RAsmPluginSession *aps, RAnalFunction *f, ut64 addr, int oplen, const char *data) {
	char *fcn_name = NULL;
	if (r_str_startswith (data, "call ")) {
		ut32 fcn_id = (ut32) r_num_get (NULL, data + 5);
		if (!(fcn_name = get_fcn_name (aps->rasm->analb.anal, fcn_id))) {
			return false;
		}
		char *res = r_str_newf ("call sym.%s", fcn_name);
		free (fcn_name);
		return res;
	}
	return NULL;
}

RAsmPlugin r_asm_plugin_wasm= {
	.meta = {
		.name = "wasm",
		.desc = "WASM pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.subvar = subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_wasm,
	.version = R2_VERSION
};
#endif
