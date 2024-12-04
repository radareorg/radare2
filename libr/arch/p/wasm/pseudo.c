/* radare - LGPL - Copyright 2019-2024 - deroad */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_asm.h>

static char* get_fcn_name(RAnal *anal, ut32 fcn_id) {
	const char *s = anal->binb.get_name (anal->binb.bin, 'f', fcn_id, false);
	return s? strdup (s): NULL;
}

static bool subvar(RAsm *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	char *fcn_name = NULL;
	str[0] = 0;
	if (!strncmp (data, "call ", 5)) {
		ut32 fcn_id = (ut32) r_num_get (NULL, data + 5);
		if (!(fcn_name = get_fcn_name (p->analb.anal, fcn_id))) {
			return false;
		}
		snprintf (str, len, "call sym.%s", fcn_name);
		free (fcn_name);
		return true;
	}
	return false;
}

RAsmPlugin r_asm_plugin_wasm= {
	.meta = {
		.name = "wasm",
		.desc = "WASM pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.subvar = &subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_wasm,
	.version = R2_VERSION
};
#endif
