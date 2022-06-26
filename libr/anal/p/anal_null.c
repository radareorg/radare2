/* radare - LGPL - Copyright 2014-2022 - jn, maijin */

#include <r_anal.h>

static int null_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	return op->size = 1;
}

static bool null_set_reg_profile(RAnal* anal) {
	return r_reg_set_profile_string(anal->reg, "");
}

RAnalPlugin r_anal_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null analysis plugin",
	.arch = "none",
	.license = "LGPL3",
	.bits = 8|16|32|64,
	.op = &null_anal,
	.set_reg_profile = &null_set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_null,
	.version = R2_VERSION
};
#endif
