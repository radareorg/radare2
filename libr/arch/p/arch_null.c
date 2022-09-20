/* radare - LGPL - Copyright 2022 - pancake */

#include <r_arch.h>

#if 0
static int null_arch(RArch *arch, RArchOp *op, ut64 addr, const ut8 *data, int len, RArchOpMask mask) {
	return op->size = 1;
}

static bool null_set_reg_profile(RArch* arch) {
	return r_reg_set_profile_string(arch->reg, "");
}
#endif

RArchPlugin r_arch_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null archysis plugin",
	.arch = "none",
	.license = "LGPL3",
//	.bits = 8|16|32|64,
//	.op = &null_arch,
//	.set_reg_profile = &null_set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_arch_plugin_null,
	.version = R2_VERSION
};
#endif
