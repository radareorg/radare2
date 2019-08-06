/* radare - LGPL - Copyright 2014 - jn, maijin */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int null_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	memset (op, '\0', sizeof(RAnalOp));
	/* This should better follow the disassembler */
	return op->size = 1;
}

static int null_set_reg_profile(RAnal* anal){
	return r_reg_set_profile_string(anal->reg, "");
}

RAnalPlugin r_anal_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null analysis plugin",
	.arch = "none",
	.license = "LGPL3",
	.bits = 8|16|32|64,	/* is this used? */
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
