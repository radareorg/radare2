/* radare - LGPL - Copyright 2014 - jn */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int null_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	memset (op, '\0', sizeof(RAnalOp));
	/* This should better follow the disassembler */
	return op->size = 1;
}

struct r_anal_plugin_t r_anal_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null analysis plugin",
	.arch = R_SYS_ARCH_NONE,
	.license = "LGPL3",
	.bits = 8|16|32|64,	/* is this used? */
	.op = &null_anal,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_null
};
#endif
