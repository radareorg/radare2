/* radare - LGPL - Copyright 2012 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;

	memset (op, '\0', sizeof (RAnalOp));
	if ((b[3]&0xf0) == 0x20) {
		int x = b[0]&1? 8:4;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr+x+ (8*b[1]);
		op->fail = addr+4;
	}
	return op->length = 4;
}

struct r_anal_plugin_t r_anal_plugin_arc = {
	.name = "arc",
	.arch = R_SYS_ARCH_ARC,
	.bits = 32,
	.desc = "ARC code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.op = &arc_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arc
};
#endif
