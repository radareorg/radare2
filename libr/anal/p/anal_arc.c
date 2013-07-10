/* radare - LGPL - Copyright 2012 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;
	memset (op, '\0', sizeof (RAnalOp));

	if (anal->bits == 32) {
		/* ARCtangent A4 */
		ut8 basecode = b[3] & 0xf8;
		if ((basecode == 0x04) || (basecode == 0x05) || /* Branch and Branch with Link */
			(basecode == 0x06)) { /* Loop */
			//int x = b[0]&1? 8:4;
			op->type = R_ANAL_OP_TYPE_CJMP;
			//op->jump = addr+x+ (8*b[1]);
			op->jump = addr + 4 + ((b[1] << 1) + (b[2] << 8) +
				((b[3] & 7) << 15) + (b[0] & (1 << 7))) << 2;
			op->fail = addr + 4;
		} else if (basecode == 0x07) { /* Conditional Jump and Jump with Link */
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = 0;
			op->fail = addr + 4;
		} else if ((basecode == 0x08) || (basecode == 0x09)) {
			op->type = R_ANAL_OP_TYPE_ADD;
		} else if ((basecode == 0x0a) || (basecode == 0x0b)) {
			op->type = R_ANAL_OP_TYPE_SUB;
		} else if (basecode == 0x0c) {
			op->type = R_ANAL_OP_TYPE_AND;
		} else if (basecode == 0x0d) {
			op->type = R_ANAL_OP_TYPE_OR;
		} else if (basecode == 0x0f) {
			op->type = R_ANAL_OP_TYPE_XOR;
		} else if (basecode == 0x13) {
			op->type = R_ANAL_OP_TYPE_ROR;
		} else if ((basecode == 0xf) && (b[0] == 0xff) && (b[1] == 0xff)) {
			op->type = R_ANAL_OP_TYPE_NOP;
		}
	} else {
		/* ARCompact ISA */
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
