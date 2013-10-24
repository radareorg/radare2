/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int arcompact_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	/* ARCompact ISA */
	const ut8 *b = (ut8 *)data;
	int lowbyte, highbyte;

	lowbyte = anal->big_endian? 0: 1;
	highbyte = anal->big_endian? 1: 0;

	if (((b[lowbyte]&0xf8) >0x38) && ((b[lowbyte]&0xf8) != 0x48)) {
		op->length = 2;
	} else {
		op->length = 4;
	}
// XXX: compact instructions can be >4 !??
	op->fail = addr + 4;
	ut8 basecode = (b[3] & 0xf8) >> 3;
	ut8 subopcode = ((b[1]&0xf)>>2)<<1;
	//eprintf ("----> ST %x\n", subopcode);
	//eprintf ("BC = 0x%x\n", basecode);
	if (!memcmp (b, "\x4a\x26\x00\x70", 4)) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return 4;
	}
	return op->length;
}

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;
	memset (op, '\0', sizeof (RAnalOp));

	/* ARCtangent A4 */
	if (anal->bits == 16)
		return arcompact_op (anal, op, addr, data, len);
	op->length = 4;
	op->fail = addr + 4;
	ut8 basecode = (b[3] & 0xf8) >> 3;
	switch (basecode) {
	case 0x04: /* Branch */
	case 0x05: /* Branch with Link */
	case 0x06: /* Loop */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + 4 + (((b[1] << 1) | (b[2] << 9) |
			((b[3] & 7) << 17) | ((b[0] & 0x80) >> 7)) << 2);
		break;
	case 0x07: /* Conditional Jump and Jump with Link */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = 0;
		break;
	case 0x08:
	case 0x09:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x0a:
	case 0x0b:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x0c:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x0d:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x0f:
		if ((b[0] == 0xff) && (b[1] == 0xff)) {
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x13:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	default:
		break;
	}
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_arc = {
	.name = "arc",
	.arch = R_SYS_ARCH_ARC,
	.bits = 16|32,
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
