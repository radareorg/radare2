/* radare - LGPL - Copyright 2012 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int arc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;
	memset (op, '\0', sizeof (RAnalOp));
	op->length = 4;

	if (anal->bits == 32) {
		/* ARCtangent A4 */
		op->fail = addr + 4;
		ut8 basecode = (b[3] & 0xf8) >> 3;
		switch (basecode) {
		case 0x04: /* Branch */
		case 0x05: /* Branch with Link */
		case 0x06: /* Loop */
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + 4 + (((b[1] << 1) | (b[2] << 8) |
				((b[3] & 7) << 16) | ((b[0] & 0x80) >> 7)) << 2);
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
	} else {
		/* ARCompact ISA */
		op->fail = addr + 4;
		ut8 basecode = (b[3] & 0xf8) >> 3;
		switch (basecode) {
		case 0x0:
			{
			ut64 imm = ((((b[0] & 0xc0) >> 6) | (b[1] << 2)) << 11) |
				((((b[2] & 0xfe) >> 1) | ((b[3] & 0x7) << 8)) << 1);
			if (imm != 0) {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = imm;
			}
			}
			break;
		case 0x01:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = 0;
			break;
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x08:
		case 0x09:
		case 0x0a:
		case 0x0b:
			break;
		default:
			/* This is 16 bit instruction */
			op->length = 2;
			op->fail = addr + 2;
			basecode = (b[1] & 0xf8) >> 3;
			switch (basecode) {
			case 0x0c:
			case 0x0d:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case 0x0e:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case 0x1b:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case 0x1c:
				if (b[0] & 0x80)
					op->type = R_ANAL_OP_TYPE_CMP;
				else
					op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case 0x1d:
			case 0x1e:
			case 0x1f:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = 0;
				break;
			default:
				break;
			}
			break;
		}
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
