/* radare - LGPL - Copyright 2012-2013 - pancake
	2014 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include <v850_disas.h>

static int v850_op(RAnal *anal, RAnalOp *op, ut64 addr,
		const ut8 *buf, int len)
{
	int ret;
	ut16 destaddr;
	st16 destaddrs;
	ut16 word1;
	struct v850_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));
	memset (op, 0, sizeof (RAnalOp));

	ret = op->size = v850_decode_command (buf, &cmd);

	if (ret <= 0) {
		return ret;
	}

	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	r_mem_copyendian ((ut8*)&word1, buf, 2, LIL_ENDIAN);

	switch ((word1 >> 5) & 0x3F) {
	case V850_MOV_IMM5:
	case V850_MOV:
	case V850_SLDB:
	case V850_SSTB:
	case V850_SLDH:
	case V850_SSTH:
	case V850_SLDW:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case V850_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case V850_DIVH:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case V850_JMP:
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case V850_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case V850_MULH:
	case V850_MULH_IMM5:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case V850_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case V850_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case V850_CMP:
	case V850_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case V850_SUBR:
	case V850_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case V850_ADD:
	case V850_ADD_IMM5:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case V850_SHR_IMM5:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case V850_SAR_IMM5:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case V850_SHL_IMM5:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case V850_BCOND:
	case V850_BCOND2:
	case V850_BCOND3:
	case V850_BCOND4:
		destaddr = ((((word1 >> 4) & 0x7) | 
			((word1 >> 11) << 3)) << 1);
		if (destaddr & 0x100) {
			destaddrs = destaddr | 0xFE00;
		} else {
			destaddrs = destaddr;
		}

		op->jump = addr + destaddrs;
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	}

	return ret;
}

struct r_anal_plugin_t r_anal_plugin_v850 = {
	.name = "v850",
	.desc = "V850 code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_V850,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = v850_op,
	.set_reg_profile = NULL,
	.fingerprint_bb	= NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_v850,
};
#endif
