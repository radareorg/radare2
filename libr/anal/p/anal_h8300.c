/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include <h8300_disas.h>

static void h8300_anal_jmp(RAnalOp *op, ut64 addr, const ut8 *buf)
{
	ut16 ad;

	switch (buf[0]) {
		case H8300_JMP_1:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case H8300_JMP_2:
			op->type = R_ANAL_OP_TYPE_JMP;
			r_mem_copyendian((ut8*)&ad, buf + 2,
					sizeof(ut16), !LIL_ENDIAN);
			op->jump = ad;
			break;
		case H8300_JMP_3:
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->jump = buf[1];
			break;
	}
}

static void h8300_anal_jsr(RAnalOp *op, ut64 addr, const ut8 *buf)
{
	ut16 ad;

	switch (buf[0]) {
		case H8300_JSR_1:
			op->type = R_ANAL_OP_TYPE_UCALL;
			break;
		case H8300_JSR_2:
			op->type = R_ANAL_OP_TYPE_CALL;
			r_mem_copyendian((ut8*)&ad, buf + 2,
					sizeof(ut16), !LIL_ENDIAN);
			op->jump = ad;
			op->fail = addr + 4;
			break;
		case H8300_JSR_3:
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->jump = buf[1];
			break;
	}
}


static int h8300_op(RAnal *anal, RAnalOp *op, ut64 addr,
		const ut8 *buf, int len)
{
	int ret;
	ut8 opcode = buf[0];
	struct h8300_cmd cmd;

	if (op == NULL)
		return 2;

	memset(op, 0, sizeof (RAnalOp));

	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	ret = op->size = h8300_decode_command(buf, &cmd);

	if  (ret < 0)
		return ret;

	switch (opcode >> 4) {
	case H8300_MOV_4BIT_2:
	case H8300_MOV_4BIT_3:
	case H8300_MOV_4BIT:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case H8300_CMP_4BIT:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case H8300_XOR_4BIT:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case H8300_AND_4BIT:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case H8300_ADD_4BIT:
	case H8300_ADDX_4BIT:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case H8300_SUBX_4BIT:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	};

	if (op->type != R_ANAL_OP_TYPE_UNK)
		return ret;

	switch (opcode) {
	case H8300_MOV_R82IND16:
	case H8300_MOV_IND162R16:
	case H8300_MOV_R82ABS16:
	case H8300_MOV_ABS162R16:
	case H8300_MOV_R82RDEC16:
	case H8300_MOV_INDINC162R16:
	case H8300_MOV_R82DISPR16:
	case H8300_MOV_DISP162R16:
	case H8300_MOV_IMM162R16:
	case H8300_MOV_1:
	case H8300_MOV_2:
	case H8300_EEPMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case H8300_RTS:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case H8300_CMP_1:
	case H8300_CMP_2:
	case H8300_BTST_R2R8:
	case H8300_BTST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case H8300_SHL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case H8300_SHR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case H8300_XOR:
	case H8300_XORC:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case H8300_MULXU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case H8300_ANDC:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case H8300_ADDB_DIRECT:
	case H8300_ADDW_DIRECT:
	case H8300_ADDS:
	case H8300_ADDX:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case H8300_SUB_1:
	case H8300_SUBW:
	case H8300_SUBS:
	case H8300_SUBX:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case H8300_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case H8300_JSR_1:
	case H8300_JSR_2:
	case H8300_JSR_3:
		h8300_anal_jsr(op, addr, buf);
		break;
	case H8300_JMP_1:
	case H8300_JMP_2:
	case H8300_JMP_3:
		h8300_anal_jmp(op, addr, buf);
		break;
	case H8300_BRA:
	case H8300_BRN:
	case H8300_BHI:
	case H8300_BLS:
	case H8300_BCC:
	case H8300_BCS:
	case H8300_BNE:
	case H8300_BEQ:
	case H8300_BVC:
	case H8300_BVS:
	case H8300_BPL:
	case H8300_BMI:
	case H8300_BGE:
	case H8300_BLT:
	case H8300_BGT:
	case H8300_BLE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + 2 + (st8)(buf[1]);
		op->fail = addr + 2;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	};

	return ret;
}

struct r_anal_plugin_t r_anal_plugin_h8300 = {
	.name = "h8300",
	.desc = "H8300 code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_H8300,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &h8300_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_sturct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_h8300
};
#endif
