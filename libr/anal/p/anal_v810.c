/* radare - LGPL - Copyright 2015 - danielps */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include <v810_disas.h>

static int v810_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int ret;
	ut32 destaddr;
	st32 destaddrs;
	ut16 word1, word2;
	struct v810_cmd cmd;
	ut8 opcode;

	memset (&cmd, 0, sizeof(cmd));
	memset (op, 0, sizeof(RAnalOp));

	ret = op->size = v810_decode_command (buf, &cmd);
	if (ret <= 0) return ret;

	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	r_mem_copyendian ((ut8*)&word1, buf, 2, LIL_ENDIAN);

	opcode = (word1 >> 10) & 0x3F;
	if (opcode>>3 == 0x4)
		opcode &= 0x20;

	switch (opcode) {
	case V810_MOV:
	case V810_MOV_IMM5:
	case V810_MOVHI:
	case V810_MOVEA:
	case V810_LDSR:
	case V810_STSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case V810_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case V810_DIV:
	case V810_DIVU:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case V810_JMP:
		if ((word1 & 0x1f) == 31)
			op->type = R_ANAL_OP_TYPE_RET;
		else
			op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case V810_OR:
	case V810_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case V810_MUL:
	case V810_MULU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case V810_XOR:
	case V810_XORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case V810_AND:
	case V810_ANDI:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case V810_CMP:
	case V810_CMP_IMM5:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case V810_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case V810_ADD:
	case V810_ADDI:
	case V810_ADD_IMM5:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case V810_SHR:
	case V810_SHR_IMM5:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case V810_SAR:
	case V810_SAR_IMM5:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case V810_SHL:
	case V810_SHL_IMM5:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case V810_LDB:
	case V810_LDH:
	case V810_LDW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case V810_STB:
	case V810_STH:
	case V810_STW:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case V810_INB:
	case V810_INH:
	case V810_INW:
	case V810_OUTB:
	case V810_OUTH:
	case V810_OUTW:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case V810_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case V810_RETI:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case V810_JAL:
	case V810_JR:
		r_mem_copyendian((ut8*)&word2, buf + 2, 2, LIL_ENDIAN);

		destaddr = ((word1 & 0x3FF) << 16) | word2;
		if (destaddr & 0x2000000)
			destaddrs = destaddr | 0xFC000000;
		else
			destaddrs = destaddr;

		op->jump = addr + destaddrs;
		op->fail = addr + 4;
		if (opcode == V810_JAL)
			op->type = R_ANAL_OP_TYPE_CALL;
		else
			op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case V810_BCOND:
		destaddr = word1 & 0x1FE;
		if (destaddr & 0x100) {
			destaddrs = destaddr | 0xFFFFFE00;
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

struct r_anal_plugin_t r_anal_plugin_v810 = {
	.name = "v810",
	.desc = "V810 code analysis plugin",
	.license = "LGPL3",
	.arch = "v810",
	.bits = 32,
	.op = v810_op,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_v810,
	.version = R2_VERSION
};
#endif
