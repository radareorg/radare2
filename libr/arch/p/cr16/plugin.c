/* radare - LGPL - Copyright 2012-2023 - pancake
	2014 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <r_arch.h>
#include "cr16_disas.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	struct cr16_cmd cmd = {0};
	const ut64 addr = op->addr;

	int oplen = cr16_decode_command (op->bytes, &cmd, op->size);
	if (oplen < 1) {
		return false;
	}
	op->size = oplen;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_str_newf ("%s %s", cmd.instr, cmd.operands);
	}

	switch (cmd.type) {
	case CR16_TYPE_MOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case CR16_TYPE_MUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case CR16_TYPE_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case CR16_TYPE_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case CR16_TYPE_BE:
	case CR16_TYPE_BNE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case CR16_TYPE_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case CR16_TYPE_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case CR16_TYPE_SCOND:
		break;
	case CR16_TYPE_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case CR16_TYPE_SHIFT:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case CR16_TYPE_BIT:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_SLPR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_BCOND:
		if (cmd.reladdr) {
			op->jump = addr + cmd.reladdr;
			op->fail = addr + 2;
		}
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case CR16_TYPE_BR:
	case CR16_TYPE_BAL:
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case CR16_TYPE_EXCP:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case CR16_TYPE_JCOND:
	case CR16_TYPE_JAL:
	case CR16_TYPE_JUMP:
	case CR16_TYPE_JUMP_UNK:
		if (cmd.reladdr) {
			op->jump = addr + cmd.reladdr;
			op->fail = addr + 2;
		}
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case CR16_TYPE_RETX:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case CR16_TYPE_PUSH:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case CR16_TYPE_POP:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case CR16_TYPE_LOAD:
	case CR16_TYPE_DI:
	case CR16_TYPE_EI:
	case CR16_TYPE_STOR:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case CR16_TYPE_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case CR16_TYPE_WAIT:
	case CR16_TYPE_EWAIT:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
	return true;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 4;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 0;
}

const RArchPlugin r_arch_plugin_cr16 = {
	.meta = {
		.name = "cr16",
		.author = "Fedor Sakharov,pancake",
		.desc = "Compact RISC processor",
		.license = "LGPL-3.0-only",
	},
	.endian = R_SYS_ENDIAN_LITTLE,
	.arch = "cr16",
// 	.cpus = "crc16c,plus", only supported in the gnu plugin, which we dont have :D
	.info = &archinfo,
	.bits = R_SYS_BITS_PACK1 (16),
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_cr16,
	.version = R2_VERSION
};
#endif
