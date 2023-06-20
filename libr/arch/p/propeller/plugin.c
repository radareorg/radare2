/* radare - LGPL - Copyright 2012-2023 - pancake */
/* 2014 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>
#include <r_util.h>

#include "./propeller_disas.h"

// static int propeller_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
static bool propeller_op(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *buf = op->bytes;
	const int len = op->size;
	if (len < 4) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	int ret;
	struct propeller_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));

	ret = op->size = propeller_decode_command (buf, &cmd);

	if (ret < 0) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = ret;
		return true;
	}

	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (cmd.prefix[0] && cmd.operands[0]) {
			op->mnemonic = r_str_newf ("%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
		} else if (cmd.operands[0]) {
			op->mnemonic = r_str_newf ("%s %s", cmd.instr, cmd.operands);
		} else {
			op->mnemonic  = r_str_newf ("%s", cmd.instr);
		}
	}

	switch (cmd.opcode) {
	case PROP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case PROP_TEST:
	case PROP_TESTN:
	case PROP_TJNZ:
	case PROP_TJZ:
	case PROP_CMPS:
	case PROP_CMPSUB:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case PROP_ADD:
	case PROP_ADDX:
	case PROP_ADDABS:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case PROP_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case PROP_RCL:
	case PROP_ROL:
	case PROP_SHL:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case PROP_RCR:
	case PROP_ROR:
	case PROP_SHR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case PROP_NEG:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case PROP_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case PROP_ABS:
	case PROP_MINS:
	case PROP_MIN:
	case PROP_MAX:
	case PROP_MAXS:
	// case PROP_RDBYTE:
	case PROP_RDLONG:
	case PROP_RDWORD:
	case PROP_MOV:
	case PROP_MOVD:
	case PROP_MOVI:
	case PROP_MOVS:
	case PROP_WAITVID:
	case PROP_MUXC:
		if (cmd.opcode == PROP_MOV && cmd.dst == 0x44 && cmd.src == 0x3c) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
		}
		break;
	case PROP_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case PROP_JMP:
	case PROP_DJNZ:
		if (cmd.immed == 0) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = 0x20 + cmd.src;
			op->fail = op->addr + 2;
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->fail = op->addr + 2;
		}
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
	op->size = ret;
	return true;
}

const RArchPlugin r_arch_plugin_propeller = {
	.meta = {
		.name = "propeller",
		.desc = "Parallax propeller code analysis plugin",
		.license = "LGPL3",
	},
	.arch = "propeller",
	.bits = 32,
	.decode = propeller_op,
};
