/* radare - LGPL - Copyright 2014-2022 - Fedor Sakharov, pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include "../arch/msp430/msp430_disas.h"

static int msp430_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int ret;
	struct msp430_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));
	//op->id = ???;
	op->size = -1;
	op->nopcode = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	ret = op->size = msp430_decode_command (buf, len, &cmd);
	if (mask & R_ANAL_OP_MASK_DISASM) {
		if (ret < 1) {
			op->mnemonic = strdup ("invalid");
		} else if (ret > 0) {
			if (cmd.operands[0]) {
				op->mnemonic = r_str_newf ("%s %s",cmd.instr, cmd.operands);
			} else {
				op->mnemonic = strdup (cmd.instr);
			}
		}
		{ // if (a->syntax != R_ASM_SYNTAX_ATT)
			char *ba = op->mnemonic;
			r_str_replace_ch (ba, '#', 0, 1);
			// r_str_replace_ch (ba, "$", "$$", 1);
			r_str_replace_ch (ba, '&', 0, 1);
			r_str_replace_ch (ba, '%', 0, 1);
		}
	}

	if (ret < 0) {
		return ret;
	}

	op->addr = addr;

	switch (cmd.type) {
	case MSP430_ONEOP:
		switch (cmd.opcode) {
		case MSP430_RRA:
		case MSP430_RRC:
			op->type = R_ANAL_OP_TYPE_ROR; break;
		case MSP430_PUSH:
			op->type = R_ANAL_OP_TYPE_PUSH; break;
		case MSP430_CALL:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->fail = addr + op->size;
			op->jump = r_read_at_le16 (buf, 2);
			break;
		case MSP430_RETI:
			op->type = R_ANAL_OP_TYPE_RET; break;
		}
		break;
	case MSP430_TWOOP:
		switch (cmd.opcode) {
		case MSP430_BIT:
		case MSP430_BIC:
		case MSP430_BIS:
		case MSP430_MOV:
			op->type = R_ANAL_OP_TYPE_MOV;
			if ((cmd.instr)[0] == 'b' && (cmd.instr)[1] == 'r') {
				// Emulated branch instruction, moves source operand to PC register.
				op->type = R_ANAL_OP_TYPE_UJMP;
			}
			break;
		case MSP430_DADD:
		case MSP430_ADDC:
		case MSP430_ADD: op->type = R_ANAL_OP_TYPE_ADD; break;
		case MSP430_SUBC:
		case MSP430_SUB: op->type = R_ANAL_OP_TYPE_SUB; break;
		case MSP430_CMP: op->type = R_ANAL_OP_TYPE_CMP; break;
		case MSP430_XOR: op->type = R_ANAL_OP_TYPE_XOR; break;
		case MSP430_AND: op->type = R_ANAL_OP_TYPE_AND; break;
		}
		break;
	case MSP430_JUMP:
		if (cmd.jmp_cond == MSP430_JMP) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
		}
		op->jump = addr + cmd.jmp_addr;
		op->fail = addr + 2;
		break;
	case MSP430_INV:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
	return ret;
}

RAnalPlugin r_anal_plugin_msp430 = {
	.name = "msp430",
	.desc = "TI MSP430 code analysis plugin",
	.license = "LGPL3",
	.arch = "msp430",
	.bits = 16,
	.op = msp430_op,
};
