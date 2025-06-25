/* radare - LGPL - Copyright 2014-2025 - Fedor Sakharov, pancake */

#include <r_arch.h>
#include "./msp430_disas.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const int addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	if (len < 1) {
		return false;
	}

	struct msp430_cmd cmd = {0};
	op->size = -1;
	op->nopcode = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	int ret = op->size = msp430_decode_command (buf, len, &cmd);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (ret < 1) {
			op->mnemonic = strdup ("invalid");
		} else if (ret > 0) {
			if (cmd.operands[0]) {
				op->mnemonic = r_str_newf ("%s %s", cmd.instr, cmd.operands);
			} else {
				op->mnemonic = strdup (cmd.instr);
			}
		}
		{ // if (a->syntax != R_ARCH_SYNTAX_ATT)
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
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case MSP430_PUSH:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case MSP430_CALL:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->fail = addr + op->size;
			if (len > 4) {
				op->jump = r_read_at_le16 (buf, 2);
			}
			break;
		case MSP430_RETI:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
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

static char* regs(RArchSession *as) {
	const char *p = \
		"=PC	pc\n"
		"=SP	sp\n"
		"=SN	r0\n"
		// this is the "new" ABI, the old was reverse order
		"=A0	r12\n"
		"=A1	r13\n"
		"=A2	r14\n"
		"=A3	r15\n"
		"gpr	r0	.16 0   0\n"
		"gpr	r1	.16 2   0\n"
		"gpr	r2	.16 4   0\n"
		"gpr	r3	.16 6   0\n"
		"gpr	r4	.16 8   0\n"
		"gpr	r5	.16 10  0\n"
		"gpr	r6	.16 12  0\n"
		"gpr	r7	.16 14  0\n"
		"gpr	r8	.16 16  0\n"
		"gpr	r9	.16 18  0\n"
		"gpr	r10   .16 20  0\n"
		"gpr	r11   .16 22  0\n"
		"gpr	r12   .16 24  0\n"
		"gpr	r13   .16 26  0\n"
		"gpr	r14   .16 28  0\n"
		"gpr	r15   .16 30  0\n"

		"gpr	pc	.16 0 0\n" // same as r0
		"gpr	sp	.16 2 0\n" // same as r1
		"flg	sr	.16 4 0\n" // same as r2
		"flg	c	.1  4 0\n"
		"flg	z	.1  4.1 0\n"
		"flg	n	.1  4.2 0\n"
		// between is SCG1 SCG0 OSOFF CPUOFF GIE
		"flg	v	.1  4.8 0\n";

	return strdup (p);
}

static int info(RArchSession *as, ut32 q) {
	return 0;
}

const RArchPlugin r_arch_plugin_msp430 = {
	.meta = {
		.name = "msp430",
		.author = "Fedor Sakharov,pancake",
		.desc = "TI MSP430 mixed signal microcontroller family from Texas Instruments",
		.license = "LGPL-3.0-only",
	},
	.arch = "msp430",
	.bits = R_SYS_BITS_PACK1 (16),
	.decode = &decode,
	.info = info,
	.regs = regs,
};
