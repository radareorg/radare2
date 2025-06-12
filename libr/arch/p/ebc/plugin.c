/* radare - LGPL - Copyright 2012-2021 - pancake, fedor.sakharov */

#include <string.h>
#include <r_arch.h>
#include "./ebc_disas.h"

static void ebc_anal_jmp8(RAnalOp *op, ut64 addr, const ut8 *buf) {
	int jmpadr = (int8_t)buf[1];
	op->addr = addr;
	op->fail = addr + 2;
	op->jump = op->fail + (jmpadr * 2);
	op->type = TEST_BIT (buf[0], 7) ? R_ANAL_OP_TYPE_CJMP: R_ANAL_OP_TYPE_JMP;
}

static void ebc_anal_jmp(RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->fail = addr + 6;
	op->jump = r_read_le32 (buf + 2);
	if (TEST_BIT (buf[1], 4)) {
		op->jump += addr + 6;
	}
	if (buf[1] & 0x7) {
		op->type = R_ANAL_OP_TYPE_UJMP;
	} else {
		op->type = (TEST_BIT (buf[1], 7)) ? R_ANAL_OP_TYPE_CJMP: R_ANAL_OP_TYPE_JMP;
	}
}

static void ebc_anal_call(RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->fail = addr + 6;
	if ((buf[1] & 0x7) == 0 && TEST_BIT (buf[0], 6) == 0 && TEST_BIT (buf[0], 7)) {
		int addr_call = r_read_le32 (buf + 2);
		if (TEST_BIT(buf[1], 4)) {
			op->jump = (addr + 6 + addr_call);
		} else {
			op->jump = addr_call;
		}
		op->type = R_ANAL_OP_TYPE_CALL;
	} else {
		op->type = R_ANAL_OP_TYPE_UCALL;
	}
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	if (len < 1) {
		return false;
	}

	ebc_command_t cmd;
	ut8 opcode = buf[0] & EBC_OPCODE_MASK;
	if (!op) {
		return false;
	}

	op->addr = addr;

	int ret = op->size = ebc_decode_command (buf, &cmd);
	if (ret < 0) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char *inststr = cmd.operands[0]
			? r_str_newf ("%s %s", cmd.instr, cmd.operands)
			: strdup (cmd.instr);
		op->mnemonic = inststr;
	}

	switch (opcode) {
	case EBC_JMP8:
		ebc_anal_jmp8 (op, addr, buf);
		break;
	case EBC_JMP:
		ebc_anal_jmp (op, addr, buf);
		break;
	case EBC_MOVBW:
	case EBC_MOVWW:
	case EBC_MOVDW:
	case EBC_MOVQW:
	case EBC_MOVBD:
	case EBC_MOVWD:
	case EBC_MOVDD:
	case EBC_MOVQD:
	case EBC_MOVSNW:
	case EBC_MOVSND:
	case EBC_MOVQQ:
	case EBC_MOVNW:
	case EBC_MOVND:
	case EBC_MOVI:
	case EBC_MOVIN:
	case EBC_MOVREL:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case EBC_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case EBC_CMPEQ:
	case EBC_CMPLTE:
	case EBC_CMPGTE:
	case EBC_CMPULTE:
	case EBC_CMPUGTE:
	case EBC_CMPIEQ:
	case EBC_CMPILTE:
	case EBC_CMPIGTE:
	case EBC_CMPIULTE:
	case EBC_CMPIUGTE:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case EBC_SHR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case EBC_SHL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case EBC_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case EBC_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case EBC_MUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case EBC_PUSH:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case EBC_POP:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case EBC_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case EBC_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case EBC_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case EBC_NEG:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case EBC_CALL:
		ebc_anal_call(op, addr, buf);
		break;
	case EBC_BREAK:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
	return ret > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 18;
	}
	return 1;
}

const RArchPlugin r_arch_plugin_ebc = {
	.meta = {
		.name = "ebc",
		.desc = "EFI Bytecode Virtual Machine",
		.license = "LGPL-3.0-only",
		.author = "Fedor Sakharov",
	},
	.info = archinfo,
	.arch = "ebc",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ebc,
	.version = R2_VERSION
};
#endif
