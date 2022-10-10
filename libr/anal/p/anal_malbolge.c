/* radare - LGPL - Copyright 2015-2022 - condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int mal_anal(RAnal *anal, RArchOp *op, ut64 addr, const ut8 *data, int len, RArchOpMask mask) {
	if (len) {
		switch ((data[0] + addr) % 94) {
		case 4:
			op->type = R_ARCH_OP_TYPE_UJMP;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("jmp [d]");
			}
			break;
		case 5:
			op->type = R_ARCH_OP_TYPE_IO;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("out a");
			}
			break;
		case 23:
			op->type = R_ARCH_OP_TYPE_IO;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("in a");
			}
			break;
		case 39:
			op->type = R_ARCH_OP_TYPE_ROR;
			op->type2 = R_ARCH_OP_TYPE_LOAD;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("rotr [d], mov a, [d]");
			}
			break;
		case 40:
			op->type = R_ARCH_OP_TYPE_LOAD;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("mov d, [d]");
			}
			break;
		case 62:
			op->type = R_ARCH_OP_TYPE_XOR;
			op->type2 = R_ARCH_OP_TYPE_LOAD;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("crz [d], a, mov a, [d]");
			}
			break;
		case 81:
			op->type = R_ARCH_OP_TYPE_TRAP;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("end");
			}
			break;
		default:
			op->type = R_ARCH_OP_TYPE_NOP;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("nop");
			}
		}
		return op->size = 1;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge analysis plugin",
	.arch = "malbolge",
	.license = "LGPL3",
	.bits = 32,
	.op = &mal_anal,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_malbolge,
	.version = R2_VERSION
};
#endif
