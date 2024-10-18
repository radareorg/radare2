/* radare - LGPL - Copyright 2015-2022 - condret */

#include <r_anal.h>
#include <r_lib.h>

static bool mal_decode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	if (op->size < 1 || !op->bytes) {
		return false;
	}
	const ut8 *data = op->bytes;
	switch ((data[0] + op->addr) % 94) {
	case 4:
		op->type = R_ANAL_OP_TYPE_UJMP;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("jmp [d]");
		}
		break;
	case 5:
		op->type = R_ANAL_OP_TYPE_IO;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("out a");
		}
		break;
	case 23:
		op->type = R_ANAL_OP_TYPE_IO;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("in a");
		}
		break;
	case 39:
		op->type = R_ANAL_OP_TYPE_ROR;
		op->type2 = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("rotr [d], mov a, [d]");
		}
		break;
	case 40:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("mov d, [d]");
		}
		break;
	case 62:
		op->type = R_ANAL_OP_TYPE_XOR;
		op->type2 = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("crz [d], a, mov a, [d]");
		}
		break;
	case 81:
		op->type = R_ANAL_OP_TYPE_TRAP;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("end");
		}
		break;
	default:
		op->type = R_ANAL_OP_TYPE_NOP;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("nop");
		}
	}
	op->size = 1;
	return true;
}

const RArchPlugin r_arch_plugin_malbolge = {
	.meta = {
		.name = "malbolge",
		.author = "pancake",
		.desc = "Malbolge analysis plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "malbolge",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = &mal_decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_malbolge,
	.version = R2_VERSION
};
#endif
