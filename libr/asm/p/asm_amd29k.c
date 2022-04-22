/* radare - LGPL - Copyright 2019 - deroad */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/amd29k/amd29k.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (!a || !op || !buf || len < 4) {
		return -1;
	}
	char buf_asm[64];
	ut64 offset = a->pc;
	amd29k_instr_t instruction = {0};
	op->size = 4;
	if (amd29k_instr_decode (buf, len, &instruction, a->config->cpu)) {
		amd29k_instr_print (buf_asm, sizeof (buf_asm), offset, &instruction);
		r_asm_op_set_asm (op, buf_asm);
		return 4;
	}
	r_asm_op_set_asm (op, "invalid");
	return -1;
}

RAsmPlugin r_asm_plugin_amd29k = {
	.name = "amd29k",
	.license = "LGPL3",
	.desc = "AMD 29k RISC CPU",
	.author = "deroad",
	.arch = CPU_29000","CPU_29050,
	.cpus = "amd29k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_amd29k,
	.version = R2_VERSION
};
#endif
