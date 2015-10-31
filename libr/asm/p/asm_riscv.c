/* radare - LGPL - Copyright 2015 - qnix */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/riscv/riscv-opc.c"
#include "../arch/riscv/riscv.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = riscv_dis (a, op, buf, len);
	op->size = dlen;
	return dlen;;
}

RAsmPlugin r_asm_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V",
	.arch = "riscv",
	.bits = 32|64,
	.license = "GPL",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_riscv,
	.version = R2_VERSION
};
#endif
