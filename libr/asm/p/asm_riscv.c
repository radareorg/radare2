/* radare - LGPL - Copyright 2015-2021 - qnix */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/riscv/riscv-opc.c"
#include "../arch/riscv/riscv.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = riscv_dis (a, op, buf, len);
}

RAsmPlugin r_asm_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V",
	.arch = "riscv",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.license = "GPL",
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_riscv,
	.version = R2_VERSION
};
#endif
