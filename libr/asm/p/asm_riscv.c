/* radare - LGPL - Copyright 2015-2021 - qnix */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
// GNU Binutils Disassembler
#include "../arch/riscv/riscv-opc.c"
#include "../arch/riscv/riscv.c"
// custom handwritten assembler
#include "../arch/riscv/riscvasm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = riscv_dis (a, op, buf, len);
}

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	ut8 *opbuf = (ut8*)r_strbuf_get (&op->buf);
	int ret = riscv_assemble (str, a->pc, opbuf);
	if (a->config->big_endian) {
		ut8 *buf = opbuf;
		ut8 tmp = buf[0];
		buf[0] = buf[3];
		buf[3] = tmp;
		tmp = buf[1];
		buf[1] = buf[2];
		buf[2] = tmp;
	}
	return ret;
}

RAsmPlugin r_asm_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V disassembler",
	.arch = "riscv",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.license = "GPL",
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_riscv,
	.version = R2_VERSION
};
#endif
