/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <psosvm/vmas/vmas.h>

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, ut8 *buf, ut64 len) {
	psosvmasm_init();
	op->inst_len = psosvm_disasm(buf, op->buf_asm);

	return op->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_op_t *op, const char *buf) {
	op->inst_len = psosvm_assemble(op->buf, buf);
	return op->inst_len;
}

RAsmPlugin r_asm_plugin_psosvm = {
	.name = "psosvm",
	.desc = "PSOS-VM disassembly plugin",
	.arch = "psosvm",
	.bits = (int[]){ 8, 16, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_psosvm
};
#endif
