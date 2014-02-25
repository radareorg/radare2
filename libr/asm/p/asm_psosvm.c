/* radare - LGPL - Copyright 2009-2013 - nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <psosvm/vmas/vmas.h>

static int disassemble(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	psosvmasm_init();
	op->size = psosvm_disasm(buf, op->buf_asm);
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	op->size = psosvm_assemble(op->buf, buf);
	return op->size;
}

RAsmPlugin r_asm_plugin_psosvm = {
	.name = "psosvm",
	.desc = "Smartcard PSOS Virtual Machine",
	.license = "BSD",
	.arch = "psosvm",
	.bits = 8|16,
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
