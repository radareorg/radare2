/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "csr/dis.c"

static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len) {
	arch_csr_disasm (aop->buf_asm, buf, a->pc);
	return (aop->inst_len=2);
}

RAsmHandler r_asm_plugin_csr = {
	.name = "csr",
	.arch = "csr",
	.bits = (int[]){ 16, 0 },
	.desc = "CSR disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_csr
};
#endif
