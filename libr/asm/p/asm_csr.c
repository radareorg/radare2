/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "csr/csr_disasm/dis.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	arch_csr_disasm(aop->buf_asm, buf, a->pc);
	aop->inst_len = 2;
	aop->disasm_obj = NULL;

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_csr = {
	.name = "asm_csr",
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
