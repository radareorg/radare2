/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <psosvm/vmas/vmas.h>


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	psosvmasm_init();
	aop->inst_len = psosvm_disasm(buf, aop->buf_asm);
	aop->disasm_obj = NULL;

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	aop->inst_len = psosvm_assemble(aop->buf, buf);
	aop->disasm_obj = NULL;
	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_psosvm = {
	.name = "asm_psosvm",
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
