/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#if 0
static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
}
#endif

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, const char *buf)
{
	int len = 0;
	char cmd[128];
	u8 *out;
	sprintf(cmd, "nasm /dev/stdin -o /dev/stdout <<__\nBITS %i\nORG 0x%llx\n%s\n__", a->bits, a->pc, buf);
	out = (u8 *)r_sys_cmd_str(cmd, "", &len);
	if (out) {
		memcpy(aop->buf, out, len);
		free(out);
	}
	aop->inst_len = len;
	aop->disasm_obj = NULL;
	return len;
}

struct r_asm_handle_t r_asm_plugin_x86_nasm = {
	.name = "asm_x86_nasm",
	.desc = "X86 nasm assembler plugin",
	.arch = "x86",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL, /*&disassemble,*/
	.assemble = &assemble, 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nasm
};
#endif
