/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "fastcall_x86.h"

#if 0
static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len)
{
}
#endif

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	int len = 0;
	char cmd[R_ASM_BUFSIZE];
	ut8 *out;
	sprintf(cmd, "nasm /dev/stdin -o /dev/stdout <<__\nBITS %i\nORG 0x%llx\n%s\n__", a->bits, a->pc, buf);
	out = (ut8 *)r_sys_cmd_str(cmd, "", &len);
	if (out) {
		memcpy(aop->buf, out, len<=R_ASM_BUFSIZE?len:R_ASM_BUFSIZE);
		free(out);
	}
	aop->inst_len = len;
	return len;
}

struct r_asm_handle_t r_asm_plugin_x86_nasm = {
	.name = "x86.nasm",
	.desc = "X86 nasm assembler plugin",
	.arch = "x86",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL, /*&disassemble,*/
	.assemble = &assemble, 
	.fastcall = fastcall,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nasm
};
#endif

#if TEST
main()
{
	struct r_asm_fastcall_t *f;
	//f = r_asm_plugin_x86_nasm.fastcall;
	printf("fastcall=%p\n", *r_asm_plugin_x86_nasm.fastcall);
	printf("fastcall=%p\n", fastcall);
	f = fastcall;//r_asm_plugin_x86_nasm.fastcall;
	printf("f=%p (%s)\n", f, f);
	printf("f[0]=%p (%s)\n", f[0], f[0]);
	printf("f[3].arg[1]=%s\n", f[3].arg[1]);
}
#endif
