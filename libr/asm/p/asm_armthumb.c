/* radare - GPL3 - Copyright 2010 pancake<nopcode.org> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/arm/arm.h"

static int disassemble(RAsm *a, RAsmAop *aop, ut8 *buf, ut64 len) {
	int *p = (int*)buf; // TODO : endian
	aop->buf_asm[0]='\0';
	aop->inst_len = armthumb_disassemble (aop->buf_asm, (ut32)a->pc, *p);
	if (!aop->inst_len)
		strncpy (aop->buf_asm, " (data)", R_ASM_BUFSIZE);
	return aop->inst_len;
}

static int assemble(RAsm *a, RAsmAop *aop, const char *buf) {
	int op = armass_assemble (buf, a->pc, R_TRUE);
	if (op==-1)
		return -1;
	r_mem_copyendian (aop->buf, (void *)&op, 2, a->big_endian);
	return armthumb_length (op);
}

RAsmPlugin r_asm_plugin_armthumb = {
	.name = "armthumb",
	.arch = "armthumb",
	.bits = (int[]){ 16, 0 },
	.desc = "ARM THUMB disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_armthumb
};
#endif
