/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <java/javasm/javasm.h>


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	javasm_init();
	aop->inst_len = java_disasm(buf, aop->buf_asm);
	aop->disasm_obj = NULL;

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	aop->inst_len = java_assemble(aop->buf, buf);
	aop->disasm_obj = NULL;
	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_java = {
	.name = "asm_java",
	.desc = "java disassembly plugin",
	.arch = "java",
	.bits = (int[]){ 8, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_java
};
#endif
