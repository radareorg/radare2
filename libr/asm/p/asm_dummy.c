/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len)
{
	printf("Dummy (dis)assembly plugin");

	return R_FALSE;
}

struct r_asm_handle_t r_asm_plugin_dummy = {
	.name = "dummy",
	.arch = "none",
	.bits = (int[]){ 0 },
	.desc = "dummy disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL,
	.fastcall = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dummy
};
#endif
