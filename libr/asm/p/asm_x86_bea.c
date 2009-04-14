/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "x86/bea/BeaEngine.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	static DISASM disasm_obj;

	memset(&disasm_obj, '\0', sizeof(DISASM));
	disasm_obj.EIP = (long long)buf;
	disasm_obj.VirtualAddr = a->pc;
	disasm_obj.Archi = ((a->bits == 64) ? 64 : 0);
	disasm_obj.SecurityBlock = len;
	if (a->syntax == R_ASM_SYN_ATT)
		disasm_obj.Options = 0x400;
	else
		disasm_obj.Options = 0;

	aop->inst_len = Disasm(&disasm_obj);
	aop->disasm_obj = &disasm_obj;

	snprintf(aop->buf_asm, 256, disasm_obj.CompleteInstr);

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_x86_bea = {
	.name = "asm_x86_bea",
	.desc = "X86 disassembly plugin (bea engine)",
	.arch = "x86",
	.bits = (int[]){ 32, 64, 0 }, /* also 16 ? */
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_bea
};
#endif
