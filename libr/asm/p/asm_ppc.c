/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "ppc/ppc_disasm/ppc_disasm.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len)
{
	ppc_word iaddr = (ppc_word)a->pc;
	ppc_word bof[4];
	char opcode[128];
	char operands[128];

	static struct DisasmPara_PPC dp;
	/* initialize DisasmPara */
	memcpy(bof, buf, 4);
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = &iaddr;
	dp.instr = bof;
	PPC_Disassemble(&dp, a->big_endian);
	aop->disasm_obj = &dp;
	snprintf(aop->buf_asm, R_ASM_BUFSIZE, "%s %s", opcode, operands);
	aop->inst_len = 4;

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_ppc = {
	.name = "ppc",
	.arch = "powepc",
	.bits = (int[]){ 32, 0 },
	.desc = "PPC disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc
};
#endif
