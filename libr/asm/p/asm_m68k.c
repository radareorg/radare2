/* radare - GPL3 - Copyright 2009-2014 - nibble */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "m68k/m68k_disasm/m68k_disasm.h"

static int disassemble(RAsm *a, RAsmOp *aop, const ut8 *buf, int len) {
	m68k_word bof[8] = {0};
	int iaddr = (int)a->pc;
	char opcode[256], operands[256];
	const unsigned char *buf2;
	int ilen ;
	static struct DisasmPara_68k dp;
	/* initialize DisasmPara */
	*operands = *opcode = 0;
	memcpy (bof, buf, R_MIN(len, sizeof(bof)));
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = (m68k_word *) (size_t)iaddr;
	dp.instr = bof;
	buf2 = (const ut8*)M68k_Disassemble (&dp);
	if (!buf2) {
		// invalid instruction
		return aop->size = 2;
	}
	ilen = (buf2-(const ut8*)bof);
	if (*operands)
		snprintf (aop->buf_asm, R_ASM_BUFSIZE, "%s %s", opcode, operands);
	else snprintf (aop->buf_asm, R_ASM_BUFSIZE, "%s", opcode);
	aop->size = ilen;
	return aop->size;
}

RAsmPlugin r_asm_plugin_m68k = {
	.name = "m68k",
	.arch = "m68k",
	.license = "BSD",
	.bits = 16|32,
	.desc = "Motorola 68000",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k
};
#endif
