/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

#include "m68k_disasm/m68k_disasm.h"

int r_asm_m68k_disasm(struct r_asm_t *a, u8 *buf, u64 len)
{
	m68k_word bof[4];
	m68k_word iaddr = (m68k_word)a->pc;
	char opcode[256];
	char operands[256];

	struct DisasmPara_68k dp;
	/* initialize DisasmPara */
	memcpy(bof, buf, 4);
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = &iaddr;
	dp.instr = bof;
	M68k_Disassemble(&dp);
	sprintf(a->buf_asm, "%s %s", opcode, operands);
	r_hex_bin2str((u8*)bof, 4, a->buf_hex);
	memcpy(a->buf, bof, 4);
	a->inst_len = 4;

	return a->inst_len;
}
