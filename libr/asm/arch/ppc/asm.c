/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

#include "ppc_disasm/ppc_disasm.h"

int r_asm_ppc_disasm(struct r_asm_t *a, u8 *buf, u64 len)
{
	ppc_word iaddr = (ppc_word)a->pc;
	ppc_word bof[4];
	char opcode[128];
	char operands[128];

	struct DisasmPara_PPC dp;
	/* initialize DisasmPara */
	memcpy(bof, buf, 4);
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = &iaddr;
	dp.instr = bof;
	PPC_Disassemble(&dp, a->big_endian);
	r_hex_bin2str((u8*)bof, 4, a->buf_hex);
	sprintf(a->buf_asm, "%s %s", opcode, operands);

	return 4;
}
