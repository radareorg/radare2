/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_asm.h>

#include "udis86/types.h"
#include "udis86/extern.h"
#include "ollyasm/disasm.h"


int r_asm_x86_disasm(struct r_asm_t *a, u8 *buf, u64 len)
{
	union {
		ud_t     ud;
		t_disasm olly;
	} disasm_obj;
	int ret = 0;

	switch (a->syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
		ud_init(&disasm_obj.ud);
		if (a->syntax == R_ASM_SYN_INTEL)
			ud_set_syntax(&disasm_obj.ud, UD_SYN_INTEL);
		else ud_set_syntax(&disasm_obj.ud, UD_SYN_ATT);
		ud_set_mode(&disasm_obj.ud, a->bits);
		ud_set_pc(&disasm_obj.ud, a->pc);
		ud_set_input_buffer(&disasm_obj.ud, buf, len);
		ud_disassemble(&disasm_obj.ud);
		snprintf(a->buf_asm, 256, "%s", ud_insn_asm(&disasm_obj.ud));
		snprintf(a->buf_hex, 256, "%s", ud_insn_hex(&disasm_obj.ud));
		ret = ud_insn_len(&disasm_obj.ud);
		break;
	case R_ASM_SYN_OLLY:
		lowercase=1;
		ret = Disasm(buf, len, a->pc, &disasm_obj.olly, DISASM_FILE);
		snprintf(a->buf_asm, 256, "%s", disasm_obj.olly.result);
		snprintf(a->buf_hex, 256, "%s", disasm_obj.olly.dump);
		break;
	default:
		ret = 0;
	}

	return ret;
}

int r_asm_x86_asm(struct r_asm_t *a, char *buf)
{
	union {
		t_asmmodel olly;
	} asm_obj;
	int idx, ret = 0;

	switch (a->syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
		/* TODO: Use gas for assembling */
		ret = 0;
		break;
	case R_ASM_SYN_OLLY:
		a->buf_err[0] = '\0';
		/* constsize == 0: Address constants and inmediate data of 16/32b */
		/* attempt == 0: First attempt */
		ret = Assemble(buf, a->pc, &asm_obj.olly, 0, 0, a->buf_err);
		if (a->buf_err[0])
			ret = 0;
		else {
			snprintf(a->buf_asm, 256, "%s", buf);
			for (idx = 0; idx < ret; idx++)
				sprintf(a->buf_hex+idx*2, "%02x", (u8)asm_obj.olly.code[idx]);
		}
		break;
	default:
		ret = 0;
	}

	return ret;
}
