/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "x86/udis86/types.h"
#include "x86/udis86/extern.h"
#include "x86/ollyasm/disasm.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	union {
		ud_t     ud;
		t_disasm olly;
	} disasm_obj;

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
		aop->inst_len = ud_insn_len(&disasm_obj.ud);
		snprintf(aop->buf_asm, 256, "%s", ud_insn_asm(&disasm_obj.ud));
		snprintf(aop->buf_hex, 256, "%s", ud_insn_hex(&disasm_obj.ud));
		break;
	case R_ASM_SYN_OLLY:
		lowercase=1;
		aop->inst_len = Disasm(buf, len, a->pc, &disasm_obj.olly, DISASM_FILE);
		snprintf(aop->buf_asm, 256, "%s", disasm_obj.olly.result);
		snprintf(aop->buf_hex, 256, "%s", disasm_obj.olly.dump);
		break;
	default:
		aop->inst_len = 0;
	}

	if (aop->inst_len > 0)
		memcpy(aop->buf, buf, aop->inst_len);

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	union {
		t_asmmodel olly;
	} asm_obj;
	int idx;

	switch (a->syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
		/* TODO: Use gas for assembling */
		aop->inst_len = 0;
		break;
	case R_ASM_SYN_OLLY:
		aop->buf_err[0] = '\0';
		/* constsize == 0: Address constants and inmediate data of 16/32b */
		/* attempt == 0: First attempt */
		aop->inst_len = Assemble(buf, a->pc, &asm_obj.olly, 0, 0, aop->buf_err);
		if (aop->buf_err[0])
			aop->inst_len = 0;
		else {
			snprintf(aop->buf_asm, 256, "%s", buf);
			for (idx = 0; idx < aop->inst_len; idx++)
				sprintf(aop->buf_hex+idx*2, "%02x", (u8)asm_obj.olly.code[idx]);
		}
		break;
	default:
		aop->inst_len = 0;
	}

	if (aop->inst_len > 0)
		memcpy(aop->buf, buf, aop->inst_len);

	return aop->inst_len;
}

static struct r_asm_handle_t r_asm_plugin_x86 = {
	.name = "asm_x86",
	.desc = "X86 disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86
};
