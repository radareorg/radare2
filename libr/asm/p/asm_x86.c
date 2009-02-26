/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "x86/udis86/types.h"
#include "x86/udis86/extern.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	static ud_t disasm_obj;

	ud_init(&disasm_obj);
	if (a->syntax == R_ASM_SYN_ATT)
		ud_set_syntax(&disasm_obj, UD_SYN_ATT);
	else
		ud_set_syntax(&disasm_obj, UD_SYN_INTEL);
	ud_set_mode(&disasm_obj, a->bits);
	ud_set_pc(&disasm_obj, a->pc);
	ud_set_input_buffer(&disasm_obj, buf, len);
	ud_disassemble(&disasm_obj);
	aop->disasm_obj = &disasm_obj;
	aop->inst_len = ud_insn_len(&disasm_obj);
	snprintf(aop->buf_asm, 256, "%s", ud_insn_asm(&disasm_obj));
	snprintf(aop->buf_hex, 256, "%s", ud_insn_hex(&disasm_obj));

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
	.assemble = NULL
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86
};
