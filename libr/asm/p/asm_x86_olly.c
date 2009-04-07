/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "x86/ollyasm/disasm.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	t_disasm disasm_obj;

	lowercase=1;
	aop->inst_len = Disasm_olly(buf, len, a->pc, &disasm_obj, DISASM_FILE);
	snprintf(aop->buf_asm, 256, "%s", disasm_obj.result);
	snprintf(aop->buf_hex, 256, "%s", disasm_obj.dump);

	if (aop->inst_len > 0)
		memcpy(aop->buf, buf, aop->inst_len);

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, const char *buf)
{
	static t_asmmodel asm_obj;
	int idx;

	aop->buf_err[0] = '\0';
	/* constsize == 0: Address constants and inmediate data of 16/32b */
	/* attempt == 0: First attempt */
	aop->inst_len = Assemble(buf, a->pc, &asm_obj, 0, 0, aop->buf_err);
	aop->disasm_obj = &asm_obj;
	if (aop->buf_err[0])
		aop->inst_len = 0;
	else {
		snprintf(aop->buf_asm, 256, "%s", buf);
		for (idx = 0; idx < aop->inst_len; idx++)
			sprintf(aop->buf_hex+idx*2, "%02x", (u8)asm_obj.code[idx]);
	}

	if (aop->inst_len > 0)
		memcpy(aop->buf, asm_obj.code, aop->inst_len);

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_x86_olly = {
	.name = "asm_x86_olly",
	.desc = "X86 disassembly plugin (olly engine)",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_olly
};
#endif
