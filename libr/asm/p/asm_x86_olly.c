/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "x86/ollyasm/disasm.h"

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	t_disasm disasm_obj;

	op->size = Disasm_olly(buf, len, a->pc, &disasm_obj, DISASM_FILE);
	snprintf(op->buf_asm, R_ASM_BUFSIZE, "%s", disasm_obj.result);

	return op->size;
}

static int assemble(struct r_asm_t *a, struct r_asm_op_t *op, const char *buf) {
	char buf_err[128];
	static t_asmmodel asm_obj;
	int attempt, constsize, oattempt = 0, oconstsize = 0, ret = 0, oret = 0xCAFE;

	/* attempt == 0: First attempt */
	/* constsize == 0: Address constants and inmediate data of 16/32b */
	for (constsize = 0; constsize < 4; constsize++) {
		for (attempt = 0; ret > 0; attempt++) {
			ret = Assemble((char*)buf, a->pc, &asm_obj, attempt, constsize, buf_err);
			if (ret > 0 && ret < oret) {
				oret = ret;
				oattempt = attempt;
				oconstsize = constsize;
			}
		}
	}
	op->size = R_MAX (0, Assemble((char*)buf, a->pc, &asm_obj, oattempt, oconstsize, buf_err));
	if (op->size > 0)
		memcpy (op->buf, asm_obj.code, R_MIN(op->size, (R_ASM_BUFSIZE-1)));
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_olly = {
	.name = "x86.olly",
	.license = "GPL2",
	.desc = "OllyDBG X86 disassembler",
	.arch = "x86",
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_olly
};
#endif
