/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "fastcall_x86.h"
#include "x86/ollyasm/disasm.h"

static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len) {
	t_disasm disasm_obj;

	lowercase=1;
	aop->disasm_obj = &disasm_obj;
	aop->inst_len = Disasm_olly(buf, len, a->pc, &disasm_obj, DISASM_FILE);
	snprintf(aop->buf_asm, R_ASM_BUFSIZE, "%s", disasm_obj.result);

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf) {
	static t_asmmodel asm_obj;
	int attempt, constsize, oattempt = 0, oconstsize = 0, ret = 0, oret = 0xCAFE;

	/* attempt == 0: First attempt */
	/* constsize == 0: Address constants and inmediate data of 16/32b */
	for (constsize = 0; constsize < 4; constsize++) {
		for (attempt = 0; ret > 0; attempt++) {
			ret = Assemble((char*)buf, a->pc, &asm_obj, attempt, constsize, aop->buf_err);
			if (ret > 0 && ret < oret) {
				oret = ret;
				oattempt = attempt;
				oconstsize = constsize;
			}
		}
	}
	aop->inst_len = Assemble((char*)buf, a->pc, &asm_obj, oattempt, oconstsize, aop->buf_err);
	if (aop->inst_len < 0)
		aop->inst_len = 0;

	aop->disasm_obj = &asm_obj;
	if (aop->inst_len > 0)
		memcpy(aop->buf, asm_obj.code, aop->inst_len<=R_ASM_BUFSIZE?aop->inst_len:R_ASM_BUFSIZE);

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_x86_olly = {
	.name = "x86.olly",
	.desc = "X86 disassembly plugin (olly engine)",
	.arch = "x86",
	.bits = (int[]){ 32, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble,
	.fastcall = (void *)fastcall,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_olly
};
#endif
