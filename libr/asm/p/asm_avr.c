/* radare - LGPL - Copyright 2010 pancake <@nopcode.org> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/avr/disasm.c"

static int disassemble(RAsm *a, RAsmAop *aop, ut8 *buf, ut64 len) {
	aop->inst_len = avrdis (aop->buf_asm, a->pc, buf, len);
	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.bits = (int[]){ 16, 32, 0 },
	.desc = "AVR Atmel disassembler",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_avr
};
#endif
