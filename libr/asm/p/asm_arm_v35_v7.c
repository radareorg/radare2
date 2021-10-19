/* radare2 - LGPL - Copyright 2021 - pancake, aemmitt */

#include <r_asm.h>
#include <r_lib.h>
#include "../arch/arm/v35arm64/arch-armv7/armv7_disasm/armv7.c"
// #include "armv7.h"

#define DISASM_SUCCESS 0

R_API int disassemble_armv7(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	Instruction inst = {0};
	char output[256];
	int fc = armv7_disassemble (&inst, output, sizeof (output));
	if (fc != DISASM_SUCCESS) {
		return -1;
	}
	op->size = 2;
	r_str_trim_tail (output);
	r_str_replace_char (output, '\t', ' ');
	r_str_replace_char (output, '#', ' ');
	if (r_str_startswith (output, "UNDEF")) {
		r_strbuf_set (&op->buf_asm, "undefined");
		return 2 - (a->pc % 2);
	}
	r_strbuf_set (&op->buf_asm, output);
	return op->size;
}
