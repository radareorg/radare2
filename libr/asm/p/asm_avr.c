/* radare - LGPL - Copyright 2010-2021 - pancake, dark_k3y */
/* AVR assembler realization by Alexander Bolshev aka @dark_k3y, LGPL -- 2015,
   heavily based (and using!) on disassemble module */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <r_types_base.h>

#include "../arch/avr/avr_disasm.h"
#include "../arch/avr/avr_instructionset.h"
#include "../arch/avr/disasm.h"
#include "../arch/avr/assemble.h"
#include "../arch/avr/format.h"


static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char buf_asm[32] = {0};
	int ret = avr_decode (a, buf_asm, sizeof (buf_asm), a->pc, buf, len);
	if (*buf_asm == '.') {
		*buf_asm = 0;
	}
	if (ret > 1) {
		op->size = ret;
	} else {
		op->size = 2;
	}
	const char *arg = (ret > 1)? buf_asm: "invalid";
	r_strbuf_set (&op->buf_asm, arg);
	return R_MAX (2, op->size);
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
    return avr_encode (a, ao, str);
}

// AVR assembler realization ends
RAsmPlugin r_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.license = "GPL",
	.bits = 8 | 16,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "AVR Atmel",
	.disassemble = &disassemble,
	.assemble = &assemble,
	.cpus =
		"ATmega8," // First one is default
		"ATmega1280,"
		"ATmega1281,"
		"ATmega168,"
		"ATmega2560,"
		"ATmega2561,"
		"ATmega328p,"
		"ATmega32u4,"
		"ATmega48,"
		"ATmega640,"
		"ATmega88,"
		"ATxmega128a4u"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_avr,
	.version = R2_VERSION
};
#endif
