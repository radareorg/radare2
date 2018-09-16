/* radare2 - LGPL - Copyright 2013-2018 - pancake, astuder */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <8051_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = _8051_disas (a->pc, op, buf, len);
	if (dlen < 0) {
		dlen = 0;
	}
	op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "8051 Intel CPU",
	.disassemble = &disassemble,
	.license = "PD",
	.cpus =
		"8051-generic," // First one is default
		"8051-shared-code-xdata"
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_8051,
	.version = R2_VERSION
};
#endif
