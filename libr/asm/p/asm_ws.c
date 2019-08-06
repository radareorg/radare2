/* radare - LGPL - Copyright 2014 - condret */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#define WS_API static
#include "../arch/whitespace/wsdis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return wsdis (op, buf, len);
}

RAsmPlugin r_asm_plugin_ws = {
	.name = "ws",
	.desc = "Whitespace esotheric VM",
	.arch = "whitespace",
	.license = "LGPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ws,
	.version = R2_VERSION
};
#endif
