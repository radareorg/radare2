/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/lua53/lua53.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = lua53dissasm (op, buf, len);
}

static int do_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->size = lua53asm (op, buf);
}

RAsmPlugin r_asm_plugin_lua53 = {
	.name = "lua53",
	.desc = "Lua 5.3 VM",
	.license = "MIT",
	.arch = "lua53",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &do_disassemble,
	.assemble = &do_assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_lua53,
	.version = R2_VERSION
};
#endif