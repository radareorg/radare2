/* radare - LGPL - Copyright 2019-2021 - pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

RAsmPlugin r_asm_plugin_null = {
	.name = "null",
	.author = "pancake",
	.version = "1.0.0",
	.arch = "null",
	.license = "MIT",
	.bits = 8 | 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "no disassemble",
	.disassemble = NULL,
	.assemble = NULL,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_null,
	.version = R2_VERSION
};
#endif
