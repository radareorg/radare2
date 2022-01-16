/* radare - LGPL3 - Copyright 2021 - condret, slowhand99 */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/jdh8/jdh8dis.c"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	int dlen = jdh8Disass(r_op, buf, len);
	return r_op->size = R_MAX (0, dlen);
}

RAsmPlugin r_asm_plugin_jdh8 = {
	.name = "jdh8",
	.desc = "jdh-8 toy architecture",
	.arch = "jdh-8",
	.author = "condret, slowhand99",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_jdh8,
	.version = R2_VERSION
};
#endif
