/* radare - LGPL - Copyright 2009-2019 - earada, pancake, h4ng3r */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <dalvik/opcode.h>

//TODO
static int dalvik_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int i;

	//a->dataalign = 2;

	char *p = strchr (buf, ' ');
	if (p) {
		*p = 0;
	}
	// TODO: use a hashtable here
	for (i = 0; i < 256; i++) {
		if (!strcmp (dalvik_opcodes[i].name, buf)) {
			ut8 buf[4];
			r_write_ble32 (buf, i, a->config->big_endian);
			r_strbuf_setbin (&op->buf, buf, sizeof (buf));
			op->size = dalvik_opcodes[i].len;
			return op->size;
		}
	}
	return 0;
}

RAsmPlugin r_asm_plugin_dalvik = {
	.name = "dalvik",
	.arch = "dalvik",
	.license = "LGPL3",
	.desc = "AndroidVM Dalvik",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	//.disassemble = &dalvik_disassemble,
	.assemble = &dalvik_assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dalvik,
	.version = R2_VERSION
};
#endif
