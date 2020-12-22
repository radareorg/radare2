/* radare2 - LGPL3 - Copyright 2018 - deroad */

#include <r_asm.h>
#include <r_lib.h>
#include "../arch/mcore/mcore.h"

static mcore_handle handle = {0};

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	mcore_t* instr = NULL;
	char tmp[256];
	if (!op || mcore_init (&handle, buf, len)) {
		return -1;
	}
	op->size = 2;
	if ((instr = mcore_next (&handle))) {
		mcore_snprint (tmp, sizeof (tmp), a->pc, instr);
		mcore_free (instr);
		r_asm_op_set_asm (op, tmp);
	} else {
		r_asm_op_set_asm (op, "invalid");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_mcore = {
	.name = "mcore",
	.desc = "Motorola MCORE disassembler",
	.license = "LGPL3",
	.arch = "mcore",
	.cpus = "mcore,c-sky",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mcore,
	.version = R2_VERSION
};
#endif
