/*
 * TMS320 disassembly engine
 *
 * Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>
 *
 * Distributed under LGPLv3
 */

#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/tms320/tms320_dasm.h"

static tms320_dasm_t engine = { };

static int tms320_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int ret = 1;

	ret = tms320_dasm(&engine, buf, len);

	snprintf(op->buf_asm, R_ASM_BUFSIZE, \
		 "%s", ret < 0 ? "invalid" : engine.syntax);

	return (op->size = ret);
}

static int tms320_set_subarch(RAsm *a, const char * name)
{
	if (strcmp(name, "C55X") == 0) {
		fprintf(stderr, "C55X requested\n");
		return 1;
	}

	return 0;
}

static int tms320_init(void * user)
{
	return tms320_dasm_init(&engine);
}

static int tms320_fini(void * user)
{
	return tms320_dasm_fini(&engine);
}

RAsmPlugin r_asm_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.desc = "TMS320 DSP family disassembly plugin",
	.license = "LGPLv3",
	.bits = 32|64,
	.init = tms320_init,
	.fini = tms320_fini,
	.disassemble = tms320_disassemble,
	.set_subarch = tms320_set_subarch,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tms320
};
#endif
