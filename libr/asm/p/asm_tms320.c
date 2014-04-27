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
	if (a->cpu && strcasecmp(a->cpu, "c54x") == 0)
		tms320_f_set_cpu(&engine, TMS320_F_CPU_C54X);
	if (a->cpu && strcasecmp(a->cpu, "c55x") == 0)
		tms320_f_set_cpu(&engine, TMS320_F_CPU_C55X);
	if (a->cpu && strcasecmp(a->cpu, "c55x+") == 0)
		tms320_f_set_cpu(&engine, TMS320_F_CPU_C55X_PLUS);
	op->size = tms320_dasm (&engine, buf, len);
	snprintf (op->buf_asm, R_ASM_BUFSIZE-1, "%s", engine.syntax);
	return op->size;
}

static int tms320_init(void * user) {
	return tms320_dasm_init (&engine);
}

static int tms320_fini(void * user) {
	return tms320_dasm_fini (&engine);
}

RAsmPlugin r_asm_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.cpus = "c54x,c55x,c55x+",
	.desc = "TMS320 DSP family",
	.license = "LGPLv3",
	.bits = 32,
	.init = tms320_init,
	.fini = tms320_fini,
	.disassemble = tms320_disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tms320
};
#endif
