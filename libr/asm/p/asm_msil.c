/* radare - GPL3 - Copyright 2011-2014 - capi_x, pancake */

#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "msil/demsil.c"

static int arch_msil_disasm(char *str, const ut8 *buf, ut64 seek) {
	ut32 n;
	int o; 
	DISASMSIL_OFFSET CodeBase = seek;
	ILOPCODE_STRUCT ilopar[8];
	o = DisasMSIL (buf, 16, CodeBase, ilopar, 8, &n);
	sprintf (str,"%s", ilopar[0].Mnemonic);
	return o;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return (op->size = arch_msil_disasm (op->buf_asm, buf, a->pc));
}

RAsmPlugin r_asm_plugin_msil = {
	.name = "msil",
	.arch = "msil",
	.license = "PD",
	.bits = 16|32|64,
	.desc = ".NET Microsoft Intermediate Language",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_msil
};
#endif
