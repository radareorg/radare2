/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <8051_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char *tmp = NULL;

	r_8051_op o = r_8051_decode (buf, len);
	memset(op->buf_asm, 0, sizeof (op->buf_asm));
	if (!o.name) return 0; // invalid instruction
	tmp = r_8051_disasm (o, a->pc, op->buf_asm, sizeof (op->buf_asm));
	if (tmp) {
		if (strlen(tmp) < sizeof (op->buf_asm)) {
			strncpy (op->buf_asm, tmp, strlen (tmp));
		} else {
			eprintf ("8051 disassemble: too big opcode!\n");
			free (tmp);
			op->size = -1;
			return -1;
		}
		free (tmp);
	}
	if (!*op->buf_asm) {
		op->size = 1;
		return -1;
	}
	return (op->size = o.length);
}

RAsmPlugin r_asm_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.bits = 8,
	.desc = "8051 Intel CPU",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL,
	.license = "PD"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_8051
};
#endif
