/* radare - LGPL - Copyright 2010-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

// XXX: TODO Implement
static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int len = 0;
	char cmd[R_ASM_BUFSIZE];
	ut8 *out;
	snprintf (cmd, sizeof (cmd),
		"gas /dev/stdin -o /dev/stdout <<__\n"
		"BITS %i\nORG 0x%"PFMT64x"\n%s\n__",
		a->bits, a->pc, buf);
	out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
	if (out) {
		memcpy (op->buf, out, len<=R_ASM_BUFSIZE?len:R_ASM_BUFSIZE);
		free (out);
	}
	op->inst_len = len;
	return len;
}

RAsmPlugin r_asm_plugin_x86_nasm = {
	.name = "gas",
	.license = "LGPL3",
	.desc = "GNU Assembler plugin",
	.arch = "x86", // XXX
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL, /*&disassemble,*/
	.assemble = &assemble, 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_gas
};
#endif
