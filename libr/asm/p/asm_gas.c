/* radare - LGPL - Copyright 2010-2015 - pancake */

// XXX: deprecate

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
	op->size = len;
	return len;
}

RAsmPlugin r_asm_plugin_x86_gas = {
	.name = "x86.gas",
	.license = "LGPL3",
	.desc = "GNU Assembler (gas)",
	.arch = NULL, //"x86", // XXX
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = NULL, /*&disassemble,*/
	.assemble = &assemble
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_gas,
	.version = R2_VERSION
};
#endif
