/* radare - LGPL - Copyright 2010-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int len = 0;
	ut8 *out;
	char *cmd = r_str_newf (
		"gas /dev/stdin -o /dev/stdout <<__\n"
		"BITS %i\nORG 0x%"PFMT64x"\n%s\n__",
		a->bits, a->pc, buf);
	ut8 *out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
	if (out) {
		r_asm_op_set_buf (op, out, len);
		free (out);
	}
	op->size = len;
	free (cmd);
	return len;
}

RAsmPlugin r_asm_plugin_x86_gas = {
	.name = "x86.gas",
	.license = "LGPL3",
	.desc = "GNU Assembler (gas)",
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_gas,
	.version = R2_VERSION
};
#endif
