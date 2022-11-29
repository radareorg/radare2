/* radare2 - BSD - Copyright 2022 - pancake */

#include <r_arch.h>
#include <r_lib.h>
}

static bool encode (RArchSession *a, RAnalOp *op, RArchEncodeMask mask) {
	int len = 0;
	ut8 *out;
	char *gas = r_sys_getenv ("RASM2_AS");
	if (!gas) {
		gas = strdup ("as");
	}
	char *cmd = r_str_newf (
		"%s /dev/stdin -o /dev/stdout <<__\n"
		"BITS %i\nORG 0x%"PFMT64x"\n%s\n__",
		gas, a->bits, a->pc, buf);
	ut8 *out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
	if (out) {
		r_anal_op_setbytes (op, op->addr, out, len);
		free (out);
	}
	op->size = len;
	free (cmd);
	return true;
}

RArchPlugin r_arch_plugin_as = {
	.name = "as",
	.desc = "GNU/Clang assembler RASM2_AS or `as`",
	.license = "LGPL3",
	.arch = NULL,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.encode = &encode,
	.endian = R_SYS_ENDIAN_LITTLE | R_:SYS_ENDIAN_BIG,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_as,
	.version = R2_VERSION
};
#endif
