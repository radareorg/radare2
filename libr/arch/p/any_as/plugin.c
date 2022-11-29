/* Copyright (C) 2008-2022 - pancake */

#include <r_arch.h>

static bool as_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	int len = 0;
	char *gas = r_sys_getenv ("RASM2_AS");
	if (!gas) {
		// TODO: find in PATH
		gas = strdup ("as");
	}
	char *cmd = r_str_newf (
		"%s -o a.out /dev/stdin <<__\n%s\n__\n"
		"rabin2 -rO 'd/S/*text' a.out; rm -f a.out\n",
		gas, op->mnemonic);
	ut8 *out = (ut8 *)r_sys_cmd_str (cmd, NULL, &len);
	if (out) {
		r_anal_op_set_bytes (op, op->addr, out, len);
		free (out);
	}
	op->size = len;
	free (cmd);
	return len > 0;
}

RArchPlugin r_arch_plugin_any_as = {
	.name = "any.as",
	.desc = "Uses system gnu/clang 'as' assembler",
	.author = "pancake",
	.license = "LGPL3",
	// TODO: add the "any" architecture to support any, instead of using null
	.arch = "any", // on purpose because that's a multi-arch plugin
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.encode = &as_encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_any_as,
	.version = R2_VERSION
};
#endif
