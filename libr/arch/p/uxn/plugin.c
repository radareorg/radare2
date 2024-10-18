/* radare2 - MIT - Copyright 2024 - pancake */

#include <r_arch.h>
#include "uxndisass.inc.c"

static bool uxn_decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	char text[32];

	int len = uxn_disassemble (op->bytes, op->size, text, sizeof (text));
	if (len > 0) {
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = len;
		op->mnemonic = strdup (text);
	} else {
		op->size = 1;
	}
	return true;
}

static int archinfo(RArchSession *a, ut32 q) {
	return 1;
}

const RArchPlugin r_arch_plugin_uxn = {
	.meta = {
		.name = "uxn",
		.author = "pancake",
		.desc = "UXN",
		.license = "MIT",
	},
	.bits = 32,
	.arch = "uxn",
	.info = archinfo,
	.decode = &uxn_decode,
	// .encode = &uxn_encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_uxn,
	.version = R2_VERSION
};
#endif
