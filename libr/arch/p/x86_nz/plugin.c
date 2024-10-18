/* Copyright (C) 2008-2023 - pancake, unlogic, emvivre */

#include <r_arch.h>
#include "nzasm.c"

static bool x86nz_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	int res = x86nz_assemble (s, op, op->mnemonic);
	if (res > 0) {
		op->size = res;
		return true;
	}
	return false;
}

const RArchPlugin r_arch_plugin_x86_nz = {
	.meta = {
		.name = "x86.nz",
		.desc = "x86 handmade assembler",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.encode = &x86nz_encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_x86_nz,
	.version = R2_VERSION
};
#endif
