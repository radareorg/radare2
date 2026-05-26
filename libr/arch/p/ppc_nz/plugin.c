/* radare - LGPL - Copyright 2026 - phix33 */

#include <r_arch.h>
#include "nzasm.c"

static bool ppc_nz_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	int n = ppc_nz_assemble (s, op, op->mnemonic);
	if (n > 0) {
		op->size = n;
		return true;
	}
	return false;
}

const RArchPlugin r_arch_plugin_ppc_nz = {
	.meta = {
		.name = "ppc.nz",
		.desc = "PowerPC handmade assembler",
		.author = "phix33",
		.license = "LGPL-3.0-only",
	},
	.arch = "ppc",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.encode = &ppc_nz_encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ppc_nz,
	.version = R2_VERSION
};
#endif
