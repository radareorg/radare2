/* radare - LGPL3 - Copyright 2021-2022 - condret, slowhand99 */

#include <r_anal.h>
#include <r_lib.h>
#include "./jdh8dis.c"

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	int dlen = 0;
	char *o = jdh8Disass (op->bytes, op->size, &dlen);
	const bool is_valid = o && strcmp (o, "invalid");
	if (R_STR_ISNOTEMPTY (o)) {
		free (op->mnemonic);
		op->mnemonic = o;
		o = NULL;
	}
	op->size = R_MAX (0, dlen);
	free (o);
	return is_valid;
}

const RArchPlugin r_arch_plugin_jdh8 = {
	.meta = {
		.name = "jdh8",
		.desc = "jdh-8 toy architecture",
		.license = "LGPL3",
	},
	.arch = "jdh8",
	.bits = R_SYS_BITS_PACK1 (16),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_jdh8,
	.version = R2_VERSION
};
#endif
