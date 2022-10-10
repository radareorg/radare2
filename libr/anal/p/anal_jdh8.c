/* radare - LGPL3 - Copyright 2021-2022 - condret, slowhand99 */

#include <r_anal.h>
#include <r_lib.h>
#include "../../asm/arch/jdh8/jdh8dis.c"

static int jdh8_op(RAnal *anal, RArchOp *op, ut64 addr, const ut8 *buf, int len, RArchOpMask mask) {
	int dlen = 0;
	char *o = jdh8Disass (buf, len, &dlen);
	op->mnemonic = strdup (o);
	op->size = R_MAX (0, dlen);
	// honor DISASM, add esil and more
	return dlen;
}

RAnalPlugin r_anal_plugin_jdh8 = {
	.name = "jdh8",
	.desc = "jdh-8 toy architecture",
	.license = "LGPL3",
	.arch = "jdh8",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.op = &jdh8_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_jdh8,
	.version = R2_VERSION
};
#endif
