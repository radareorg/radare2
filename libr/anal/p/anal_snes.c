/* radare - LGPL - Copyright 2015 - condret */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/snes/snes_op_table.h"

static int snes_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	memset (op, '\0', sizeof (RAnalOp));
	op->size = snes_op[data[0]].len;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (data[0]) {
		case 0xea:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_snes = {
	.name = "snes",
	.desc = "SNES analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_NONE,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &snes_anop,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_snes,
	.version = R2_VERSION
};
#endif
