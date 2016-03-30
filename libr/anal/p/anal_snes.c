/* radare - LGPL - Copyright 2015 - condret */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/snes/snes_op_table.h"

static int snes_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	memset (op, '\0', sizeof (RAnalOp));
	op->size = snes_op_get_size(anal->bits, &snes_op[data[0]]);
	if (op->size > len)
		return op->size = 0;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (data[0]) {
		case 0xea:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 0xfb:
			op->type = R_ANAL_OP_TYPE_XCHG;
			break;
		case 0x1b:				//TCS
		case 0x3b:				//TSC
		case 0x5b:				//TCD
		case 0x7b:				//TDC
		case 0x8a:				//TXA
		case 0x98:				//TYA
		case 0x9a:				//TXS
		case 0x9b:				//TXY
		case 0xa8:				//TAY
		case 0xaa:				//TAX
		case 0xba:				//TSX
		case 0xbb:				//TYX
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_snes = {
	.name = "snes",
	.desc = "SNES analysis plugin",
	.license = "LGPL3",
	.arch = "snes",
	.bits = 16,
	.op = &snes_anop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_snes,
	.version = R2_VERSION
};
#endif
