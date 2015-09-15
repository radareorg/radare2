/* radare - LGPL - Copyright 2015 - condret */


#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/snes/snes_op_table.h"

static int _6502_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	memset (op, '\0', sizeof (RAnalOp));
	op->size = snes_op[data[0]].len;	//snes-arch is similiar to nes/6502
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (data[0]) {
		case 0x80:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x22:
		case 0x23:
		case 0x32:
		case 0x33:
		case 0x34:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x82:
		case 0x83:
		case 0x92:
		case 0x93:
		case 0xa3:
		case 0xb2:
		case 0xb3:
		case 0xc2:
		case 0xc3:
		case 0xd2:
		case 0xd3:
		case 0xd4:
		case 0xe2:
		case 0xe3:
		case 0xf2:
		case 0xf3:
		case 0xf4:
		case 0x07:
		case 0x17:
		case 0x27:
		case 0x37:
		case 0x47:
		case 0x57:
		case 0x67:
		case 0x77:
		case 0x87:
		case 0x97:
		case 0xa7:
		case 0xb7:
		case 0xc7:
		case 0xd7:
		case 0xe7:
		case 0xf7:
		case 0x89:
		case 0x0b:
		case 0x0c:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x2b:
		case 0x3a:
		case 0x3b:
		case 0x3c:
		case 0x4b:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x6b:
		case 0x7a:
		case 0x7b:
		case 0x7c:
		case 0x8b:
		case 0x9b:
		case 0x9c:
		case 0xab:
		case 0xbb:
		case 0xcb:
		case 0xda:
		case 0xdb:
		case 0xdc:
		case 0xeb:
		case 0xfa:
		case 0xfb:
		case 0xfc:
		case 0x0f:
		case 0x1f:
		case 0x2f:
		case 0x3f:
		case 0x4f:
		case 0x5f:
		case 0x6f:
		case 0x7f:
		case 0x8f:
		case 0x9e:
		case 0x9f:
		case 0xaf:
		case 0xbf:
		case 0xcf:
		case 0xdf:
		case 0xef:
		case 0xff:
			op->size = 1;
			op->type = R_ANAL_OP_TYPE_ILL;		//those do not exist for 6502 - snes only
			break;
		case 0xea:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_NONE,
	.bits = 8,
	.init = NULL,
	.fini = NULL,
	.op = &_6502_op,
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
	.data = &r_anal_plugin_6502,
	.version = R2_VERSION
};
#endif
