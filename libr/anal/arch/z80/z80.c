/* radare - LGPL - Copyright 2014-2015 - condret
                   Copyright 2016      - unlogic
*/

#include <r_asm.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>
#include "z80_tab.h"

// deprecate this file completely
static ut8 z80_op_24_branch_index_res(ut8 hex) {
	if (hex < 0x40) {
		return hex;
	}
	switch (hex) {
	case 0x46: return 0x40;
	case 0x4e: return 0x41;
	case 0x56: return 0x42;
	case 0x5e: return 0x43;
	case 0x66: return 0x44;
	case 0x6e: return 0x45;
	case 0x76: return 0x46;
	case 0x7e: return 0x47;
	}
	return (hex > 0x7f)? hex - 0x38: 0xc8;
}

static int z80OpLength(const ut8 *buf, int len) {
	const z80_opcode *op;
	int type = 0, ret = 0;
	if (len < 1) {
		return 0;
	}
	op = z80_op;
	if (op[buf[0]].type & Z80_OP_UNK) {
		if (len < 2) {
			return 0;
		}
		if (op[buf[0]].type & Z80_ENC0) {
			op = (const z80_opcode *)op[buf[0]].op_moar;
			type = op[z80_fddd_branch_index_res(buf[1])].type;
		} else if (op[buf[0]].type & Z80_ENC1) {
			op = (const z80_opcode *)op[buf[0]].op_moar;
			type = op[z80_ed_branch_index_res(buf[1])].type;
		}
	} else {
		type = op[buf[0]].type;
	}
	if (type & Z80_OP8) {
		ret++;
	}
	if ((type & Z80_ARG8) && !(type & Z80_ARG16)) { //XXX
		ret++;
	}
	if (type & Z80_OP16) {
		ret += 2;
	}
	if (type & Z80_ARG16) {
		ret += 2;
	}
	if (type & Z80_OP24) {
		ret += 3;
	}
	if (ret > len) {
		return 0;
	}
	return ret;
}
