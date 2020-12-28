/* radare - LGPL - Copyright 2014-2015 - condret
                   Copyright 2016      - unlogic
*/

#include <r_asm.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>
#include "z80_tab.h"

static ut8 z80_op_24_branch_index_res (ut8 hex) {
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

static int z80OpLength (const ut8 *buf, int len) {
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

// #include'd in asm/p/asm_z80.c
FUNC_ATTR_USED static int z80Disass (RAsmOp *op, const ut8 *buf, int len) {
	int ret = z80OpLength (buf, len);
	const z80_opcode *z_op;
	const char **cb_tab;
	ut8 res;
	if (!ret) {
		return ret;
	}
	z_op = z80_op;
	const char *buf_asm = "invalid";
	switch (z_op[buf[0]].type) {
	case Z80_OP8:
		buf_asm = sdb_fmt ("%s", z_op[buf[0]].name);
		break;
	case Z80_OP8^Z80_ARG8:
		buf_asm = sdb_fmt (z_op[buf[0]].name, buf[1]);
		break;
	case Z80_OP8^Z80_ARG16:
		buf_asm = sdb_fmt (z_op[buf[0]].name, buf[1]+(buf[2]<<8));
		break;
	case Z80_OP16:
		cb_tab = (const char **) z_op[buf[0]].op_moar;
		buf_asm = sdb_fmt ("%s", cb_tab[buf[1]]);
		break;
	case Z80_OP_UNK ^ Z80_ENC1:
		z_op = (const z80_opcode *)z_op[buf[0]].op_moar;
		res = z80_ed_branch_index_res (buf[1]);
		if (z_op[res].type == Z80_OP16) {
			buf_asm = sdb_fmt ("%s", z_op[res].name);
		}
		if (z_op[res].type == (Z80_OP16^Z80_ARG16)) {
			buf_asm = sdb_fmt (z_op[res].name, buf[2]+(buf[3]<<8));
		}
		break;
	case Z80_OP_UNK ^ Z80_ENC0:
		z_op = (const z80_opcode *)z_op[buf[0]].op_moar;
		res = z80_fddd_branch_index_res (buf[1]);
		if (z_op[res].type == Z80_OP16) {
			buf_asm = sdb_fmt ("%s", z_op[res].name);
		}
		if (z_op[res].type == (Z80_OP16^Z80_ARG16)) {
			buf_asm = sdb_fmt (z_op[res].name, buf[2]+(buf[3]<<8));
		}
		if (z_op[res].type == (Z80_OP16^Z80_ARG8)) {
			buf_asm = sdb_fmt (z_op[res].name, buf[2]);
		}
		if (z_op[res].type == (Z80_OP24 ^ Z80_ARG8)) {
			cb_tab = (const char **) z_op[res].op_moar;
			buf_asm = sdb_fmt (cb_tab[z80_op_24_branch_index_res (buf[3])], buf[2]);
		}
		if (z_op[res].type == (Z80_OP16 ^ Z80_ARG8 ^ Z80_ARG16)) {
			buf_asm = sdb_fmt (z_op[res].name, buf[2], buf[3]);
		}
		break;
	}
	if (!strcmp (buf_asm, "invalid")) {
		ret = 0;
	}
	r_asm_op_set_asm (op, buf_asm);
	return ret;
}
