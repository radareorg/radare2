/* radare - LGPL - Copyright 2014-2015 - condret
                   Copyright 2016      - unlogic
*/

#include <r_asm.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>
#include "z80_tab.h"

static ut8 z80_fddd_branch_index_res (ut8 hex)
{
	switch (hex) {
		case 0x9:
			return 0x0;
		case 0x19:
			return 0x1;
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
			return hex-0x1f;
		case 0x29:
		case 0x2a:
		case 0x2b:
		case 0x2c:
		case 0x2d:
		case 0x2e:
			return hex-0x21;
		case 0x34:
		case 0x35:
		case 0x36:
			return hex-0x26;
		case 0x39:
			return 0x11;
		case 0x44:
		case 0x45:
		case 0x46:
			return hex-0x32;
		case 0x4c:
		case 0x4d:
		case 0x4e:
			return hex-0x37;
		case 0x54:			//0x18
		case 0x55:
		case 0x56:
			return hex-0x3c;
		case 0x5c:
		case 0x5d:
		case 0x5e:			//0x1d
			return hex-0x41;
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
		case 0x68:
		case 0x69:
		case 0x6a:
		case 0x6b:
		case 0x6c:
		case 0x6d:
		case 0x6e:
		case 0x6f:
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
			return hex-0x42;
		case 0x77:
			return 0x34;
		case 0x7c:
		case 0x7d:
		case 0x7e:
			return hex-0x47;
		case 0x84:
		case 0x85:
		case 0x86:
			return hex-0x4c;
		case 0x8c:
		case 0x8d:
		case 0x8e:
			return hex-0x51;
		case 0x94:
		case 0x95:
		case 0x96:
			return hex-0x56;
		case 0x9c:
		case 0x9d:
		case 0x9e:
			return hex-0x5b;
		case 0xa4:
		case 0xa5:
		case 0xa6:
			return hex-0x60;
		case 0xac:
		case 0xad:
		case 0xae:
			return hex-0x65;
		case 0xb4:
		case 0xb5:
		case 0xb6:
			return hex-0x6a;
		case 0xbc:
		case 0xbd:
		case 0xbe:
			return hex-0x6f;
		case 0xcb:
			return 0x50;
		case 0xe1:
			return 0x51;
		case 0xe3:
			return 0x52;
		case 0xe5:
			return 0x53;
		case 0xe9:
			return 0x54;
		case 0xf9:
			return 0x55;
	}
	return 0x56;
}

static ut8 z80_ed_branch_index_res (ut8 hex) {
	if (hex > 0x3f && 0x4c > hex)
		return hex-0x40;
	if (hex == 0x4d)
		return 0xc;
	if (hex > 0x4d && 0x54 > hex)
		return hex-0x42;
	if (hex > 0x55 && 0x5c > hex)
		return hex-0x44;
	if (hex > 0x5d && 0x63 > hex)
		return hex-0x46;
	if (hex > 0x66 && 0x6b > hex)
		return hex-0x4a;
	if (hex > 0x6e && 0x74 > hex)
		return hex-0x4e;
	if (hex > 0x77 && 0x7c > hex)
		return hex-0x52;
	if (hex > 0x9f && 0xa4 > hex)
		return hex-0x76;
	if (hex > 0xa7 && 0xac > hex)
		return hex-0x7a;
	if (hex > 0xaf && 0xb4 > hex)
		return hex-0x7e;
	if (hex > 0xb7 && 0xbc > hex)
		return hex-0x82;
	return 0x3b;
}

static ut8 z80_op_24_branch_index_res (ut8 hex) {
	if (hex < 0x40)
		return hex;
	switch (hex) {
		case 0x46:
			return 0x40;
		case 0x4e:
			return 0x41;
		case 0x56:
			return 0x42;
		case 0x5e:
			return 0x43;
		case 0x66:
			return 0x44;
		case 0x6e:
			return 0x45;
		case 0x76:
			return 0x46;
		case 0x7e:
			return 0x47;
	}
	if (hex > 0x7f)
		return hex-0x38;
	return 0xc8;
}

static int z80OpLength (const ut8 *buf, int len) {
	z80_opcode *op;
	int type = 0, ret = 0;
	if (len < 1)
		return 0;
	op = z80_op;
	if (op[buf[0]].type & Z80_OP_UNK) {
		if (len < 2)
			return 0;
		if (op[buf[0]].type & Z80_ENC0) {
			op = (z80_opcode *)op[buf[0]].op_moar;
			type = op[z80_fddd_branch_index_res(buf[1])].type;
		} else if (op[buf[0]].type & Z80_ENC1) {
			op = (z80_opcode *)op[buf[0]].op_moar;
			type = op[z80_ed_branch_index_res(buf[1])].type;
		}
	} else {
		type = op[buf[0]].type;
	}
	if (type & Z80_OP8)
		ret++;
	if ((type & Z80_ARG8) && !(type & Z80_ARG16))								//XXX
		ret++;
	if (type & Z80_OP16)
		ret += 2;
	if (type & Z80_ARG16)
		ret += 2;
	if (type & Z80_OP24)
		ret += 3;
	if (ret > len)
		return 0;

	return ret;
}

static int z80Disass (RAsmOp *op, const ut8 *buf, int len) {
	int ret = z80OpLength (buf, len);
	z80_opcode *z_op;
	char **cb_tab;
	ut8 res;
	if (!ret)
		return ret;
	z_op = z80_op;

	switch (z_op[buf[0]].type) {
		case Z80_OP8:
			sprintf (op->buf_asm, "%s", z_op[buf[0]].name);
			return ret;
		case Z80_OP8^Z80_ARG8:
			sprintf (op->buf_asm, z_op[buf[0]].name, buf[1]);
			return ret;
		case Z80_OP8^Z80_ARG16:
			sprintf (op->buf_asm, z_op[buf[0]].name, buf[1]+(buf[2]<<8));
			return ret;
		case Z80_OP16:
			cb_tab = (char **) z_op[buf[0]].op_moar;
			sprintf (op->buf_asm, "%s", cb_tab[buf[1]]);
			return ret;
		case Z80_OP_UNK^Z80_ENC1:
			z_op = (z80_opcode *)z_op[buf[0]].op_moar;
			res = z80_ed_branch_index_res (buf[1]);
			if (z_op[res].type == Z80_OP16)
				sprintf (op->buf_asm, "%s", z_op[res].name);
			if (z_op[res].type == (Z80_OP16^Z80_ARG16))
				sprintf (op->buf_asm, z_op[res].name, buf[2]+(buf[3]<<8));
			return ret;
		case Z80_OP_UNK^Z80_ENC0:
			z_op = (z80_opcode *)z_op[buf[0]].op_moar;
			res = z80_fddd_branch_index_res (buf[1]);
			if (z_op[res].type == Z80_OP16)
				sprintf (op->buf_asm, "%s", z_op[res].name);
			if (z_op[res].type == (Z80_OP16^Z80_ARG16))
				sprintf (op->buf_asm, z_op[res].name, buf[2]+(buf[3]<<8));
			if (z_op[res].type == (Z80_OP16^Z80_ARG8))
				sprintf (op->buf_asm, z_op[res].name, buf[2], buf[3]);
			if (z_op[res].type == (Z80_OP24^Z80_ARG8)) {
				cb_tab = (char **) z_op[res].op_moar;
				sprintf (op->buf_asm, cb_tab[z80_op_24_branch_index_res (buf[3])], buf[2]);
			}
			if (z_op[res].type == (Z80_OP16^Z80_ARG8^Z80_ARG16))
				sprintf (op->buf_asm, z_op[res].name, buf[2], buf[3]);
	}
	if (!strcmp (op->buf_asm, "invalid"))
		ret = 0;
	return ret;
}
