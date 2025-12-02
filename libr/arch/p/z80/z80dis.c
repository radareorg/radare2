/* radare - GPL - Copyright 2002-2025 - pancake, condret, unlogic */

#include <r_arch.h>
#include <string.h>
#include "z80_tab.h"
#include "z80dis.h"

// AITODO this function looks wrong or confusing, and i bet it can be reimplkemented in a much cleaner and simpler way
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

// AITODO this function looks like dupped work from the decoder
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
			type = op[z80_fddd_branch_index_res (buf[1])].type;
		} else if (op[buf[0]].type & Z80_ENC1) {
			op = (const z80_opcode *)op[buf[0]].op_moar;
			type = op[z80_ed_branch_index_res (buf[1])].type;
		}
	} else {
		type = op[buf[0]].type;
	}
	if (type & Z80_OP8) {
		ret++;
	}
	if ((type & Z80_ARG8) && ! (type & Z80_ARG16)) { // XXX review this code
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

void z80_op_size(const ut8 *_data, int len, int *size, int *size_prefix) {
	ut8 data[4] = { 0 };
	int type = 0;
	if (len < 1) {
		return;
	}
	memcpy (data, _data, R_MIN (len, 4));
	switch (data[0]) {
	case 0xed:
		{
			int idx = z80_ed_branch_index_res (data[1]);
			type = ed[idx].type;
		}
		break;
	case 0xcb:
		type = Z80_OP16;
		break;
	case 0xdd:
		type = dd[z80_fddd_branch_index_res (data[1])].type;
		break;
	case 0xfd:
		type = fd[z80_fddd_branch_index_res (data[1])].type;
		break;
	default:
		type = z80_op[data[0]].type;
		break;
	}

	if (type & Z80_OP8) {
		*size_prefix = 1;
	} else if (type & Z80_OP16) {
		*size_prefix = 2;
	} else if (type & Z80_OP24) {
		*size_prefix = 3;
	}
	if (type & Z80_ARG16) {
		*size = *size_prefix + 2;
	} else if (type & Z80_ARG8) {
		*size = *size_prefix + 1;
	} else {
		*size = *size_prefix;
	}
}

char *z80dis(const ut8 *buf, int len) {
	const char **cb_tab;
	ut8 res;
	int ret = z80OpLength (buf, len);
	if (!ret) {
		return NULL;
	}
	const z80_opcode *z_op = z80_op;
	r_strf_buffer (64);
	const char *buf_asm = "invalid";
	switch (z_op[buf[0]].type) {
	case Z80_OP8:
		buf_asm = r_strf ("%s", z_op[buf[0]].name);
		break;
	case Z80_OP8 ^ Z80_ARG8:
		buf_asm = r_strf (z_op[buf[0]].name, buf[1]);
		break;
	case Z80_OP8 ^ Z80_ARG16:
		buf_asm = r_strf (z_op[buf[0]].name, buf[1] + (buf[2] << 8));
		break;
	case Z80_OP16:
		cb_tab = (const char **)z_op[buf[0]].op_moar;
		buf_asm = r_strf ("%s", cb_tab[buf[1]]);
		break;
	case Z80_OP_UNK ^ Z80_ENC1:
		z_op = (const z80_opcode *)z_op[buf[0]].op_moar;
		res = z80_ed_branch_index_res (buf[1]);
		if (z_op[res].type == Z80_OP16) {
			buf_asm = r_strf ("%s", z_op[res].name);
		}
		if (z_op[res].type == (Z80_OP16 ^ Z80_ARG16)) {
			buf_asm = r_strf (z_op[res].name, buf[2] + (buf[3] << 8));
		}
		break;
	case Z80_OP_UNK ^ Z80_ENC0:
		z_op = (const z80_opcode *)z_op[buf[0]].op_moar;
		res = z80_fddd_branch_index_res (buf[1]);
		if (z_op[res].type == Z80_OP16) {
			buf_asm = r_strf ("%s", z_op[res].name);
		}
		if (z_op[res].type == (Z80_OP16 ^ Z80_ARG16)) {
			buf_asm = r_strf (z_op[res].name, buf[2] + (buf[3] << 8));
		}
		if (z_op[res].type == (Z80_OP16 ^ Z80_ARG8)) {
			buf_asm = r_strf (z_op[res].name, buf[2]);
		}
		if (z_op[res].type == (Z80_OP24 ^ Z80_ARG8)) {
			cb_tab = (const char **)z_op[res].op_moar;
			buf_asm = r_strf (cb_tab[z80_op_24_branch_index_res (buf[3])], buf[2]);
		}
		if (z_op[res].type == (Z80_OP16 ^ Z80_ARG8 ^ Z80_ARG16)) {
			buf_asm = r_strf (z_op[res].name, buf[2], buf[3]);
		}
		break;
	}
	if (!strcmp (buf_asm, "invalid")) {
		return NULL;
	}
	return strdup (buf_asm);
}
