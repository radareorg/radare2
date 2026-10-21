/* radare - LGPL - Copyright 2015-2019 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "8051_ops.h"

static char *r_8051_disas(ut64 pc, const ut8 *buf, int len, int *olen) {
	int i = 0;
	while (_8051_ops[i].string && _8051_ops[i].op != (buf[0] & ~_8051_ops[i].mask)) {
		i++;
	}
	const char *name = _8051_ops[i].string;
	if (!name) {
		return NULL;
	}
	const ut8 mask = _8051_ops[i].mask;
	const ut8 arg1 = _8051_ops[i].arg1;
	const ut8 arg2 = _8051_ops[i].arg2;
	const ut8 arg3 = _8051_ops[i].arg3;
	const ut8 oplen = _8051_ops[i].len;
	if (len < oplen) {
		*olen = -1;
		return strdup ("truncated");
	}
	char *disasm = NULL;
	switch (oplen) {
	case 1:
		if ((arg1 == A_RI) || (arg1 == A_RN)) {
			// op @Ri; op Rn
			disasm = r_str_newf (name, buf[0] & mask);
		} else {
			disasm = strdup (name);
		}
		break;
	case 2:
		if (arg1 == A_OFFSET) {
			disasm = r_str_newf (name, arg_offset (pc + 2, buf[1]));
		} else if (arg1 == A_ADDR11) {
			disasm = r_str_newf (name, arg_addr11 (pc + 2, buf));
		} else if ((arg1 == A_RI) || (arg1 == A_RN)) {
			// op @Ri, arg; op Rn, arg
			if (arg2 == A_OFFSET) {
				disasm = r_str_newf (name, buf[0] & mask, arg_offset (pc + 2, buf[1]));
			} else {
				disasm = r_str_newf (name, buf[0] & mask, buf[1]);
			}
		} else if ((arg2 == A_RI) || (arg2 == A_RN)) {
			// op arg, @Ri; op arg, Rn
			disasm = r_str_newf (name, buf[1], buf[0] & mask);
		} else if (arg1 == A_BIT) {
			disasm = r_str_newf (name, arg_bit (buf[1]), buf[1] & 0x07);
		} else {
			// direct, immediate, bit
			disasm = r_str_newf (name, buf[1]);
		}
		break;
	case 3:
		if ((arg1 == A_ADDR16) || (arg1 == A_IMM16)) {
			disasm = r_str_newf (name, 0x100 * buf[1] + buf[2]);
		} else if (arg2 == A_OFFSET) {
			if (arg1 == A_BIT) {
				disasm = r_str_newf (name, arg_bit (buf[1]), buf[1] & 0x07, arg_offset (pc + 3, buf[2]));
			} else {
				// direct, offset; a, immediate, offset
				disasm = r_str_newf (name, buf[1], arg_offset (pc + 3, buf[2]));
			}
		} else if (arg3 == A_OFFSET) {
			// @Ri/Rn, immediate, offset
			disasm = r_str_newf (name, buf[0] & mask, buf[1], arg_offset (pc + 3, buf[2]));
		} else if (arg1 == A_DIRECT && arg2 == A_DIRECT) {
			// op direct, direct has src and dest swapped
			disasm = r_str_newf (name, buf[2], buf[1]);
		} else {
			// direct, immediate
			disasm = r_str_newf (name, buf[1], buf[2]);
		}
		break;
	default:
		return NULL;
	}
	*olen = oplen;
	return disasm;
}
