/* radare - LGPL - Copyright 2015-2017 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "8051_ops.h"
#include "8051_disas.h"

static const char *_8051_regs[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", // 0x00
	0, 0, 0, 0, 0, 0, 0, 0, // 0x08
	0, 0, 0, 0, 0, 0, 0, 0, // 0x10
	0, 0, 0, 0, 0, 0, 0, 0, // 0x18
	0, 0, 0, 0, 0, 0, 0, 0, // 0x20
	0, 0, 0, 0, 0, 0, 0, 0, // 0x28
	0, 0, 0, 0, 0, 0, 0, 0, // 0x30
	0, 0, 0, 0, 0, 0, 0, 0, // 0x38
	0, 0, 0, 0, 0, 0, 0, 0, // 0x40
	0, 0, 0, 0, 0, 0, 0, 0, // 0x48
	0, 0, 0, 0, 0, 0, 0, 0, // 0x50
	0, 0, 0, 0, 0, 0, 0, 0, // 0x58
	0, 0, 0, 0, 0, 0, 0, 0, // 0x60
	0, 0, 0, 0, 0, 0, 0, 0, // 0x68
	0, 0, 0, 0, 0, 0, 0, 0, // 0x70
	0, 0, 0, 0, 0, 0, 0, 0, // 0x78
	"p0", "sp", "dpl", "dph", 0, 0, 0, "pcon", // 0x80
	"tcon", "tmod", "tl0", "tl1", "th0", "th1", 0, 0, // 0x88
	"p1", 0, 0, 0, 0, 0, 0, 0, // 0x90
	"scon", "sbuf", 0, 0, 0, 0, 0, 0, // 0x98
	"p2", 0, 0, 0, 0, 0, 0, 0, // 0xa0
	"ie", 0, 0, 0, 0, 0, 0, 0, // 0xa8
	"p3", 0, 0, 0, 0, 0, 0, 0, // 0xb0
	"ip", 0, 0, 0, 0, 0, 0, 0, // 0xb8
	0, 0, 0, 0, 0, 0, 0, 0, // 0xc0
	0, 0, 0, 0, 0, 0, 0, 0, // 0xc8
	"psw", 0, 0, 0, 0, 0, 0, 0, // 0xd0
	0, 0, 0, 0, 0, 0, 0, 0, // 0xd8
	"acc", 0, 0, 0, 0, 0, 0, 0, // 0xe0
	0, 0, 0, 0, 0, 0, 0, 0, // 0xe8
	"b", 0, 0, 0, 0, 0, 0, 0, // 0xf0
	0, 0, 0, 0, 0, 0, 0, 0  // 0xf8
};

R_API char* _replace_register (char* disasm, ut8 arg, ut8 val) {
	char key[10];
	char subst[10];
	if (arg == A_DIRECT) {
		if (_8051_regs[val]) {
			sprintf (key, " 0x%02x", val);
			sprintf (subst, " %s", _8051_regs[val]);
			disasm = r_str_replace (disasm, key, subst, 0);
		}
	} else if (arg == A_BIT) {
		val = arg_bit (val);
		if (_8051_regs[val]) {
			sprintf (key, "0x%02x.", val);
			sprintf (subst, "%s.", _8051_regs[val]);
			disasm = r_str_replace (disasm, key, subst, 0);
		}
	}
	return disasm;
}

int _8051_disas (ut64 pc, RAsmOp *op, const ut8 *buf, ut64 len) {
	int i = 0;
	while (_8051_ops[i].string && _8051_ops[i].op != (buf[0] & ~_8051_ops[i].mask)) {
		i++;
	}

	if (_8051_ops[i].string) {
		// valid opcodes
		const char* name = _8051_ops[i].string;
		ut8 mask = _8051_ops[i].mask;
		ut8 arg1 = _8051_ops[i].arg1;
		ut8 arg2 = _8051_ops[i].arg2;
		ut8 arg3 = _8051_ops[i].arg3;
		ut8 oplen = _8051_ops[i].len;
		ut8 val1, val2 = 0;
		char* disasm = 0;

		switch (oplen) {
		case 1:
			if ((arg1 == A_RI) || (arg1 == A_RN)) {
				// op @Ri; op Rn
				disasm = r_str_newf (name, buf[0] & mask);
			} else {
				disasm = r_str_new (name);
			}
			break;
		case 2:
			if (len>1) {
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
					val2 = buf[1];
				} else if ((arg2 == A_RI) || (arg2 == A_RN)) {
					// op arg, @Ri; op arg, Rn
					disasm = r_str_newf (name, buf[1], buf[0] & mask);
					val1 = buf[1];
				} else if (arg1 == A_BIT) {
					// bit addressing mode
					disasm = r_str_newf (name, arg_bit (buf[1]), buf[1] & 0x07);
					val1 = buf[1];
				} else {
					// direct, immediate, bit
					disasm = r_str_newf (name, buf[1]);
					val1 = buf[1];
				}
			} else {
				strcpy (op->buf_asm, "truncated");
				return -1;
			}
			break;
		case 3:
			if (len > 2) {
				if ((arg1 == A_ADDR16) || (arg1 == A_IMM16)) {
					disasm = r_str_newf (name, 0x100 * buf[1] + buf[2]);
				} else if (arg1 == A_IMM16) {
					disasm = r_str_newf (name, 0x100 * buf[1] + buf[2]);
				} else if (arg2 == A_OFFSET) {
					if (mask != A_NONE) {
						// @Ri, immediate, offset; Rn, immediate, offset
						disasm = r_str_newf (name, buf[0] & mask, buf[1], arg_offset (pc + 3, buf[1]));
					} else if (arg1 == A_BIT) {
						// bit, offset
						disasm = r_str_newf (name, arg_bit (buf[1]), buf[1] & 0x07, arg_offset (pc + 3, buf[2]));
						val1 = buf[1];
					} else {
						// direct, offset; a, immediate, offset
						disasm = r_str_newf (name, buf[1], arg_offset (pc + 3, buf[2]));
						val1 = buf[1];
					}
				} else if (arg3 == A_OFFSET) {
					// @Ri/Rn, direct, offset
					disasm = r_str_newf (name, buf[0] & mask, buf[1], arg_offset (pc + 3, buf[2]));
					val2 = buf[1];
				} else if (arg1 == A_DIRECT && arg2 == A_DIRECT) {
					// op direct, direct has src and dest swapped
					disasm = r_str_newf (name, buf[2], buf[1]);
					val1 = buf[2];
					val2 = buf[1];
				} else {
					// direct, immediate
					disasm = r_str_newf (name, buf[1], buf[2]);
					val1 = buf[1];
				}
			} else {
				strcpy (op->buf_asm, "truncated");
				return -1;
			}
			break;
		default:
			// if we get here something is wrong
			return 0;
		}

		// substitute direct addresses with register name
		if (disasm) {
			disasm = _replace_register (disasm, arg1, val1);
			disasm = _replace_register (disasm, arg2, val2);
			r_str_ncpy (op->buf_asm, disasm, sizeof (op->buf_asm));
			free (disasm);
		}
		return oplen;
	}

	// invalid op-code
	return 0;
}
