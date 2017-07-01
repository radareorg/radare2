/* radare - LGPL - Copyright 2015-2017 - pancake, condret, riq, qnix, astuder */

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "8051_ops.h"
#include "8051_disas.h"

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
		switch (oplen) {
		case 1:
			if ((arg1 == A_RI) || (arg1 == A_RN)) {
				// op @Ri; op Rn
				sprintf (op->buf_asm, name, buf[0] & mask);
			} else {
				sprintf (op->buf_asm, "%s", name);
			}
			break;
		case 2:
			if (len>1) {
				if (arg1 == A_OFFSET) {
					sprintf (op->buf_asm, name, arg_offset (pc + 2, buf[1]));
				} else if (arg1 == A_ADDR11) {
					sprintf (op->buf_asm, name, arg_addr11 (pc + 2, buf));
				} else if ((arg1 == A_RI) || (arg1 == A_RN)) {
					// op @Ri, arg; op Rn, arg
					if (arg2 == A_OFFSET) {
						sprintf (op->buf_asm, name, buf[0] & mask, arg_offset (pc + 2, buf[1]));
					} else {
						sprintf (op->buf_asm, name, buf[0] & mask, buf[1]);
					}
				} else if ((arg2 == A_RI) || (arg2 == A_RN)) {
					// op arg, @Ri; op arg, Rn
					sprintf (op->buf_asm, name, buf[1], buf[0] & mask);
				} else if (arg1 == A_BIT) {
					// bit addressing mode
					sprintf (op->buf_asm, name, arg_bit (buf[1]), buf[1] & 0x07);
				} else {
					// direct, immediate, bit
					sprintf (op->buf_asm, name, buf[1]);
				}
			} else {
				strcpy (op->buf_asm, "truncated");
				return -1;
			}
			break;
		case 3:
			if (len>2) {
				if ((arg1 == A_ADDR16) || (arg1 == A_IMM16)) {
					sprintf (op->buf_asm, name, 0x100 * buf[1] + buf[2]);
				} else if (arg1 == A_IMM16) {
					sprintf (op->buf_asm, name, 0x100 * buf[1] + buf[2]);
				} else if (arg2 == A_OFFSET) {
					if (mask != A_NONE) {
						// @Ri, immediate, offset; Rn, immediate, offset
						sprintf (op->buf_asm, name, buf[0] & mask, buf[1], arg_offset (pc + 3, buf[1]));
					} else if (arg1 == A_BIT) {
						// bit, offset
						sprintf (op->buf_asm, name, arg_bit (buf[1]), buf[1] & 0x07, arg_offset (pc + 3, buf[2]));
					} else {
						// direct, offset; a, immediate, offset
						sprintf (op->buf_asm, name, buf[1], arg_offset (pc + 3, buf[2]));
					}
				} else if (arg3 == A_OFFSET) {
					// @Ri/Rn, direct, offset
					sprintf (op->buf_asm, name, buf[0] & mask, buf[1], arg_offset (pc + 3, buf[2]));
				} else if (arg1 == A_DIRECT && arg2 == A_DIRECT) {
					// op direct, direct has src and dest swapped
					sprintf (op->buf_asm, name, buf[2], buf[1]);
				} else {
					// direct, immediate
					sprintf (op->buf_asm, name, buf[1], buf[2]);
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
		return oplen;
	}

	// invalid op-code
	return 0;
}
