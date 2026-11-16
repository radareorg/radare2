/* radare - LGPL - Copyright 2013-2023 - condret, pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "gb_op_table.h"

static int gbOpLength(int gboptype) {
	switch (gboptype) {
	case GB_8BIT:
		return 1;
	case GB_8BIT + ARG_8 + GB_IO:
	case GB_8BIT + ARG_8:
	case GB_16BIT:
		return 2;
	case GB_8BIT + ARG_16:
		return 3;
	default:
		return 0;
	}
}

static void gbDisass(RAnalOp *op, const ut8 *buf) {
	switch (gb_op[buf[0]].type) {
	case GB_8BIT:
		op->mnemonic = r_str_newf ("%s", gb_op[buf[0]].name);
		break;
	case GB_16BIT:
		op->mnemonic = r_str_newf ("%s %s", cb_ops[buf[1] >> 3u], cb_regs[buf[1] & 7u]);
		break;
	case GB_8BIT + ARG_8:
		op->mnemonic = r_str_newf (gb_op[buf[0]].name, buf[1]);
		break;
	case GB_8BIT + ARG_16:
		op->mnemonic = r_str_newf (gb_op[buf[0]].name, buf[1] + 0x100 * buf[2]);
		break;
	case GB_8BIT + ARG_8 + GB_IO:
		{
			char address[8];
			const char *reg = gb_io_regs[buf[1]];
			if (!reg) {
				snprintf (address, sizeof (address), "0xff%02x", buf[1]);
				reg = address;
			}
			op->mnemonic = r_str_newf (gb_op[buf[0]].name, reg);
		}
		break;
	default:
		op->mnemonic = strdup ("invalid");
	}
}
