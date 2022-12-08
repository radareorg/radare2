/* radare - LGPL - Copyright 2015-2018 - condret, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>
#include <r_lib.h>
#include <string.h>
#include "optable.h"

static int snesDisass(int M_flag, int X_flag, ut64 pc, RAnalOp *op, const ut8 *buf, int len) {
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = snes_op_get_size (M_flag, X_flag, s_op);
	if (len < op_len) {
		return 0;
	}
	switch (s_op->flags) {
	case SNES_OP_8BIT:
		op->mnemonic = r_str_newf ("%s", s_op->name);
		break;
	case SNES_OP_16BIT:
		if (*buf % 0x20 == 0x10 || *buf == 0x80) { // relative branch
			op->mnemonic = r_str_newf (s_op->name, (ut32)(pc + 2 + (st8)buf[1]));
		} else {
			op->mnemonic = r_str_newf (s_op->name, buf[1]);
		}
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			op->mnemonic = r_str_newf (s_op->name, buf[1], buf[2]);
		} else if (*buf == 0x82) { // brl
			op->mnemonic = r_str_newf (s_op->name, pc + 3 + (st16)ut8p_bw(buf + 1));
		} else {
			op->mnemonic = r_str_newf (s_op->name, ut8p_bw (buf + 1));
		}
		break;
	case SNES_OP_32BIT:
		op->mnemonic = r_str_newf (s_op->name, buf[1]|buf[2]<<8|buf[3]<<16);
		break;
	case SNES_OP_IMM_M:
		if (M_flag) {
			op->mnemonic = r_str_newf ("%s #0x%02x", s_op->name, buf[1]);
		} else {
			op->mnemonic = r_str_newf ("%s #0x%04x", s_op->name, ut8p_bw (buf + 1));
		}
		break;
	case SNES_OP_IMM_X:
		if (X_flag) {
			op->mnemonic = r_str_newf ("%s #0x%02x", s_op->name, buf[1]);
		} else {
			op->mnemonic = r_str_newf ("%s #0x%04x", s_op->name, ut8p_bw (buf + 1));
		}
		break;
	}
	return op_len;
}
