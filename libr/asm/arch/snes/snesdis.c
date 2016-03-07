/* radare - LGPL - Copyright 2015 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>
#include "snes_op_table.h"

static int snesDisass(int bits, RAsmOp *op, const ut8 *buf, int len){
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = s_op->len;
	if (op_len == SNES_OP_IMM)
		op_len = bits == 8 ? SNES_OP_16BIT : SNES_OP_24BIT;
	if (len < op_len)
		return 0;
	switch (s_op->len) {
	case SNES_OP_8BIT:
		strcpy (op->buf_asm, s_op->name);
		break;
	case SNES_OP_16BIT:
		sprintf (op->buf_asm, s_op->name, buf[1]);
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			sprintf (op->buf_asm, s_op->name, buf[1], buf[2]);
		} else {
			sprintf (op->buf_asm, s_op->name, ut8p_bw(buf+1));
		}
		break;
	case SNES_OP_32BIT:
		sprintf (op->buf_asm, s_op->name, buf[1]|buf[2]<<8|buf[3]<<16);
		break;
	case SNES_OP_IMM:
		if (bits == 8) {
			sprintf (op->buf_asm, "%s #0x%02x", s_op->name, buf[1]);
		} else {
			sprintf (op->buf_asm, "%s #0x%04x", s_op->name,
				ut8p_bw(buf+1));
		}
		break;
	}
	return op_len;
}
