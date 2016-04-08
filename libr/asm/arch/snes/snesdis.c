/* radare - LGPL - Copyright 2015-2016 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>
#include "snes_op_table.h"

static int snesDisass(int bits, ut64 pc, RAsmOp *op, const ut8 *buf, int len){
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = snes_op_get_size(bits, s_op);
	if (len < op_len)
		return 0;
	switch (s_op->len) {
	case SNES_OP_8BIT:
		strncpy (op->buf_asm, s_op->name, sizeof (op->buf_asm) - 1);
		break;
	case SNES_OP_16BIT:
		if (*buf % 0x20 == 0x10 || *buf == 0x80) { // relative branch
			snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, pc + 2 + (st8)buf[1]);
		} else {
			snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, buf[1]);
		}
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, buf[1], buf[2]);
		} else if (*buf == 0x82) { // brl
			snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, pc + 3 + (st16)ut8p_bw(buf+1));
		} else {
			snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, ut8p_bw(buf+1));
		}
		break;
	case SNES_OP_32BIT:
		snprintf (op->buf_asm, sizeof (op->buf_asm), s_op->name, buf[1]|buf[2]<<8|buf[3]<<16);
		break;
	case SNES_OP_IMM:
		if (bits == 8) {
			snprintf (op->buf_asm, sizeof (op->buf_asm), "%s #0x%02x",
				s_op->name, buf[1]);
		} else {
			snprintf (op->buf_asm, sizeof (op->buf_asm), "%s #0x%04x",
				s_op->name, ut8p_bw (buf+1));
		}
		break;
	}
	return op_len;
}
