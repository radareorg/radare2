/* radare - LGPL - Copyright 2013-2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>
#include "snes_op_table.h"

static int snesDisass(RAsmOp *op, const ut8 *buf, int len){
	if (len<snes_op[buf[0]].len)
		return 0;
	switch (snes_op[buf[0]].len) {
		case SNES_OP_8BIT:
			sprintf(op->buf_asm,"%s",snes_op[buf[0]].name);
			break;
		case SNES_OP_16BIT:
			sprintf(op->buf_asm,snes_op[buf[0]].name,buf[1]);
			break;
		case SNES_OP_24BIT:
			if(*buf==0x44 || *buf==0x54){
				sprintf (op->buf_asm, snes_op[buf[0]].name,
					buf[1], buf[2]);
			} else {
				sprintf (op->buf_asm, snes_op[buf[0]].name,
					buf[1]+0x100*buf[2]);
			}
			break;
		case SNES_OP_32BIT:
			sprintf (op->buf_asm, snes_op[buf[0]].name,
				buf[1]+0x100*buf[2]+0x10000*buf[3]);
			break;
	}
	return snes_op[buf[0]].len;
}
