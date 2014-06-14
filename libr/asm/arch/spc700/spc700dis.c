/* radare - LGPL - Copyright 2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_asm.h>
#include <stdio.h>
#include <string.h>
#include "spc700_opcode_table.h"

static int spc700OpLength(int spcoptype){
	switch(spcoptype) {
	case SPC_OP:
		return 1;
	case SPC_ARG8_1:
		return 2;
	case SPC_ARG8_2:
	case SPC_ARG16:
		return 3;
	}
	return 0;
}

static int spc700Disass(RAsmOp *op, const ut8 *buf, int len) {
	int foo = spc700OpLength (spc_op_table[buf[0]].type);
	if (len < foo)
		return 0;
	switch (spc_op_table[buf[0]].type) {
	case SPC_OP:
		sprintf (op->buf_asm, "%s", spc_op_table[buf[0]].name);
		break;
	case SPC_ARG8_1:
		sprintf (op->buf_asm, spc_op_table[buf[0]].name, buf[1]);
		break;
	case SPC_ARG8_2:
		sprintf (op->buf_asm, spc_op_table[buf[0]].name, buf[1], buf[2]);
		break;
	case SPC_ARG16:
		sprintf (op->buf_asm, spc_op_table[buf[0]].name, buf[1]+0x100*buf[2]);
		break;
	}
	return foo;
}
