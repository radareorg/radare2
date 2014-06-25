/* radare - LGPL - Copyright 2013-2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <stdio.h>
#include <string.h>
#include "gb_op_table.h"

static int gbOpLength(int gboptype){
	switch(gboptype) {
	case GB_8BIT:
		return 1;
	case GB_8BIT+ARG_8+GB_IO:
	case GB_8BIT+ARG_8:
	case GB_16BIT:
		return 2;
	case GB_8BIT+ARG_16:
		return 3;
	}
	return 0;
}

#ifndef GB_DIS_LEN_ONLY
static int gbDisass(RAsmOp *op, const ut8 *buf, int len){
	int foo = gbOpLength (gb_op[buf[0]].type);
	if (len<foo)
		return 0;
	switch (gb_op[buf[0]].type) {
	case GB_8BIT:
		sprintf (op->buf_asm, "%s", gb_op[buf[0]].name);
		break;
	case GB_16BIT:
		sprintf (op->buf_asm, "%s %s", cb_ops[buf[1]>>3], cb_regs[buf[1]&7]);
		break;
	case GB_8BIT+ARG_8:
		sprintf (op->buf_asm, gb_op[buf[0]].name, buf[1]);
		break;
	case GB_8BIT+ARG_16:
		sprintf (op->buf_asm, gb_op[buf[0]].name, buf[1]+0x100*buf[2]);
		break;
	case GB_8BIT+ARG_8+GB_IO:
		sprintf (op->buf_asm, gb_op[buf[0]].name, 0xff00+buf[1]);
		break;
	}
	return foo;
}
#endif
