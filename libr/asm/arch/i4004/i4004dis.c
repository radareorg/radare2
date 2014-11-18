/* radare - LGPL - Copyright 2014 - condret@runas-racer.com */
#include <r_asm.h>
#include <r_types.h>
#include <string.h>
#include <stdio.h>

const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1			//That 3 is a hack
};

const char *i4004_e[16] = {
	"wrm",
	"wmp",
	"wrr",
	"wpm",
	"wr0",
	"wr1",
	"wr2",
	"wr3",
	"sbm",
	"rdm",
	"rdr",
	"adm",
	"rd0",
	"rd1",
	"rd2",
	"rd3"
};

const char *i4004_f[16] = {
	"clb",
	"clc",
	"iac",
	"cmc",
	"cma",
	"ral",
	"rar",
	"tcc",
	"dac",
	"tcs",
	"stc",
	"daa",
	"kbp",
	"dcl",
	"invalid",
	"invalid"
};






static int i4004_get_ins_len (ut8 hex)
{
	int ret;
	ut8 high = (hex & 0xf0)>>4;
	ret = i4004_ins_len[high];
	if (ret == 3)
		ret = (hex & 1) ? 1 : 2;
	return ret;
}

static int i4004dis (RAsmOp *op, const ut8 *buf, int len)
{
	int rlen = i4004_get_ins_len (*buf);
	ut8 low = (*buf & 0xf), high = (*buf & 0xf0)>>4;
	if (rlen > len)	return op->size = 0;
	switch (high) {
		case 0:
			if (low)
				sprintf (op->buf_asm, "invalid");
			else	sprintf (op->buf_asm, "nop");
			break;
		case 1:
			sprintf (op->buf_asm, "jcn %d 0x%02x", low, buf[1]);
			break;
		case 2:
			if (rlen == 1)
				sprintf (op->buf_asm, "scr r%d", (low & 0xe));
			else	sprintf (op->buf_asm, "fim r%d, 0x%02x", (low & 0xe), buf[1]);
			break;
		case 3:
			sprintf (op->buf_asm, "fin r%d", (low & 0xe));
			break;
		case 4:
			sprintf (op->buf_asm, "jun %03x", ((ut16)(low<<8) | buf[1]));
			break;
		case 5:
			sprintf (op->buf_asm, "jms %03x", ((ut16)(low<<8) | buf[1]));
			break;
		case 6:
			sprintf (op->buf_asm, "inc r%d", low);
			break;
		case 7:
			sprintf (op->buf_asm, "isz r%d, 0x%02x", low, buf[1]);
			break;
		case 8:
			sprintf (op->buf_asm, "add r%d", low);
			break;
		case 9:
			sprintf (op->buf_asm, "sub r%d", low);
			break;
		case 10:
			sprintf (op->buf_asm, "ld r%d", low);
			break;
		case 11:
			sprintf (op->buf_asm, "xch r%d", low);
			break;
		case 12:
			sprintf (op->buf_asm, "bbl %d", low);
			break;
		case 13:
			sprintf (op->buf_asm, "ldm %d", low);
			break;
		case 14:
			sprintf (op->buf_asm, i4004_e[low]);
			break;
		case 15:
			sprintf (op->buf_asm, i4004_f[low]);
			break;
	}
	return op->size = rlen;
}
