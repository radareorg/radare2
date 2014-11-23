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

static int i4004_get_ins_len (ut8 hex) {
	int ret;
	ut8 high = (hex & 0xf0)>>4;
	ret = i4004_ins_len[high];
	if (ret == 3)
		ret = (hex & 1) ? 1 : 2;
	return ret;
}

static int i4004dis (RAsmOp *op, const ut8 *buf, int len) {
	int rlen = i4004_get_ins_len (*buf);
	ut8 low = (*buf & 0xf);
	ut8 high = (*buf & 0xf0)>>4;
	char *buf_asm = op->buf_asm;
	size_t buf_asm_size = sizeof(op->buf_asm)-1;

	if (rlen > len)	return op->size = 0;
	switch (high) {
		case 0:
			if (low) strcpy (op->buf_asm, "invalid");
			else strcpy (op->buf_asm, "nop");
			break;
		case 1:
			snprintf (buf_asm, buf_asm_size, "jcn %d 0x%02x", low, buf[1]);
			break;
		case 2:
			if (rlen == 1)
				snprintf (buf_asm, buf_asm_size, "scr r%d", (low & 0xe));
			else	snprintf (buf_asm, buf_asm_size, "fim r%d, 0x%02x", (low & 0xe), buf[1]);
			break;
		case 3:
			snprintf (buf_asm, buf_asm_size, "fin r%d", (low & 0xe));
			break;
		case 4:
			snprintf (buf_asm, buf_asm_size, "jun %03x", ((ut16)(low<<8) | buf[1]));
			break;
		case 5:
			snprintf (buf_asm, buf_asm_size, "jms %03x", ((ut16)(low<<8) | buf[1]));
			break;
		case 6:
			snprintf (buf_asm, buf_asm_size, "inc r%d", low);
			break;
		case 7:
			snprintf (buf_asm, buf_asm_size, "isz r%d, 0x%02x", low, buf[1]);
			break;
		case 8:
			snprintf (buf_asm, buf_asm_size, "add r%d", low);
			break;
		case 9:
			snprintf (buf_asm, buf_asm_size, "sub r%d", low);
			break;
		case 10:
			snprintf (buf_asm, buf_asm_size, "ld r%d", low);
			break;
		case 11:
			snprintf (buf_asm, buf_asm_size, "xch r%d", low);
			break;
		case 12:
			snprintf (buf_asm, buf_asm_size, "bbl %d", low);
			break;
		case 13:
			snprintf (buf_asm, buf_asm_size, "ldm %d", low);
			break;
		case 14:
			strcpy (op->buf_asm, i4004_e[low]);
			break;
		case 15:
			strcpy (op->buf_asm, i4004_f[low]);
			break;
	}
	return op->size = rlen;
}
