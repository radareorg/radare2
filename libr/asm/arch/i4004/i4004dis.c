/* radare - LGPL - Copyright 2014 - condret@runas-racer.com */

#include <r_asm.h>
#include <r_types.h>
#include <string.h>
#include <stdio.h>

/* That 3 is a hack */
const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
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
	ut8 high = (hex & 0xf0)>>4;
	int ret = i4004_ins_len[high];
	if (ret == 3)
		ret = (hex & 1) ? 1 : 2;
	return ret;
}

static int i4004dis (RAsmOp *op, const ut8 *buf, int len) {
	const size_t basz = sizeof (op->buf_asm)-1;
	char *basm = op->buf_asm;
	int rlen = i4004_get_ins_len (*buf);
	ut8 high = (*buf & 0xf0)>>4;
	ut8 low = (*buf & 0xf);

	if (rlen > len)	return op->size = 0;
	switch (high) {
		case 0: strcpy (basm, low? "invalid": "nop"); break;
		case 1: snprintf (basm, basz, "jcn %d 0x%02x", low, buf[1]); break;
		case 2:
			if (rlen == 1)
				snprintf (basm, basz, "scr r%d", (low & 0xe));
			else	snprintf (basm, basz, "fim r%d, 0x%02x", (low & 0xe), buf[1]);
			break;
		case 3: snprintf (basm, basz, "fin r%d", (low & 0xe)); break;
		case 4: snprintf (basm, basz, "jun %03x", ((ut16)(low<<8) | buf[1])); break;
		case 5: snprintf (basm, basz, "jms %03x", ((ut16)(low<<8) | buf[1])); break;
		case 6: snprintf (basm, basz, "inc r%d", low); break;
		case 7: snprintf (basm, basz, "isz r%d, 0x%02x", low, buf[1]); break;
		case 8: snprintf (basm, basz, "add r%d", low); break;
		case 9: snprintf (basm, basz, "sub r%d", low); break;
		case 10: snprintf (basm, basz, "ld r%d", low); break;
		case 11: snprintf (basm, basz, "xch r%d", low); break;
		case 12: snprintf (basm, basz, "bbl %d", low); break;
		case 13: snprintf (basm, basz, "ldm %d", low); break;
		case 14: strcpy (basm, i4004_e[low]); break;
		case 15: strcpy (basm, i4004_f[low]); break;
	}
	return op->size = rlen;
}
