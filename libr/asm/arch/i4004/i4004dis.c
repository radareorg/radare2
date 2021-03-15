/* radare - LGPL - Copyright 2014-2018 - condret, pancake */

#include <r_asm.h>
#include <r_types.h>
#include <string.h>
#include <stdio.h>

/* That 3 is a hack */
static const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
};

static const char *i4004_e[16] = {
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

static const char *i4004_f[16] = {
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

static int i4004_get_ins_len(ut8 hex) {
	ut8 high = (hex & 0xf0) >> 4;
	int ret = i4004_ins_len[high];
	if (ret == 3)
		ret = (hex & 1) ? 1 : 2;
	return ret;
}

static int i4004dis(RAsmOp *op, const ut8 *buf, int len) {
	int rlen = i4004_get_ins_len (*buf);
	ut8 high = (*buf & 0xf0) >> 4;
	ut8 low = (*buf & 0xf);
	const char *buf_asm = "invalid";
	if (rlen > len)	{
		return op->size = 0;
	}
	switch (high) {
	case 0: buf_asm = low? "invalid": "nop"; break;
	case 1: buf_asm = sdb_fmt ("jcn %d 0x%02x", low, buf[1]); break;
	case 2:
		if (rlen == 1) {
			buf_asm = sdb_fmt ("src r%d", (low & 0xe));
		} else {
			buf_asm = sdb_fmt ("fim r%d, 0x%02x", (low & 0xe), buf[1]);
		}
		break;
	case 3:
		if ((low & 1) == 1) {
			buf_asm = sdb_fmt ("jin r%d", (low & 0xe));
		} else {
			buf_asm = sdb_fmt ("fin r%d", (low & 0xe));
		}
		break;
	case 4: buf_asm = sdb_fmt ("jun 0x%03x", ((ut16)(low<<8) | buf[1])); break;
	case 5: buf_asm = sdb_fmt ("jms 0x%03x", ((ut16)(low<<8) | buf[1])); break;
	case 6: buf_asm = sdb_fmt ("inc r%d", low); break;
	case 7: buf_asm = sdb_fmt ("isz r%d, 0x%02x", low, buf[1]); break;
	case 8: buf_asm = sdb_fmt ("add r%d", low); break;
	case 9: buf_asm = sdb_fmt ("sub r%d", low); break;
	case 10: buf_asm = sdb_fmt ("ld r%d", low); break;
	case 11: buf_asm = sdb_fmt ("xch r%d", low); break;
	case 12: buf_asm = sdb_fmt ("bbl %d", low); break;
	case 13: buf_asm = sdb_fmt ("ldm %d", low); break;
	case 14: buf_asm = i4004_e[low]; break;
	case 15: buf_asm = i4004_f[low]; break;
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
	return op->size = rlen;
}
