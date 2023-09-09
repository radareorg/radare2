/* radare - LGPL - Copyright 2015-2016 - pancake, condret, riq, qnix */

#include <r_anal.h>
#include <r_lib.h>
#include <string.h>
#include "../snes/snesdis.c"

static struct {
	ut8 op;
	char *name;
	size_t len;
} ops[] = {
	{0x00, "brk", 1},
	{0x0b, "anc #0x%02x", 2},
	{0x2b, "anc #0x%02x", 2},
	{0x8b, "ane #0x%02x", 2},
	{0x6b, "arr #0x%02x", 2},
	{0x4b, "asr #0x%02x", 2},
	{0xc7, "dcp 0x%02x", 2},
	{0xd7, "dcp 0x%02x, x", 2},
	{0xcf, "dcp 0x%04x", 3},
	{0xdf, "dcp 0x%04x, x", 3},
	{0xdb, "dcp 0x%04x, y", 3},
	{0xc3, "dcp (0x%02x, x)", 2},
	{0xd3, "dcp (0x%02x), y", 2},
	{0xe7, "isb 0x%02x", 2},
	{0xf7, "isb 0x%02x, x", 2},
	{0xef, "isb 0x%04x", 3},
	{0xff, "isb 0x%04x, x", 3},
	{0xfb, "isb 0x%04x, y", 3},
	{0xe3, "isb (0x%02x, x)", 2},
	{0xf3, "isb (0x%02x), y", 2},
	{0x02, "hlt", 1},
	{0x12, "hlt", 1},
	{0x22, "hlt", 1},
	{0x32, "hlt", 1},
	{0x42, "hlt", 1},
	{0x52, "hlt", 1},
	{0x62, "hlt", 1},
	{0x72, "hlt", 1},
	{0x92, "hlt", 1},
	{0xb2, "hlt", 1},
	{0xd2, "hlt", 1},
	{0xf2, "hlt", 1},
	{0xbb, "lae 0x%04x, y", 3},
	{0xa7, "lax 0x%02x", 2},
	{0xb7, "lax 0x%02x, y", 2},
	{0xaf, "lax 0x%04x", 3},
	{0xbf, "lax 0x%04x, y", 3},
	{0xa3, "lax (0x%02x, x)", 2},
	{0xb3, "lax (0x%02x), y", 2},
	{0xab, "lxa #0x%02x", 2},
	{0xea, "nop", 1},
	{0x1a, "nop", 1},
	{0x3a, "nop", 1},
	{0x5a, "nop", 1},
	{0x7a, "nop", 1},
	{0xda, "nop", 1},
	{0xfa, "nop", 1},
	{0x80, "nop #0x%02x", 2},
	{0x82, "nop #0x%02x", 2},
	{0x89, "nop #0x%02x", 2},
	{0xc2, "nop #0x%02x", 2},
	{0xe2, "nop #0x%02x", 2},
	{0x04, "nop 0x%02x", 2},
	{0x44, "nop 0x%02x", 2},
	{0x64, "nop 0x%02x", 2},
	{0x14, "nop 0x%02x, x", 2},
	{0x34, "nop 0x%02x, x", 2},
	{0x54, "nop 0x%02x, x", 2},
	{0x74, "nop 0x%02x, x", 2},
	{0xd4, "nop 0x%02x, x", 2},
	{0xf4, "nop 0x%02x, x", 2},
	{0x0c, "nop 0x%04x", 3},
	{0x1c, "nop 0x%04x, x", 3},
	{0x3c, "nop 0x%04x, x", 3},
	{0x5c, "nop 0x%04x, x", 3},
	{0x7c, "nop 0x%04x, x", 3},
	{0xdc, "nop 0x%04x, x", 3},
	{0xfc, "nop 0x%04x, x", 3},
	{0x27, "rla 0x%02x", 2},
	{0x37, "rla 0x%02x, x", 2},
	{0x2f, "rla 0x%04x", 3},
	{0x3f, "rla 0x%04x, x", 3},
	{0x3b, "rla 0x%04x, y", 3},
	{0x23, "rla (0x%02x, x)", 2},
	{0x33, "rla (0x%02x), y", 2},
	{0x67, "rra 0x%02x", 2},
	{0x77, "rra 0x%02x, x", 2},
	{0x6f, "rra 0x%04x", 3},
	{0x7f, "rra 0x%04x, x", 3},
	{0x7b, "rra 0x%04x, y", 3},
	{0x63, "rra (0x%02x, x)", 2},
	{0x73, "rra (0x%02x), y", 2},
	{0x87, "sax 0x%02x", 2},
	{0x97, "sax 0x%02x, y", 2},
	{0x8f, "sax 0x%04x", 3},
	{0x83, "sax (0x%02x, x)", 2},
	{0xe9, "sbc #0x%02x", 2},
	{0xe5, "sbc 0x%02x", 2},
	{0xf5, "sbc 0x%02x, x", 2},
	{0xed, "sbc 0x%04x", 3},
	{0xfd, "sbc 0x%04x, x", 3},
	{0xf9, "sbc 0x%04x, y", 3},
	{0xe1, "sbc (0x%02x, x)", 2},
	{0xf1, "sbc (0x%02x), y", 2},
	{0xeb, "sbc #0x%02x", 2},
	//{0xef, "sbc 0x%06x", 4},
	//{0xff, "sbc 0x%06x, x", 4},
	//{0xf2, "sbc (0x%02x)", 2},
	//{0xe7, "sbc [0x%02x]", 2},
	//{0xf7, "sbc [0x%02x], y", 2},
	//{0xe3, "sbc 0x%02x, s", 2},
	//{0xf3, "sbc (0x%02x, s),y", 2},
	{0xcb, "sbx 0x%02x", 2},
	{0x93, "sha 0x%04x, x", 3},
	{0x9f, "sha 0x%04x, y", 3},
	{0x9b, "shs 0x%04x, y", 3},
	{0x9e, "shx 0x%04x, y", 3},
	{0x9c, "shy 0x%04x, x", 3},
	{0x07, "slo 0x%02x", 2},
	{0x17, "slo 0x%02x, x", 2},
	{0x0f, "slo 0x%04x", 3},
	{0x1f, "slo 0x%04x, x", 3},
	{0x1b, "slo 0x%04x, y", 3},
	{0x03, "slo (0x%02x, x)", 2},
	{0x13, "slo (0x%02x), y", 2},
	{0x47, "sre 0x%02x", 2},
	{0x57, "sre 0x%02x, x", 2},
	{0x4f, "sre 0x%04x", 3},
	{0x5f, "sre 0x%04x, x", 3},
	{0x5b, "sre 0x%04x, y", 3},
	{0x43, "sre (0x%02x, x)", 2},
	{0x53, "sre (0x%02x), y", 2},
	{-1, NULL, 0}};

static int _6502Disass(ut64 pc, RAnalOp *op, const ut8 *buf, ut64 len) {
	int i;
	for (i = 0; ops[i].name; i++) {
		if (ops[i].op == buf[0]) {
			op->mnemonic = strdup ("invalid");
			int oplen = ops[i].len;
			if (oplen > len) {
				return 0;
			}
			switch (ops[i].len) {
			case 1:
				op->mnemonic = strdup (ops[i].name);
				break;
			case 2:
				if (len > 1) {
					op->mnemonic = r_str_newf (ops[i].name, buf[1]);
				} else {
					op->mnemonic = strdup ("truncated");
					len = -1;
				}
				break;
			case 3:
				if (len > 2) {
					op->mnemonic = r_str_newf (ops[i].name, buf[1] + 0x100 * buf[2]);
				} else {
					op->mnemonic = strdup ("truncated");
					len = -1;
				}
				break;
			case 4:
				if (len > 3) {
					op->mnemonic = r_str_newf (ops[i].name, buf[1]+0x100*buf[2]+0x10000*buf[3]);
				} else {
					op->mnemonic = strdup ("truncated");
					len = -1;
				}
				break;
			default:
				goto beach;
			}
			return oplen;
		}
	}
beach:
	return snesDisass (1, 1, pc, op, buf, len);
}
