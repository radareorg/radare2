/* radare - LGPL3 - Copyright 2021 - condret, slowhand99 */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

static const int jdh_len[16] = {
	2, 3, 3, 1, 1, 3, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2
};

static const char reg[6] = { 'A', 'B', 'C', 'D', 'L', 'H' };

static int jdh_get_ins_len(ut8 hex) {
	ut8 high = (hex & 0xf0) >> 4;
	int ret = jdh_len[high];
	if (ret == 3) {
		ret = (hex & 8) ? 2 : 3;
	}
	else if (ret == 1) {
		ret = (hex & 8) ? 1 : 2;
	}
	return ret;
}

static int jdh8Disass(RAsmOp *op, const ut8 *buf, int len) {
	int ilen = jdh_get_ins_len (*buf);
	const ut8 high = (*buf & 0xf0) >> 4;
	const ut8 low = (*buf & 0xf);
	const char *buf_asm = "invalid";
	if (rlen > len) {
		return op->size = 0;
	}
	switch (high) {
	case 0:
		buf_asm = (low & 8)? snprintf (buf, sizeof (buf), "mw %c, %c", reg[low & 7], reg[buf[1]]):
			snprintf (buf, sizeof (buf), "mw %c, 0x%02x", reg[low & 7], buf[1]);
		break;
	case 1:
		if (rlen == 2) {
			buf_asm = snprintf (buf, sizeof (buf), "lw %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "lw %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 2:
		if (rlen == 2) {
			buf_asm = snprintf (buf, sizeof (buf), "sw %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "sw 0x%04x, %c", ((ut16)(buf[1] << 8) | buf[2]), reg[low & 7]);
		}
		break;
	case 3:
		if (rlen == 1) {
			buf_asm = snprintf (buf, sizeof (buf), "push %c", reg[low & 7]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "push 0x%02x", buf[1]);
		}
		break;
	case 4:
		buf_asm = snprintf (buf, sizeof (buf), "pop %c", reg[low & 7]);
		break;
	case 5:
		buf_asm = snprintf (buf, sizeof (buf), "lda 0x%03x", ((ut16)(buf[1] << 8) | buf[2]));
		break;
	case 6:
		if (rlen == 1) {
			buf_asm = snprintf (buf, sizeof (buf), "jnz %c", reg[low & 7]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "jnz 0x%02x", buf[1]);
		}
		break;
	case 7:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "inb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "inb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 8:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "outb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "outb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 9:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "add %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "add %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 10:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "adc %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "adc %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 11:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "and %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "and %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 12:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "or %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "or %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 13:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "nor %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "nor %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 14:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "cmp %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "cmp %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 15:
		if (low & 8) {
			buf_asm = snprintf (buf, sizeof (buf), "sbb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			buf_asm = snprintf (buf, sizeof (buf), "sbb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	default:
		break;
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
	return op->size = rlen;
}
