/* radare - LGPL3 - Copyright 2021-2022 - condret, slowhand99 */

#include <r_util.h>

static const int jdh_len[16] = {
	2, 3, 3, 1, 1, 3, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2
};

static const char reg[6] = { 'A', 'B', 'C', 'D', 'L', 'H' };

static int jdh_get_ins_len(ut8 hex) {
	ut8 high = (hex & 0xf0) >> 4;
	int ret = jdh_len[high];
	if (ret == 3) {
		ret = (hex & 8) ? 2 : 3;
	} else if (ret == 1) {
		ret = (hex & 8) ? 1 : 2;
	}
	return ret;
}

static char *jdh8Disass(const ut8 *buf, int len, int *dlen) {
	char *dis = NULL;
	int ilen = jdh_get_ins_len (*buf);
	const ut8 high = (*buf & 0xf0) >> 4;
	const ut8 low = (*buf & 0xf);
	if (ilen > len) {
		ilen = 0;
	} else switch (high) {
	case 0:
		if (low & 8) {
			dis = r_str_newf ("mw %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("mw %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 1:
		if (ilen == 2) {
			dis = r_str_newf ("lw %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("lw %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 2:
		if (ilen == 2) {
			dis = r_str_newf ("sw %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("sw 0x%04x, %c", ((ut16)(buf[1] << 8) | buf[2]), reg[low & 7]);
		}
		break;
	case 3:
		if (ilen == 1) {
			dis = r_str_newf ("push %c", reg[low & 7]);
		} else {
			dis = r_str_newf ("push 0x%02x", buf[1]);
		}
		break;
	case 4:
		dis = r_str_newf ("pop %c", reg[low & 7]);
		break;
	case 5:
		dis = r_str_newf ("lda 0x%03x", ((ut16)(buf[1] << 8) | buf[2]));
		break;
	case 6:
		if (ilen == 1) {
			dis = r_str_newf ("jnz %c", reg[low & 7]);
		} else {
			dis = r_str_newf ("jnz 0x%02x", buf[1]);
		}
		break;
	case 7:
		if (low & 8) {
			dis = r_str_newf ("inb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("inb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 8:
		if (low & 8) {
			dis = r_str_newf ("outb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("outb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 9:
		if (low & 8) {
			dis = r_str_newf ("add %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("add %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 10:
		if (low & 8) {
			dis = r_str_newf ("adc %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("adc %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 11:
		if (low & 8) {
			dis = r_str_newf ("and %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("and %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 12:
		if (low & 8) {
			dis = r_str_newf ("or %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("or %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 13:
		if (low & 8) {
			dis = r_str_newf ("nor %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("nor %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 14:
		if (low & 8) {
			dis = r_str_newf ("cmp %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("cmp %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	case 15:
		if (low & 8) {
			dis = r_str_newf ("sbb %c, %c", reg[low & 7], reg[buf[1]]);
		} else {
			dis = r_str_newf ("sbb %c, 0x%02x", reg[low & 7], buf[1]);
		}
		break;
	default:
		dis = strdup ("invalid");
		break;
	}
	if (dlen) {
		*dlen = len;
	}
	return dis;
}
