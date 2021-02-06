/* radare - LGPL - Copyright 2012-2020 - condret, pancake */

#include <r_util.h>
#include <r_types.h>
#include <r_asm.h>
#include <string.h>

static void str_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A')) {
		c[0] += 0x20;
	}
}

static int gb_reg_idx (char r) {
	const char *rstr = "bcdehl a";
	const char *ptr = strchr (rstr, r);
	return ptr ? (int)(size_t)(ptr - rstr) : -1;
}

static bool gb_parse_cb1 (ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
// minlen varries between 4 and 6
	int i;
	size_t j;
	if (strlen (buf_asm) < minlen || minlen < 1) {
		return false;
	}
	buf[0] = base;
	char *ptr_asm = buf_asm + minlen - 1;
	j = strlen (ptr_asm);
	r_str_replace_in (ptr_asm, (ut32)j, "[ ", "[", true);
	r_str_replace_in (ptr_asm, (ut32)j, " ]", "]", true);
	r_str_do_until_token (str_op, buf_asm, ' ');
	i = gb_reg_idx (buf_asm[minlen - 1]);
	if (i != (-1)) {
		buf[0] |= (ut8)i;
		return true;
	}
	if (!strncmp (&buf_asm[minlen - 1], "[hl]", 4)) {
		buf[0] |= 6;
		return true;
	}
	return false;
}

static bool gb_parse_cb2 (ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	ut64 num;
	int i;
	char *p, *q;
	if ((i = strlen (buf_asm)) < minlen) {
		return false;
	}
	r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", true);
	r_str_replace_in (buf_asm, (ut32)i, " ]", "]", true);
	r_str_replace_in (buf_asm, (ut32)i, ", ", ",", true);
	p = strchr (buf_asm, (int)' ');
	if (!p) {
		return false;
	}
	q = strchr (p, (int)',');
	if (!q) {
		return false;
	}
	q[0] = '\0';
	if (p[1] == '\0' || q[1] == '\0') {
		q[0] = ',';
		return false;
	}
	num = r_num_get (NULL, &p[1]);
	q[0] = ',';
	if (num > 7) {
		return false;
	}
	buf[0] = base + (ut8)num * 8;
	i = gb_reg_idx (q[1]);
	if (i != -1) {
		buf[0] |= (ut8)i;
		return true;
	}
	if (strlen (q + 1) < 4) {
		return false;
	}
	if (!strncmp (q + 1, "[hl]", 4)) {
		buf[0] |= 6;
		return true;
	}
	return false;
}

static int gb_parse_arith1(ut8 *buf, const int minlen, char *buf_asm, ut8 base, ut8 alt) {
	int i;
	ut64 num;
	if (strlen (buf_asm) < minlen) {
		return 0;
	}
	buf[0] = base;
	char *ptr_asm = buf_asm + minlen - 1;
	i = strlen (ptr_asm);
	r_str_replace_in (ptr_asm, (ut32)i, "[ ", "[", true);
	r_str_replace_in (ptr_asm, (ut32)i, " ]", "]", true);
	r_str_do_until_token (str_op, buf_asm, ' ');
	i = gb_reg_idx (buf_asm[minlen - 1]);
	if (i != -1) {
		buf[0] |= (ut8)i;
	} else if (!strncmp (buf_asm + minlen - 1, "[hl]", 4)) {
		buf[0] |= 6;
	} else {
		buf[0] = alt;
		num = r_num_get (NULL, buf_asm + minlen - 1);
		buf[1] = (ut8)(num & 0xff);
		return 2;
	}
	return 1;
}

static bool gb_parse_ld1(ut8 *buf, const int minlen, char *buf_asm) {
	int i;
	r_str_replace_in (buf_asm, strlen (buf_asm), ", ", ",", true);
	if (strlen (buf_asm) < minlen) {
		return false;
	}
	r_str_do_until_token (str_op, buf_asm, '\0');
	if (buf_asm[4] == ',') {
		i = gb_reg_idx (buf_asm[3]);
		if (i == (-1)) {
			return false;
		}
		buf[0] = (ut8)(0x40 + (i * 8));
		i = gb_reg_idx (buf_asm[5]);
		if (i == -1) {
			if (strncmp (buf_asm + 5, "[hl]", 4)) {
				return false;
			}
			i = 6;
		}
		buf[0] |= (ut8)i;
		return true;
	}
	if (!strncmp (buf_asm + 3, "[hl],", 5)) {
		if ((i = gb_reg_idx (buf_asm[8])) == (-1)) {
			//'ld [hl], [hl]' does not exist
			return false;
		}
		buf[0] = 0x70 | (ut8)i;
		return true;
	}
	return false;
}

static bool gb_parse_ld2 (ut8 *buf, char *buf_asm) {
	int i;
	ut64 num;
	if (strlen (buf_asm) < 6) {
		return false;
	}
	if (buf_asm[4] == ',') {
		if ((i = gb_reg_idx (buf_asm[3])) == -1) {
			return false;
		}
		buf[0] = 0x6 + (ut8)(i * 8);
		num = r_num_get (NULL, buf_asm + 5);
		buf[1] = (ut8)(num & 0xff);
		return true;
	} else if (!strncmp (buf_asm + 3, "[hl],", 5)) {
		buf[0] = 0x36;
		num = r_num_get (NULL, buf_asm + 8);
		buf[1] = (ut8)(num & 0xff);
		return true;
	}
	return false;
}

static bool gb_parse_ld3 (ut8 *buf, char *buf_asm) {
	if (strlen (buf_asm) < 7) {
		return false;
	}
	if (buf_asm[5] != ',') {
		return false;
	}

	const ut16 reg = (buf_asm[3] << 8) | buf_asm[4];
	switch (reg) {
	case 0x6263:	//bc
		buf[0] = 0x01;
		break;
	case 0x6465:	//de
		buf[0] = 0x11;
		break;
	case 0x686c:	//hl
		buf[0] = 0x21;
		break;
	case 0x7370:	//sp
		buf[0] = 0x31;
		break;
	default:
		return false;
	}

	const ut64 num = r_num_get (NULL, buf_asm + 6);
	buf[1] = num & 0xff;
	buf[2] = (num & 0xff00) >> 8;
	return true;
}

static int gbAsm(RAsm *a, RAsmOp *op, const char *buf) {
	int mn_len, j, len = 1;
	ut32 mn = 0;
	ut64 num;
	size_t i;
	if (!a || !op || !buf) {
		return 0;
	}
	ut8 opbuf[4] = {0};
	r_strbuf_set (&op->buf_asm, buf);
	char *buf_asm = r_strbuf_get (&op->buf_asm);
	ut32 buf_len = strlen (buf);
	while (strstr (buf_asm, "  ")) {
		r_str_replace_in (buf_asm, buf_len, "  ", " ", true);
	}
	r_str_replace_in (buf_asm, buf_len, " ,", ",", true);
	mn_len = r_str_do_until_token (str_op, buf_asm, ' ');
	if (mn_len < 2 || mn_len > 4) {
		return 0;
	}
	for (j = 0; j < mn_len; j++) {
		mn = (mn << 8) | buf_asm[j];
	}
	switch (mn) {
	case 0x6e6f70: //nop
		opbuf[0] = 0x00;
		break;
	case 0x696e63: //inc
		if ((i = strlen (buf_asm)) < 5) {
			return op->size = 0;
		}
		r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", true);
		r_str_replace_in (buf_asm, (ut32)i, " ]", "]", true);
		r_str_do_until_token (str_op, buf_asm + 4, '\0');
		if (buf_asm[4] == 'b') {
			opbuf[0] = (buf_asm[5] == 'c')? 3: 4;
		} else if (buf_asm[4] == 'c') {
			opbuf[0] = 0x0c;
		} else if (buf_asm[4] == 'd') {
			opbuf[0] = (buf_asm[5] == 'e')? 0x13: 0x14;
		} else if (buf_asm[4] == 'e') {
			opbuf[0] = 0x1c;
		} else if (buf_asm[4] == 'h') {
			opbuf[0] = (buf_asm[5] == 'l')? 0x23: 0x24;
		} else if (buf_asm[4] == 'l') {
			opbuf[0] = 0x2c;
		} else if (buf_asm[4] == 'a') {
			opbuf[0] = 0x3c;
		} else if (buf_asm[4] == 's' && buf_asm[5] == 'p') {
			opbuf[0] = 0x33;
		} else if (!strncmp (buf_asm + 4, "[hl]", 4)) {
			opbuf[0] = 0x34;
		} else {
			len = 0;
		}
		break;
	case 0x646563:			//dec
		if ((i = strlen (buf_asm)) < 5) {
			return op->size = 0;
		}
		r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", true);
		r_str_replace_in (buf_asm, (ut32)i, " ]", "]", true);
		r_str_do_until_token (str_op, &buf_asm[4], '\0');
		switch (buf_asm[4]) {
		case 'b':
			opbuf[0] = (buf_asm[5] == 'c')? 0x0b: 0x05;
			break;
		case 'c':
			opbuf[0] = 0x0d;
			break;
		case 'd':
			opbuf[0] = (buf_asm[5] == 'e')? 0x1b: 0x15;
			break;
		case 'e':
			opbuf[0] = 0x1d;
			break;
		case 'h':
			opbuf[0] = (buf_asm[5] == 'l')? 0x2b: 0x25;
			break;
		case 'l':
			opbuf[0] = 0x2d;
			break;
		case 'a':
			opbuf[0] = 0x3d;
			break;
		default:
			if (!strncmp (buf_asm + 4, "sp", 2)) {
				opbuf[0] = 0x3b;
			} else if (!strncmp (buf_asm, "[hl]", 4)) {
				opbuf[0] = 0x35;
			} else {
				len = 0;	
			}
			break;
		}
		break;
	case 0x726c6361: //rlca
		opbuf[0] = 0x07;
		break;
	case 0x72726361: //rrca
		opbuf[0] = 0xf0;
		break;
	case 0x73746f70:		//stop
		opbuf[0] = 0x10;
		break;
	case 0x726c61:			//rla
		opbuf[0] = 0x17;
		break;
	case 0x727261:			//rra
		opbuf[0] = 0x1f;
		break;
	case 0x646161:			//daa
		opbuf[0] = 0x27;
		break;
	case 0x63706c:			//cpl
		opbuf[0] = 0x2f;
		break;
	case 0x616464:			//add
		r_str_replace_in (buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return op->size = 0;
		if (buf_asm[4] == 's'
			&& buf_asm[5] == 'p'
			&& buf_asm[6] == ','
			&& buf_asm[7] != '\0') {
			opbuf[0] = 0xe8;
			num = r_num_get (NULL, buf_asm + 7);
			opbuf[1] = (ut8)(num & 0xff);
			len = 2;
		} else if (!strcmp (buf_asm, "hl,bc")) {
			opbuf[0] = 0x09;
		} else if (!strcmp (buf_asm + 4, "hl,de")) {
			opbuf[0] = 0x19;
		} else if (!strcmp (buf_asm + 4, "hl,hl")) {
			opbuf[0] = 0x29;
		} else if (!strcmp (buf_asm + 4, "hl,sp")) {
			opbuf[0] = 0x39;
		} else {
			len = gb_parse_arith1 (opbuf, 5, buf_asm, 0x80, 0xc6);
		}
		break;
	case 0x616463:			//adc
		len = gb_parse_arith1 (opbuf, 5, buf_asm, 0x88, 0xce);
		break;
	case 0x737562:			//sub
		len = gb_parse_arith1 (opbuf, 5, buf_asm, 0x90, 0xd6);
		break;
	case 0x736263:			//sbc
		len = gb_parse_arith1 (opbuf, 5, buf_asm, 0x98, 0xde);
		break;
	case 0x616e64:			//and
		len = gb_parse_arith1 (opbuf, 5, buf_asm, 0xa0, 0xe6);
		break;
	case 0x786f72:			//xor
		len = gb_parse_arith1 (opbuf, 5, buf_asm, 0xa8, 0xee);
		break;
	case 0x6f72:			//or
		len = gb_parse_arith1 (opbuf, 4, buf_asm, 0xb0, 0xf6);
		break;
	case 0x6370:			//cp
		len = gb_parse_arith1 (opbuf, 4, buf_asm, 0xb8, 0xfe);
		break;
	case 0x736366:			//scf
		opbuf[0] = 0x37;
		break;
	case 0x636366:			//ccf
		opbuf[0] = 0x3f;
		break;
	case 0x68616c74: //halt
		opbuf[0] = 0x76;
		break;
	case 0x726574: //ret
		if (strlen (buf_asm) < 5) {
			opbuf[0] = 0xc9;
		} else if (strlen (buf_asm) < 6) {
			// there is no way that there can be "  " - we did r_str_replace_in
			str_op (buf_asm + 4);
			if (buf_asm[4] == 'z') { //ret Z
				opbuf[0] = 0xc8;
			} else if (buf_asm[4] == 'c') { //ret C
				opbuf[0] = 0xd8;
			} else {
				return op->size = 0;
			}
		} else {
			str_op (&buf_asm[4]);
			if (buf_asm[4] != 'n') {
				return op->size = 0;
			}
			str_op (&buf_asm[5]);	//if (!(strlen(buf_asm) < 6)) => must be 6 or greater
			if (buf_asm[5] == 'z') { //ret nZ
				opbuf[0] = 0xc0;
			} else if (buf_asm[5] == 'c') { //ret nC
				opbuf[0] = 0xd0;
			} else {
				return op->size = 0;
			}
		}
		break;
	case 0x72657469: //reti
		opbuf[0] = 0xd9;
		break;
	case 0x6469: //di
		opbuf[0] = 0xf3;
		break;
	case 0x6569: //ei
		opbuf[0] = 0xfb;
		break;
	case 0x6c64: //ld
		i = strlen (buf_asm);
		r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", true);
		r_str_replace_in (buf_asm, (ut32)i, " ]", "]", true);
		if (!gb_parse_ld1 (opbuf, 6, buf_asm)) {
			len++;
			if (!gb_parse_ld2 (opbuf, buf_asm)) {
				len++;
				if (!gb_parse_ld3 (opbuf, buf_asm)) {
					len = 0;
				}
			}
		}
		break;
	case 0x727374: //rst
		if (strlen (buf_asm) < 5) {
			return op->size = 0;
		}
		num = r_num_get (NULL, &buf_asm[4]);
		if ((num & 7) || ((num/8) > 7)) {
			return op->size = 0;
		}
		opbuf[0] = (ut8)((num & 0xff) + 0xc7);
		break;
	case 0x70757368: //push
		if (strlen (buf_asm) < 7) {
			return op->size = 0;
		}
		str_op (buf_asm + 5);
		str_op (buf_asm + 6);
		if (buf_asm[5] == 'b' && buf_asm[6] == 'c') {
			opbuf[0] = 0xc5;
		} else if (buf_asm[5] == 'd' && buf_asm[6] == 'e') {
			opbuf[0] = 0xd5;
		} else if (buf_asm[5] == 'h' && buf_asm[6] == 'l') {
			opbuf[0] = 0xe5;
		} else if (buf_asm[5] == 'a' && buf_asm[6] == 'f') {
			opbuf[0] = 0xf5;
		} else {
			len = 0;
		}
		break;
	case 0x706f70:			//pop	
		if (strlen (buf_asm) < 6)
			return op->size = 0;
		str_op (&buf_asm[4]);
		str_op (&buf_asm[5]);
		if (buf_asm[4] == 'b' && buf_asm[5] == 'c') {
			opbuf[0] = 0xc1;
		} else if (buf_asm[4] == 'd' && buf_asm[5] == 'e') {
			opbuf[0] = 0xd1;
		} else if (buf_asm[4] == 'h' && buf_asm[5] == 'l') {
			opbuf[0] = 0xe1;
		} else if (buf_asm[4] == 'a' && buf_asm[5] == 'f') {
			opbuf[0] = 0xf1;
		} else {
			len = 0;
		}
		break;
	case 0x6a70: //jp
		if (strlen (buf_asm) < 4) {
			return op->size = 0;
		}
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				str_op (&buf_asm[3]);
				str_op (&buf_asm[4]);
				if (buf_asm[3] == 'h' && buf_asm[4] == 'l')
					opbuf[0] = 0xe9;
				else {
					num = r_num_get (NULL, &buf_asm[3]);
					len = 3;
					opbuf[0] = 0xc3;
					opbuf[1] = (ut8)(num & 0xff);
					opbuf[2] = (ut8)((num & 0xff00) >> 8);
				}
			} else {
				str_op (p-2);
				str_op (p-1);
				if (*(p-2) == 'n') {
					if (*(p-1) == 'z') {
						opbuf[0] = 0xc2;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0xd2;
					} else {
						return op->size = 0;
					}
				} else if (*(p-2) == ' ') {
					if (*(p-1) == 'z') {
						opbuf[0] = 0xca;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0xda;
					} else {
						return op->size = 0;
					}
				} else {
					return op->size = 0;
				}
				r_str_replace_in (p, strlen(p), ", ", ",", true);
				if (!p[0] || !p[1]) {
					return op->size = 0;
				}
				num = r_num_get (NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
				len = 3;
			}
		}
		break;
	case 0x6a72: // jr
		if (strlen (buf_asm) < 4)
			return op->size = 0;
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				num = r_num_get (NULL, &buf_asm[3]);
				len = 2;
				opbuf[0] = 0x18;
				opbuf[1] = (ut8)(num & 0xff);
			} else {
				str_op (p-2);
				str_op (p-1);
				if (*(p-2) == 'n') {
					if (*(p-1) == 'z')
						opbuf[0] = 0x20;
					else if (*(p-1) == 'c')
						opbuf[0] = 0x30;
					else	return op->size = 0;
				} else if (*(p-2) == ' ') {
					if (*(p-1) == 'z')
						opbuf[0] = 0x28;
					else if (*(p-1) == 'c')
						opbuf[0] = 0x38;
					else	return op->size = 0;
				} else {
					return op->size = 0;
				}
				r_str_replace_in (p, strlen(p), ", ", ",", true);
				if (!p[1]) {
					return op->size = 0;
				}
				num = r_num_get (NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				len = 2;
			}
		}
		break;
	case 0x63616c6c:		//call 
		if (strlen(buf_asm) < 6) {
			return op->size = 0;
		}
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				num = r_num_get (NULL, buf_asm + 4);
				len = 3;
				opbuf[0] = 0xcd;
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
			} else {
				str_op (p-2);
				str_op (p-1);
				if (*(p-2) == 'n') {
					if (*(p - 1) == 'z') {
						opbuf[0] = 0xc4;
					} else if (*(p - 1) == 'c') {
						opbuf[0] = 0xd4;
					} else {
						return op->size = 0;
					}
				} else if (*(p - 2) == ' ') {
					if (*(p - 1) == 'z') {
						opbuf[0] = 0xcc;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0xdc;
					} else {
						return op->size = 0;
					}
				} else {
					return op->size = 0;
				}
				r_str_replace_in (p, strlen(p), ", ", ",", true);
				if (!*p || !p[1]) {
					return op->size = 0;
				}
				num = r_num_get (NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
				len = 3;
			}
		}
		break;
	case 0x726c63:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 5, buf_asm, 0x00)? 2: 0;
		break;
	case 0x727263:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 5, buf_asm, 0x08)? 2: 0;
		break;
	case 0x726c:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 4, buf_asm, 0x10)? 2: 0;
		break;
	case 0x7272:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 4, buf_asm, 0x18)? 2: 0;
		break;
	case 0x736c61:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 5, buf_asm, 0x20)? 2: 0;
		break;
	case 0x737261:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 5, buf_asm, 0x28)? 2: 0;
		break;
	case 0x73776170:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 6, buf_asm, 0x30)? 2: 0;
		break;
	case 0x73726c:
		opbuf[0] = 0xcb;
		len = gb_parse_cb1 (opbuf + 1, 6, buf_asm, 0x38)? 2: 0;
		break;
	case 0x626974:
		opbuf[0] = 0xcb;
		len = gb_parse_cb2 (opbuf + 1, 6, buf_asm, 0x40)? 2: 0;
		break;
	case 0x726573:
		opbuf[0] = 0xcb;
		len = gb_parse_cb2 (opbuf + 1, 6, buf_asm, 0x80)? 2: 0;
		break;
	case 0x736574:
		opbuf[0] = 0xcb;
		len = gb_parse_cb2 (opbuf + 1, 6, buf_asm, 0xc0)? 2: 0;
		break;
	default:
		len = 0;
		break;
	}
	memcpy(r_strbuf_get(&op->buf), opbuf, sizeof(ut8) * len);
	return op->size = len;
}
