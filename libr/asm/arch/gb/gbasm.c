#include <r_util.h>
#include <r_types.h>
#include <r_asm.h>
#include <string.h>

static void str_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A'))
		c[0] += 0x20;
}

static int gb_reg_idx (char r) {
	const char *rstr = "bcdehla";
	const char *ptr = strchr (rstr, r);
	return ptr?(int)(size_t)(ptr-rstr):-1;
}

static bool gb_parse_cb1 (ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	int i;
	if (strlen (buf_asm) < minlen)
		return false;
	buf[0] = base;
	i = strlen (&buf_asm[minlen - 1]);
	r_str_replace_in (&buf_asm[minlen - 1], (ut32)i, "[ ", "[", true);
	r_str_replace_in (&buf_asm[minlen - 1], (ut32)i, " ]", "]", true);
	r_str_do_until_token (str_op, buf_asm, ' ');
	i = gb_reg_idx (buf_asm[minlen-1]);
	if (i != (-1)) {
		buf[0] |= (ut8)i;
		return true;
	} else if (buf_asm[minlen - 1] == '['
		&& buf_asm[minlen] == 'h'
		&& buf_asm[minlen + 1] == 'l'
		&& buf_asm[minlen + 2] == ']' ) {
		buf[0] |= 6;
		return true;
	} else 	return false;
}

static bool gb_parse_cb2 (ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	ut64 num;
	int i;
	char *p, *q;
	if ((i = strlen (buf_asm)) < minlen)
		return false;
	r_str_replace_in (buf_asm, (ut32)i, "[ ", "[", true);
	r_str_replace_in (buf_asm, (ut32)i, " ]", "]", true);
	r_str_replace_in (buf_asm, (ut32)i, ", ", ",", true);
	p = strchr (buf_asm, (int)' ');
	if (!p) return false;
	q = strchr (p, (int)',');
	if (!q) return false;
	q[0] = '\0';
	if (p[1] == '\0' || q[1] == '\0') {
		q[0] = ',';
		return false;
	}
	num = r_num_get (NULL, &p[1]);
	q[0] = ',';
	if (num > 7)
		return false;
	buf[0] = base + (ut8)num * 8;
	i = gb_reg_idx (q[1]);
	if (i != (-1)) {
		buf[0] |= (ut8)i;
		return true;
	}
	if (strlen(&q[1]) < 4)
		return false;
	if (q[1] == '[' && q[2] == 'h'
			&& q[3] == 'l'
			&& q[4] == ']') {
		buf[0] |= 6;
		return true;
	}
	return false;
}

static int gb_parse_arith1 (ut8 *buf, const int minlen, char *buf_asm, ut8 base, ut8 alt) {
	int i;
	ut64 num;
	if (strlen (buf_asm) < minlen)
		return 0;
	buf[0] = base;
	i = strlen (&buf_asm[minlen - 1]);
	r_str_replace_in (&buf_asm[minlen - 1], (ut32)i, "[ ", "[", true);
	r_str_replace_in (&buf_asm[minlen - 1], (ut32)i, " ]", "]", true);
	r_str_do_until_token (str_op, buf_asm, ' ');
	i = gb_reg_idx (buf_asm[minlen-1]);
	if (i != (-1))
		buf[0] |= (ut8)i;
	else if (buf_asm[minlen - 1] == '['
		&& buf_asm[minlen] == 'h'
		&& buf_asm[minlen + 1] == 'l'
		&& buf_asm[minlen + 2] == ']' )
		buf[0] |= 6;
	else {
		buf[0] = alt;
		num = r_num_get (NULL, &buf_asm[minlen - 1]);
		buf[1] = (ut8)(num & 0xff);
		return 2;
	}
	return 1;
}

static bool gb_parse_ld1 (ut8 *buf, const int minlen, char *buf_asm) {
	int i;
	r_str_replace_in (buf_asm, strlen(buf_asm), ", ", ",", true);
	if ((i = strlen(buf_asm)) < minlen)
		return false;
	r_str_do_until_token (str_op, buf_asm, '\0');
	if (buf_asm[4] == ',') {
		i = gb_reg_idx (buf_asm[3]);
		if (i == (-1))
			return false;
		buf[0] = (ut8)(0x40 + (i * 8));
		if ((i = gb_reg_idx (buf_asm[5])) == (-1))
			return false;
		buf[0] |= (ut8)i;
	} else if (buf_asm[3] == '['
		&& buf_asm[4] == 'h'
		&& buf_asm[5] == 'l'
		&& buf_asm[6] == ']'
		&& buf_asm[7] == ',') {
		if ((i = gb_reg_idx (buf_asm[8])) == (-1))
			return false;
		buf[0] = 0x70 | (ut8)i;
	}
	return true;
}

static bool gb_parse_ld2 (ut8 *buf, char *buf_asm) {
	int i;
	ut64 num;
	if (strlen (buf_asm) < 6)
		return false;
	if (buf_asm[4] == ',') {
		if ((i = gb_reg_idx (buf_asm[3])) == (-1))
			return false;
		buf[0] = 0x6 + (ut8)(i * 8);
		num = r_num_get (NULL, &buf_asm[5]);
		buf[1] = (ut8)(num & 0xff);
		return true;
	} else if (buf_asm[3] == '['
		&& buf_asm[4] == 'h'
		&& buf_asm[5] == 'l'
		&& buf_asm[6] == ']'
		&& buf_asm[7] == ','
		&& buf_asm[8] != '\0') {
		buf[0] = 0x36;
		num = r_num_get (NULL, &buf_asm[8]);
		buf[1] = (ut8)(num & 0xff);
		return true;
	}
	return false;
}

static int gbAsm(RAsm *a, RAsmOp *op, const char *buf) {
	int mn_len, i, len = 1;
	ut32 mn = 0;
	ut64 num;
	if (!a || !op || !buf)
		return 0;
	strncpy (op->buf_asm, buf, R_ASM_BUFSIZE-1);
	op->buf_asm[R_ASM_BUFSIZE-1] = 0;
	i = strlen (op->buf_asm);
	while (strstr (op->buf_asm, "  "))
		r_str_replace_in (op->buf_asm, (ut32)i, "  ", " ", true);
	r_str_replace_in (op->buf_asm, (ut32)i, " ,", ",", true);
	mn_len = r_str_do_until_token (str_op, op->buf_asm, ' ');
	if (mn_len < 2 || mn_len > 4)
		return 0;
	for (i = 0; i < mn_len; i++)
		mn = (mn << 8) | op->buf_asm[i];
	switch (mn) {
		case 0x6e6f70:			//nop
			op->buf[0] = 0x00;
			break;
		case 0x696e63:			//inc
			if ((i = strlen (op->buf_asm)) < 5)
				return op->size = 0;
			r_str_replace_in (op->buf_asm, (ut32)i, "[ ", "[", true);
			r_str_replace_in (op->buf_asm, (ut32)i, " ]", "]", true);
			r_str_do_until_token (str_op, &op->buf_asm[4], '\0');
			if (op->buf_asm[4] == 'b') {
				if (op->buf_asm[5] == 'c')
					op->buf[0] = 0x03;
				else	op->buf[0] = 0x04;
			} else if (op->buf_asm[4] == 'c')
				op->buf[0] = 0x0c;
			else if (op->buf_asm[4] == 'd') {
				if (op->buf_asm[5] == 'e')
					op->buf[0] = 0x13;
				else	op->buf[0] = 0x14;
			} else if (op->buf_asm[4] == 'e')
				op->buf[0] = 0x1c;
			else if (op->buf_asm[4] == 'h') {
				if (op->buf_asm[5] == 'l')
					op->buf[0] = 0x23;
				else	op->buf[0] = 0x24;
			} else if (op->buf_asm[4] == 'l')
				op->buf[0] = 0x2c;
			else if (op->buf_asm[4] == 'a')
				op->buf[0] = 0x3c;
			else if (op->buf_asm[4] == 's'
				&& op->buf_asm[5] == 'p')
				op->buf[0] = 0x33;
			else if (op->buf_asm[4] == '['
				&& op->buf_asm[5] == 'h'
				&& op->buf_asm[6] == 'l'
				&& op->buf_asm[7] == ']')
				op->buf[0] = 0x34;
			else	len = 0;	
			break;
		case 0x646563:			//dec
			if ((i = strlen (op->buf_asm)) < 5)
				return op->size = 0;
			r_str_replace_in (op->buf_asm, (ut32)i, "[ ", "[", true);
			r_str_replace_in (op->buf_asm, (ut32)i, " ]", "]", true);
			r_str_do_until_token (str_op, &op->buf_asm[4], '\0');
			if (op->buf_asm[4] == 'b') {
				if (op->buf_asm[5] == 'c')
					op->buf[0] = 0x0b;
				else	op->buf[0] = 0x05;
			} else if (op->buf_asm[4] == 'c')
				op->buf[0] = 0x0d;
			else if (op->buf_asm[4] == 'd') {
				if (op->buf_asm[5] == 'e')
					op->buf[0] = 0x1b;
				else	op->buf[0] = 0x15;
			} else if (op->buf_asm[4] == 'e')
				op->buf[0] = 0x1d;
			else if (op->buf_asm[4] == 'h') {
				if (op->buf_asm[5] == 'l')
					op->buf[0] = 0x2b;
				else	op->buf[0] = 0x25;
			} else if (op->buf_asm[4] == 'l')
				op->buf[0] = 0x2d;
			else if (op->buf_asm[4] == 'a')
				op->buf[0] = 0x3d;
			else if (op->buf_asm[4] == 's'
				&& op->buf_asm[5] == 'p')
				op->buf[0] = 0x3b;
			else if (op->buf_asm[4] == '['
				&& op->buf_asm[5] == 'h'
				&& op->buf_asm[6] == 'l'
				&& op->buf_asm[7] == ']')
				op->buf[0] = 0x35;
			else	len = 0;	
			break;
		case 0x726c6361:		//rlca
			op->buf[0] = 0x07;
			break;
		case 0x72726361:		//rrca
			op->buf[0] = 0xf0;
			break;
		case 0x73746f70:		//stop
			op->buf[0] = 0x10;
			break;
		case 0x726c61:			//rla
			op->buf[0] = 0x17;
			break;
		case 0x727261:			//rra
			op->buf[0] = 0x1f;
			break;
		case 0x646161:			//daa
			op->buf[0] = 0x27;
			break;
		case 0x63706c:			//cpl
			op->buf[0] = 0x2f;
			break;
		case 0x616464:			//add
			r_str_replace_in (op->buf_asm, strlen(op->buf_asm), ", ", ",", true);
			if (strlen(op->buf_asm) < 5)
				return op->size = 0;
			if (op->buf_asm[4] == 's'
				&& op->buf_asm[5] == 'p'
				&& op->buf_asm[6] == ','
				&& op->buf_asm[7] != '\0') {
				op->buf[0] = 0xe8;
				num = r_num_get (NULL, &op->buf_asm[7]);
				op->buf[1] = (ut8)(num & 0xff);
				len = 2;
			}
			else if (!strcmp (op->buf_asm, "hl,bc"))
				op->buf[0] = 0x09;
			else if (!strcmp (&op->buf_asm[4], "hl,de"))
				op->buf[0] = 0x19;
			else if (!strcmp (&op->buf_asm[4], "hl,hl"))
				op->buf[0] = 0x29;
			else if (!strcmp (&op->buf_asm[4], "hl,sp"))
				op->buf[0] = 0x39;
			else	len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0x80, 0xc6);
			break;
		case 0x616463:			//adc
			len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0x88, 0xce);
			break;
		case 0x737562:			//sub
			len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0x90, 0xd6);
			break;
		case 0x736263:			//sbc
			len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0x98, 0xde);
			break;
		case 0x616e64:			//and
			len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0xa0, 0xe6);
			break;
		case 0x786f72:			//xor
			len = gb_parse_arith1 (op->buf, 5, op->buf_asm, 0xa8, 0xee);
			break;
		case 0x6f72:			//or
			len = gb_parse_arith1 (op->buf, 4, op->buf_asm, 0xb0, 0xf6);
			break;
		case 0x6370:			//cp
			len = gb_parse_arith1 (op->buf, 4, op->buf_asm, 0xb8, 0xfe);
			break;
		case 0x736366:			//scf
			op->buf[0] = 0x37;
			break;
		case 0x636366:			//ccf
			op->buf[0] = 0x3f;
			break;
		case 0x68616c74:		//halt
			op->buf[0] = 0x76;
			break;
		case 0x726574:			//ret
			if (strlen(op->buf_asm) < 5)
				op->buf[0] = 0xc9;
			else if (strlen (op->buf_asm) < 6) {	//there is no way that there can be "  " - we did r_str_replace_in
				str_op(&op->buf_asm[4]);
				if (op->buf_asm[4] == 'z')	//ret Z
					op->buf[0] = 0xc8;
				else if (op->buf_asm[4] == 'c')	//ret C
					op->buf[0] = 0xd8;
				else	return op->size = 0;
			} else {
				str_op(&op->buf_asm[4]);
				if (op->buf_asm[4] != 'n')
					return op->size = 0;
				str_op(&op->buf_asm[5]);	//if (!(strlen(op->buf_asm) < 6)) => must be 6 or greater
				if (op->buf_asm[5] == 'z')	//ret nZ
					op->buf[0] = 0xc0;
				else if (op->buf_asm[5] == 'c')	//ret nC
					op->buf[0] = 0xd0;
				else	return op->size = 0;
			}
			break;
		case 0x72657469:		//reti
			op->buf[0] = 0xd9;
			break;
		case 0x6469:			//di
			op->buf[0] = 0xf3;
			break;
		case 0x6569:			//ei
			op->buf[0] = 0xfb;
			break;
		case 0x6c64:			//ld
			if (!gb_parse_ld1 (op->buf, 6, op->buf_asm)) {
				len++;
				if (!gb_parse_ld2 (op->buf, op->buf_asm))
					len = 0;
			}
			break;
		case 0x727374:			//rst
			if (strlen (op->buf_asm) < 5)
				return op->size = 0;
			num = r_num_get (NULL, &op->buf_asm[4]);
			if ((num & 7) || ((num/8) > 7))
				return op->size = 0;
			op->buf[0] = (ut8)((num & 0xff) + 0xc7);
			break;
		case 0x70757368:		//push
			if (strlen (op->buf_asm) < 7)
				return op->size = 0;
			str_op (&op->buf_asm[5]);
			str_op (&op->buf_asm[6]);
			if (op->buf_asm[5] == 'b' && op->buf_asm[6] == 'c') {
				op->buf[0] = 0xc5;
			} else if (op->buf_asm[5] == 'd' && op->buf_asm[6] == 'e') {
				op->buf[0] = 0xd5;
			} else if (op->buf_asm[5] == 'h' && op->buf_asm[6] == 'l') {
				op->buf[0] = 0xe5;
			} else if (op->buf_asm[5] == 'a' && op->buf_asm[6] == 'f') {
				op->buf[0] = 0xf5;
			} else len = 0;
			break;
		case 0x706f70:			//pop	
			if (strlen (op->buf_asm) < 6)
				return op->size = 0;
			str_op (&op->buf_asm[4]);
			str_op (&op->buf_asm[5]);
			if (op->buf_asm[4] == 'b' && op->buf_asm[5] == 'c') {
				op->buf[0] = 0xc1;
			} else if (op->buf_asm[4] == 'd' && op->buf_asm[5] == 'e') {
				op->buf[0] = 0xd1;
			} else if (op->buf_asm[4] == 'h' && op->buf_asm[5] == 'l') {
				op->buf[0] = 0xe1;
			} else if (op->buf_asm[4] == 'a' && op->buf_asm[5] == 'f') {
				op->buf[0] = 0xf1;
			} else len = 0;
			break;
		case 0x6a70:			//jp
			if (strlen(op->buf_asm) < 4)
				return op->size = 0;
			{
				char *p = strchr (op->buf_asm, (int)',');
				if (!p) {
					str_op (&op->buf_asm[3]);
					str_op (&op->buf_asm[4]);
					if (op->buf_asm[3] == 'h' && op->buf_asm[4] == 'l')
						op->buf[0] = 0xe9;
					else {
						num = r_num_get (NULL, &op->buf_asm[3]);
						len = 3;
						op->buf[0] = 0xc3;
						op->buf[1] = (ut8)(num & 0xff);
						op->buf[2] = (ut8)((num & 0xff00) >> 8);
					}
				} else {
					str_op (p-2);
					str_op (p-1);
					if (*(p-2) == 'n') {
						if (*(p-1) == 'z')
							op->buf[0] = 0xc2;
						else if (*(p-1) == 'c')
							op->buf[0] = 0xd2;
						else	return op->size = 0;
					} else if (*(p-2) == ' ') {
						if (*(p-1) == 'z')
							op->buf[0] = 0xca;
						else if (*(p-1) == 'c')
							op->buf[0] = 0xda;
						else	return op->size = 0;
					} else	return op->size = 0;
					r_str_replace_in (p, strlen(p), ", ", ",", true);
					if (p[1] == '\0')
						return op->size = 0;
					num = r_num_get (NULL, p + 1);
					op->buf[1] = (ut8)(num & 0xff);
					op->buf[2] = (ut8)((num & 0xff00) >> 8);
					len = 3;
				}
			}
			break;
		case 0x6a72:			//jr
			if (strlen (op->buf_asm) < 4)
				return op->size = 0;
			{
				char *p = strchr (op->buf_asm, (int)',');
				if (!p) {
					num = r_num_get (NULL, &op->buf_asm[3]);
					len = 2;
					op->buf[0] = 0x18;
					op->buf[1] = (ut8)(num & 0xff);
				} else {
					str_op (p-2);
					str_op (p-1);
					if (*(p-2) == 'n') {
						if (*(p-1) == 'z')
							op->buf[0] = 0x20;
						else if (*(p-1) == 'c')
							op->buf[0] = 0x30;
						else	return op->size = 0;
					} else if (*(p-2) == ' ') {
						if (*(p-1) == 'z')
							op->buf[0] = 0x28;
						else if (*(p-1) == 'c')
							op->buf[0] = 0x38;
						else	return op->size = 0;
					} else	return op->size = 0;
					r_str_replace_in (p, strlen(p), ", ", ",", true);
					if (p[1] == '\0')
						return op->size = 0;
					num = r_num_get (NULL, p + 1);
					op->buf[1] = (ut8)(num & 0xff);
					len = 2;
				}
			}
			break;
		case 0x63616c6c:		//call 
			if (strlen(op->buf_asm) < 6)
				return op->size = 0;
			{
				char *p = strchr (op->buf_asm, (int)',');
				if (!p) {
					num = r_num_get (NULL, &op->buf_asm[3]);
					len = 3;
					op->buf[0] = 0xcd;
					op->buf[1] = (ut8)(num & 0xff);
					op->buf[2] = (ut8)((num & 0xff00) >> 8);
				} else {
					str_op (p-2);
					str_op (p-1);
					if (*(p-2) == 'n') {
						if (*(p-1) == 'z')
							op->buf[0] = 0xc4;
						else if (*(p-1) == 'c')
							op->buf[0] = 0xd4;
						else	return op->size = 0;
					} else if (*(p-2) == ' ') {
						if (*(p-1) == 'z')
							op->buf[0] = 0xcc;
						else if (*(p-1) == 'c')
							op->buf[0] = 0xdc;
						else	return op->size = 0;
					} else	return op->size = 0;
					r_str_replace_in (p, strlen(p), ", ", ",", true);
					if (p[1] == '\0')
						return op->size = 0;
					num = r_num_get (NULL, p + 1);
					op->buf[1] = (ut8)(num & 0xff);
					op->buf[2] = (ut8)((num & 0xff00) >> 8);
					len = 3;
				}
			}
			break;
		case 0x726c63:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 5, op->buf_asm, 0x00))
				len = 0;
			break;
		case 0x727263:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 5, op->buf_asm, 0x08))
				len = 0;
			break;
		case 0x726c:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 4, op->buf_asm, 0x10))
				len = 0;
			break;
		case 0x7272:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 4, op->buf_asm, 0x18))
				len = 0;
			break;
		case 0x736c61:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 5, op->buf_asm, 0x20))
				len = 0;
			break;
		case 0x737261:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 5, op->buf_asm, 0x28))
				len = 0;
			break;
		case 0x73776170:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 6, op->buf_asm, 0x30))
				len = 0;
			break;
		case 0x73726c:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb1 (&op->buf[1], 5, op->buf_asm, 0x38))
				len = 0;
			break;
		case 0x626974:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb2 (&op->buf[1], 6, op->buf_asm, 0x40))
				len = 0;
			break;
		case 0x726573:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb2 (&op->buf[1], 6, op->buf_asm, 0x80))
				len = 0;
			break;
		case 0x736574:
			op->buf[0] = 0xcb;
			len = 2;
			if (!gb_parse_cb2 (&op->buf[1], 6, op->buf_asm, 0xc0))
				len = 0;
			break;
		default:
			len = 0;
			break;
	}
	return op->size = len;
}
