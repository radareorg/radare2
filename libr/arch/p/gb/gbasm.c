/* radare - LGPL - Copyright 2012-2023 - condret, pancake */

#include <r_util.h>

static inline void str_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A')) {
		c[0] += 0x20;
	}
}

static int gb_reg_idx(const char *operand) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (cb_regs); i++) {
		if (!r_str_casecmp (operand, cb_regs[i])) {
			return i;
		}
	}
	return -1;
}

static char *gb_split_operands(char *operands) {
	char *src = strchr (operands, ',');
	if (src) {
		*src++ = 0;
		r_str_trim (operands);
		r_str_trim (src);
	}
	return src;
}

static bool gb_parse_number(const char *operand, ut64 *value) {
	// RNum accepts partial expressions, so validate the complete operand first.
	const char *p = operand;
	int depth = 0;
	bool need_number = true;
	while (*(p = r_str_trim_head_ro (p))) {
		if (need_number) {
			if (*p == '(') {
				if (++depth > 32) {
					return false;
				}
				p++;
				continue;
			}
			if (*p == '-' || *p == '~' || *p == '!') {
				p++;
				continue;
			}
			const char *digits = "0123456789";
			if (*p == '0' && p[1]) {
				switch (p[1]) {
				case 'x': case 'X': digits = "0123456789abcdefABCDEF"; p += 2; break;
				case 'b': case 'B': digits = "01"; p += 2; break;
				case 'o': case 'O': digits = "01234567"; p += 2; break;
				}
			}
			size_t len = strspn (p, digits);
			if (!len) {
				return false;
			}
			p += len;
			need_number = false;
		} else if (*p == ')' && depth) {
			depth--;
			p++;
		} else if (r_num_is_op (*p) || *p == '<' || *p == '>') {
			char op = *p++;
			if (*p == op && (op == '<' || op == '>' || op == '&' || op == '|' || op == '^')) {
				p++;
				if (*p == op && (op == '<' || op == '>')) {
					p++;
				}
			}
			need_number = true;
		} else {
			return false;
		}
	}
	if (need_number || depth) {
		return false;
	}
	RNum num = {0};
	const char *error = NULL;
	*value = r_num_math_err (&num, operand, &error);
	return !error && !num.dbz;
}

static bool gb_parse_cb1(ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	if (strlen (buf_asm) < minlen) {
		return false;
	}
	char *operand = buf_asm + minlen - 1;
	r_str_trim (operand);
	int reg = gb_reg_idx (operand);
	if (reg < 0) {
		return false;
	}
	buf[0] = base | reg;
	return true;
}

static bool gb_parse_cb2(ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	if (strlen (buf_asm) < minlen) {
		return false;
	}
	char *bit = buf_asm + 4;
	char *operand = gb_split_operands (bit);
	ut64 number;
	if (!operand || !gb_parse_number (bit, &number) || number > 7) {
		return false;
	}
	int reg = gb_reg_idx (operand);
	if (reg < 0) {
		return false;
	}
	buf[0] = base | (number << 3) | reg;
	return true;
}

static int gb_parse_arith1(ut8 *buf, const int minlen, char *buf_asm, ut8 base, ut8 alt) {
	if (strlen (buf_asm) < minlen) {
		return 0;
	}
	char *operand = buf_asm + minlen - 1;
	r_str_trim (operand);
	if (!r_str_ncasecmp (operand, "a,", 2)) {
		operand += 2;
		r_str_trim (operand);
	}
	int reg = gb_reg_idx (operand);
	if (reg >= 0) {
		buf[0] = base | reg;
		return 1;
	}
	ut64 number;
	if (!gb_parse_number (operand, &number)) {
		return 0;
	}
	buf[0] = alt;
	buf[1] = number;
	return 2;
}

static int gb_parse_ld(ut8 *buf, char *dst, bool high) {
	static const char *const pairs[] = { "bc", "de", "hl", "sp" };
	static const struct {
		const char *name;
		ut8 store;
		ut8 load;
	} mem_ops[] = {
		{ "bc", 0x02, 0x0a }, { "de", 0x12, 0x1a },
		{ "hl+", 0x22, 0x2a }, { "hl-", 0x32, 0x3a }, { "c", 0xe2, 0xf2 }
	};
	char *src = gb_split_operands (dst);
	if (!src) {
		return 0;
	}
	r_str_case (dst, false);
	r_str_case (src, false);
	int dst_reg = gb_reg_idx (dst);
	int src_reg = gb_reg_idx (src);
	ut64 number;
	if (!high) {
		if (dst_reg >= 0 && src_reg >= 0) {
			if (dst_reg == 6 && src_reg == 6) {
				return 0;
			}
			buf[0] = 0x40 | (dst_reg << 3) | src_reg;
			return 1;
		}
		if (dst_reg >= 0 && gb_parse_number (src, &number)) {
			buf[0] = 0x06 | (dst_reg << 3);
			buf[1] = number;
			return 2;
		}
		if (!strcmp (dst, "sp") && !strcmp (src, "hl")) {
			buf[0] = 0xf9;
			return 1;
		}
		if (!strcmp (dst, "hl") && r_str_startswith (src, "sp")) {
			const char *offset = r_str_trim_head_ro (src + 2);
			if (*offset == '+' && gb_parse_number (offset + 1, &number)) {
				buf[0] = 0xf8;
				buf[1] = number;
				return 2;
			}
			return 0;
		}
		int i;
		for (i = 0; i < R_ARRAY_SIZE (pairs); i++) {
			if (!strcmp (dst, pairs[i]) && gb_parse_number (src, &number)) {
				buf[0] = 0x01 | (i << 4);
				r_write_le16 (buf + 1, number);
				return 3;
			}
		}
	}
	bool load = !strcmp (dst, "a");
	bool accumulator = load || !strcmp (src, "a");
	char *mem = load? src: dst;
	if ((!accumulator && (high || strcmp (src, "sp")))
			|| *mem != '[' || !r_str_endswith (mem, "]")) {
		return 0;
	}
	mem[strlen (mem) - 1] = 0;
	r_str_trim (++mem);
	char *offset = strrchr (mem, '+');
	if (offset && !strcmp (r_str_trim_head_ro (offset + 1), "c")) {
		*offset = 0;
		if (!gb_parse_number (mem, &number) || number != 0xff00) {
			return 0;
		}
		mem = "c";
	}
	int i;
	for (i = 0; i < R_ARRAY_SIZE (mem_ops); i++) {
		if (!strcmp (mem, mem_ops[i].name)) {
			if (!accumulator || (high && strcmp (mem, "c"))) {
				return 0;
			}
			buf[0] = load? mem_ops[i].load: mem_ops[i].store;
			return 1;
		}
	}
	if (*mem == 'r') {
		for (i = 0; i < R_ARRAY_SIZE (gb_io_regs); i++) {
			if (gb_io_regs[i] && !r_str_casecmp (mem, gb_io_regs[i])) {
				number = 0xff00 + i;
				break;
			}
		}
		if (i == R_ARRAY_SIZE (gb_io_regs)) {
			return 0;
		}
	} else if (!gb_parse_number (mem, &number)) {
		return 0;
	}
	if (high) {
		if (number > 0xff && (number < 0xff00 || number > 0xffff)) {
			return 0;
		}
		buf[0] = load? 0xf0: 0xe0;
		buf[1] = number;
		return 2;
	}
	buf[0] = load? 0xfa: accumulator? 0xea: 0x08;
	r_write_le16 (buf + 1, number);
	return 3;
}

static int gbAsm(const char *buf, ut8 **outbuf) {
	int mn_len, j, len = 1;
	ut32 mn = 0;
	ut64 num;
	size_t i;
	if (!buf) {
		return 0;
	}
	ut8 opbuf[4] = {0};
	char *buf_asm = strdup (buf);
	if (!buf_asm) {
		return 0;
	}
	buf_asm = r_str_replace (buf_asm, "$", "0x", true);
	if (!buf_asm) {
		return 0;
	}
	ut32 buf_len = strlen (buf_asm);
	while (strstr (buf_asm, "  ")) {
		r_str_replace_in (buf_asm, buf_len + 1, "  ", " ", true);
	}
	r_str_replace_in (buf_asm, buf_len + 1, " ,", ",", true);
	r_str_replace_in (buf_asm, buf_len + 1, "[ ", "[", true);
	r_str_replace_in (buf_asm, buf_len + 1, " ]", "]", true);
	mn_len = r_str_do_until_token (str_op, buf_asm, ' ');
	if (mn_len < 2 || mn_len > 4) {
		free (buf_asm);
		return 0;
	}
	for (j = 0; j < mn_len; j++) {
		mn = (mn << 8) | buf_asm[j];
	}
	switch (mn) {
	case 0x6e6f70: // nop
		opbuf[0] = 0x00;
		break;
	case 0x696e63: // inc
		if ((i = strlen (buf_asm)) < 5) {
			free (buf_asm);
			return 0;
		}
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
			free (buf_asm);
			return 0;
		}
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
			} else if (!strncmp (buf_asm + 4, "[hl]", 4)) {
				opbuf[0] = 0x35;
			} else {
				len = 0;
			}
			break;
		}
		break;
	case 0x726c6361: // rlca
		opbuf[0] = 0x07;
		break;
	case 0x72726361: // rrca
		opbuf[0] = 0x0f;
		break;
	case 0x726c61: // rla
		opbuf[0] = 0x17;
		break;
	case 0x727261: // rra
		opbuf[0] = 0x1f;
		break;
	case 0x646161: // daa
		opbuf[0] = 0x27;
		break;
	case 0x63706c: // cpl
		opbuf[0] = 0x2f;
		break;
	case 0x616464: // add
		r_str_replace_in (buf_asm, strlen (buf_asm) + 1, ", ", ",", true);
		if (strlen (buf_asm) < 5) {
			free (buf_asm);
			return 0;
		}
		if (buf_asm[4] == 's'
			&& buf_asm[5] == 'p'
			&& buf_asm[6] == ','
			&& buf_asm[7] != '\0') {
			opbuf[0] = 0xe8;
			len = 0;
			if (gb_parse_number (buf_asm + 7, &num)) {
				opbuf[1] = num;
				len = 2;
			}
		} else if (!strcmp (buf_asm + 4, "hl,bc")) {
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
	case 0x736366: // scf
		opbuf[0] = 0x37;
		break;
	case 0x636366: // ccf
		opbuf[0] = 0x3f;
		break;
	case 0x73746f70: // stop
		opbuf[0] = 0x10;
		opbuf[1] = 0;
		len = 2;
		break;
	case 0x68616c74: // halt
		opbuf[0] = 0x76;
		break;
	case 0x726574: // ret
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
				free (buf_asm);
				return 0;
			}
		} else {
			str_op (&buf_asm[4]);
			if (buf_asm[4] != 'n') {
				free (buf_asm);
				return 0;
			}
			str_op (&buf_asm[5]);	//if (!(strlen(buf_asm) < 6)) => must be 6 or greater
			if (buf_asm[5] == 'z') { //ret nZ
				opbuf[0] = 0xc0;
			} else if (buf_asm[5] == 'c') { //ret nC
				opbuf[0] = 0xd0;
			} else {
				free (buf_asm);
				return 0;
			}
		}
		break;
	case 0x72657469: // "reti"
		opbuf[0] = 0xd9;
		break;
	case 0x6469: // "di"
		opbuf[0] = 0xf3;
		break;
	case 0x6569: // "ei"
		opbuf[0] = 0xfb;
		break;
	case 0x6c64: // ld
	case 0x6c6468: // ldh
		len = buf_asm[mn_len]? gb_parse_ld (opbuf, buf_asm + mn_len + 1, mn == 0x6c6468): 0;
		break;
	case 0x727374: //rst
		if (strlen (buf_asm) < 5) {
			free (buf_asm);
			return 0;
		}
		num = r_num_math (NULL, &buf_asm[4]);
		if ((num & 7) || ((num/8) > 7)) {
			free (buf_asm);
			return 0;
		}
		opbuf[0] = (ut8)((num & 0xff) + 0xc7);
		break;
	case 0x70757368: //push
		if (strlen (buf_asm) < 7) {
			free (buf_asm);
			return 0;
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
		if (strlen (buf_asm) < 6) {
			free (buf_asm);
			return 0;
		}
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
			free (buf_asm);
			return 0;
		}
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				str_op (&buf_asm[3]);
				str_op (&buf_asm[4]);
				if (!r_str_casecmp (buf_asm + 3, "hl") || !r_str_casecmp (buf_asm + 3, "[hl]")) {
					opbuf[0] = 0xe9;
				} else {
					num = r_num_math (NULL, &buf_asm[3]);
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
						return 0;
					}
				} else if (*(p-2) == ' ') {
					if (*(p-1) == 'z') {
						opbuf[0] = 0xca;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0xda;
					} else {
						free (buf_asm);
						return 0;
					}
				} else {
					free (buf_asm);
					return 0;
				}
				r_str_replace_in (p, strlen (p) + 1, ", ", ",", true);
				if (!p[0] || !p[1]) {
					free (buf_asm);
					return 0;
				}
				num = r_num_math (NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
				len = 3;
			}
		}
		break;
	case 0x6a72: // jr
		if (strlen (buf_asm) < 4) {
			free (buf_asm);
			return 0;
		}
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				num = r_num_math (NULL, &buf_asm[3]);
				len = 2;
				opbuf[0] = 0x18;
				opbuf[1] = (ut8)(num & 0xff);
			} else {
				str_op (p-2);
				str_op (p-1);
				if (*(p-2) == 'n') {
					if (*(p-1) == 'z') {
						opbuf[0] = 0x20;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0x30;
					} else {
						free (buf_asm);
						return 0;
					}
				} else if (*(p-2) == ' ') {
					if (*(p-1) == 'z') {
						opbuf[0] = 0x28;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0x38;
					} else {
						free (buf_asm);
						return 0;
					}
				} else {
					free (buf_asm);
					return 0;
				}
				r_str_replace_in (p, strlen (p) + 1, ", ", ",", true);
				if (!p[1]) {
					free (buf_asm);
					return 0;
				}
				num = r_num_math (NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				len = 2;
			}
		}
		break;
	case 0x63616c6c:		//call
		if (strlen(buf_asm) < 6) {
			free (buf_asm);
			return 0;
		}
		{
			char *p = strchr (buf_asm, (int)',');
			if (!p) {
				num = r_num_math (NULL, buf_asm + 4);
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
						return 0;
					}
				} else if (*(p - 2) == ' ') {
					if (*(p - 1) == 'z') {
						opbuf[0] = 0xcc;
					} else if (*(p-1) == 'c') {
						opbuf[0] = 0xdc;
					} else {
						free (buf_asm);
						return 0;
					}
				} else {
					free (buf_asm);
					return 0;
				}
				r_str_replace_in (p, strlen (p) + 1, ", ", ",", true);
				if (!*p || !p[1]) {
					free (buf_asm);
					return 0;
				}
				num = r_num_math (NULL, p + 1);
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
		len = gb_parse_cb1 (opbuf + 1, 5, buf_asm, 0x38)? 2: 0;
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
	free (buf_asm);

	const size_t num_bytes = sizeof (ut8) * len;
	// XXX dont use the heap to write 2 bytes
	*outbuf = malloc (num_bytes);
	if (!*outbuf) {
		return 0;
	}
	memcpy (*outbuf, opbuf, num_bytes);
	return len;
}
