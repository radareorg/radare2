/* radare - LGPL - Copyright 2020 - pancake */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

// https://www.renesas.com/us/en/doc/products/mpumcu/doc/v850/r01us0037ej0100_v850e2.pdf

static int replace(int argc, const char *argv[], char *newstr) {
	int i, j, k;
	struct {
		int narg;
		char *op;
		char *str;
	} ops[] = {
		{0, "ei", "enable-interrupts"},
		{0, "di", "disable-interrupts"},
		{0, "reti", "ret"},
		{2, "ld.hu", "2 = 1"},
		{1, "zxb", "1 = O"},
		{1, "zxh", "1 = O"},
		{1, "zxw", "1 = O"},
		{2, "set1", "2 |= (I << 2)"},
		{2, "clr1", "2 &= ~(I << 2)"},
		{2, "sld.w", "2 = (word) 1"},
		{2, "sld.h", "2 = (half) 1"},
		{2, "sld.b", "2 = (byte) 1"},
		{2, "ld.bu", "2 = 1"},
		{2, "ld.w", "2 = (word) 1"},
		{2, "ld.h", "2 = (half) 1"},
		{2, "ld.b", "2 = (byte) 1"},
		{2, "st.h", "2 = (half) 1"},
		{2, "st.w", "2 = (word) 1"},
		{2, "st.b", "2 = (byte) 1"},
		{2, "sst.w", "2 = (word) 1"},
		{2, "sst.h", "2 = (half) 1"},
		{2, "sst.b", "2 = (byte) 1"},
		{2, "stsr", "2 = 1"},
		{2, "ldsr", "2 = 1"},
		{2, "and", "3 = 2 & 1"},
		{3, "andi", "3 = 2 & 1"},
		{2, "add", "2 += 1"},
		{3, "addi", "3 = 2 + 1"},
		{2, "sub", "2 -= 1"},
		{2, "divh", "2 /= 1"},
		{3, "divh", "3 = 2 / 1"},
		{2, "mulh", "2 *= 1"},
		{3, "mul", "3 = 2 * 1"},
		{3, "mulf.s", "3 = 2 * 1"},
		{2, "shl", "2 <<= 1"},
		{2, "shr", "2 >>= 1"},
		{2, "xor", "2 ^= 1"},
		{3, "xori", "3 = 1 ^ 2"},
		{2, "tst", "2 == 1"},
		{2, "tst1", "2 == 1"},
		{1, "jr", "jmp 1"},
		{2, "cmp", "2 == 1"},
		{4, "cmov", "4 == 1 ? 2 : 3"},
		{2, "mov", "2 = 1"},
		{3, "movhi", "3 = (1 << XX) + 2"},
		{3, "movea", "3 = 1 & 2"},
		{3, "ori", "3 = 1 | 2"},
		{2, "jarl", "call 1 # 2"},
		{0, NULL}
	};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp (ops[i].op, argv[0])) {
			for (j = k = 0; ops[i].str[j]; j++, k++) {
				if (IS_DIGIT (ops[i].str[j])) {
					int index = ops[i].str[j] - '0';
					if (index >= 0 && index < argc) {
						const char *w = argv[index];
						if (!R_STR_ISEMPTY (w)) {
							r_str_cpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					}
				} else if (ops[i].str[j] == 'X') {
					newstr[k] = '1';
					k++;
					j++;
					newstr[k] = '6';
				} else if (ops[i].str[j] == 'I') {
					newstr[k] = '1';
				} else if (ops[i].str[j] == 'O') {
					newstr[k] = '0';
				} else {
					newstr[k] = ops[i].str[j];
				}
			}
			newstr[k] = '\0';
			if (argc == 4 && argv[2][0] == '[') {
				strcat (newstr + k, "+");
				strcat (newstr + k + 3, argv[2]);
			}
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat (newstr, argv[i]);
		strcat (newstr, (i == 0 || i == argc - 1) ? " " : ",");
	}
	r_str_replace_in (newstr, strlen (newstr), "+= -", "-= ", true);
	r_str_replace_in (newstr, strlen (newstr), " + -", " - ", true);
//	strcpy (newstr, a);
	return false;
}

static char *reorder(char *buf) {
	char *arr = strstr (buf, "-0x");
	if (!arr) {
		arr = strstr (buf, "0x");
	}
	if (!arr) {
		return buf;
	}
	char *par = strchr (arr + 2, '[');
	if (par) {
		char arg[32], reg[32];
		char *end = strchr (par + 1, ']');
		if (end) {
			r_str_ncpy (reg, par + 1, end - par);
			r_str_ncpy (arg, arr, par - arr + 1);
			sprintf (buf, "%s[%s]", reg, arg);
		}
	}
	return buf;
}

static void guard_braces (char *buf) {
	bool braces = false;
	char *p = buf;
	for (;*p;p++) {
		switch (*p) {
		case '{':
			braces = true;
			break;
		case '}':
			braces = false;
			break;
		case ',':
			if (braces) {
				*p = ' ';
			}
			break;
		}
	}
}

static int parse(RParse *p, const char *data, char *str) {
	if (!strncmp (data, "|| ", 3)) {
		data += 3;
	}
	if (R_STR_ISEMPTY (data)) {
		*str = 0;
		return false;
	}

	char *buf = strdup (data);
	guard_braces (buf);
	RListIter *iter;
	char *sp = strchr (buf, ' ');
	size_t nw = 1;
	const char *wa[5] = {0};
	wa[0] = buf;
	RList *list = NULL;
	if (sp) {
		*sp++ = 0;
		list = r_str_split_list (sp, ",", 0);
		char *w;
		r_list_foreach (list, iter, w) {
			wa[nw] = reorder(w);
			nw++;
			if (nw == 5) {
				break;
			}
		}
	}
	replace (nw, wa, str);

	free (buf);
	r_list_free (list);

	return true;
}

RParsePlugin r_parse_plugin_v850_pseudo = {
	.name = "v850.pseudo",
	.desc = "v850 pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_v850_pseudo,
	.version = R2_VERSION};
#endif
