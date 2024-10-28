/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_anal.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	struct {
		int narg;
		const char *op;
		const char *str;
		int args[MAXPSEUDOOPS];
	} ops[] = {
		// { 0, "ldw", "# = [#]", { 1, 2 } },
		{ 0, "ldf", "# = #", { 1, 2 } },
		{ 2, "ldw", "# = #", { 1, 2 } }, // ldw 0x00, x | x = [0x00]
		{ 2, "ld", "# = #", { 1, 2 } },  // ld a, 0x86  | a = [0x86]
		{ 3, "ld", "# = # + #", { 3, 2, 1 } },
		{ 0, "decw", "# --", { 1 } },
		{ 0, "clrw", "# = 0", { 1 } },
		{ 1, "clr", "# = 0", { 1 } },
		{ 0, "dec", "# --", { 1 } },
		{ 0, "ret", "return a;", {}},
		{ 0, "iret", "return;", {}},
		{ 2, "mov", "# = #", { 1, 2 } }, // MOVS are stores
		{ 2, "mul", "# *= #", { 1, 2 } },
		{ 1, "neg", "# = !#", { 1, 1 } }, // TODO carry = (res != 0)
		{ 2, "divw", "# /= #", { 1, 2 } },
		{ 2, "div", "# /= #", { 1, 2 } },
		{ 2, "or", "# |= #", { 1, 2 } },
		{ 2, "bcp", "res = # & (1 << #)", { 1, 2 } },
		{ 1, "cpl", "complement (#)", { 1, 1 } },
		{ 2, "and", "# |= #", { 1, 2 } },
		{ 1, "popw", "# = [sp] , sp += 2", { 1 } },
		{ 1, "pop", "# = [sp] , sp += 1", { 1 } },
		{ 1, "pushw", "sp -= 2, [sp] = #", { 1 } },
		{ 1, "push", "sp -= 1, [sp] = #", { 1 } },
		{ 1, "incw", "# ++", { 1 } },
		{ 1, "inc", "# ++", { 1 } },
		{ 0, "subw", "# -= #", { 1, 2 } },
		{ 0, "addw", "# += #", { 1, 2 } },
		{ 2, "bset", "# |= (1 << #)", { 1, 2 } },
		{ 2, "bres", "# &= ~(1 << #)", { 1, 2 } },
		{ 0, "jp", "goto #", { 1 } },
		{ 1, "rrwa", "a >>= #", { 1 } },
		{ 1, "rrc", "# = rotate_right(#, 1)", { 1, 1 } },
		{ 1, "rlc", "# = rotate_left(#, 1)", { 1, 1 } },
		{ 1, "srl", "# = shift_right(#, 1)", { 1, 1 } },
		{ 2, "xor", "# ^= #", { 1, 2 } },
		{ 1, "rlwa", "a <<= #", { 1 } },
		{ 1, "sra", "a >>= #", { 1 } },
		{ 1, "sla", "a <<= #", { 1 } },
		{ 2, "cpw", "res = # - #", { 1, 2 } },
		{ 2, "cp", "res = # - #", { 1, 2 } },
		{ 1, "tnz", "res = # < 1", { 1 } },
		{ 1, "jrsgt", "if (res > 0) goto #", { 1 } },
		{ 1, "jrslt", "if (res < 0) goto #", { 1 } },
		{ 1, "jrugt", "if (res > 0) goto #", { 1 } }, // TODO: support signed vs unsigned
		{ 1, "jrult", "if (res < 0) goto #", { 1 } }, // TODO: support signed vs unsigned
		{ 1, "jrule", "if (res <= 0) goto #", { 1 } },
		{ 0, "jrne", "if (res != 0) goto #", { 1 } },
		{ 0, "jreq", "if (res == 0) goto #", { 1 } },
		{ 0, "jrnc", "if (!res.carry) goto #", { 1 } },
		{ 0, "jrc", "if (res.carry) goto #", { 1 } },
		{ 0, "jra", "goto #", { 1 } },
		{ 3, "btjt", "if (# & (1 << #)) goto #", { 1, 2, 3 } },
		{ 3, "btjf", "if (!(# & (1 << #))) goto #", { 1, 2, 3 } },
		{ 0, "sllw", "# <<= 1", { 1 } },
		{ 1, "sll", "# <<= 1", { 1, 1 } },
		{ 2, "exgw", "# <=> #", {1, 2}},
		{ 2, "exg", "# <=> #", {1, 2}},
		{ 0, "slaw", "# <<= 1", { 1 } },
		{ 0, "srlw", "# >>= 1", { 1 } },
		{ 0, "srl", "# >>= 1", { 1 } },
		{ 0, "callr", "# ()", { 1 } },
		{ 0, "callf", "# ()", { 1 } },
		{ 0, "rvf", "res.overflow = 0", { } },
		{ 0, "sraw", "# >>= 1", { 1 } },
		{ 2, "add", "# += #", { 1, 2 } },
		{ 2, "sub", "# -= #", { 1, 2 } },
		{ 1, "int", "goto #", { 1 } }, // goto interrupt
		{ 2, "sbc", "# -= #", { 1, 2 } }, // carry
		{ 0, NULL }
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
			if (newstr) {
				d = 0;
				j = 0;
				ch = ops[i].str[j];
				for (j = 0, k = 0; ch != '\0'; j++, k++) {
					ch = ops[i].str[j];
					if (ch == '#') {
						if (d >= MAXPSEUDOOPS) {
							// XXX Shouldn't ever happen...
							continue;
						}
						int idx = ops[i].args[d];
						d++;
						if (idx <= 0) {
							// XXX Shouldn't ever happen...
							continue;
						}
						const char *w = argv[idx];
						if (w) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ch;
					}
				}
				newstr[k] = '\0';
			}
			// r_str_replace_char (newstr, '{', '(');
			// r_str_replace_char (newstr, '}', ')');
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat (newstr, argv[i]);
		strcat (newstr, (!i || i == argc - 1)? " " : ",");
	}
	return false;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256], w4[256];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;

	if (len >= sizeof (w0)) {
		return false;
	}
	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);
#if 0
	buf = r_str_replace (buf, "(0", "0", true);
	buf = r_str_replace (buf, "p)", "p", true);
	buf = r_str_replace (buf, "x)", "x", true);
#endif
#if 0
	r_str_replace_char (buf, '(', '{');
	r_str_replace_char (buf, ')', '}');
#endif
	const char *op0 = buf;
	if (!strcmp (op0, "ret") || !strcmp (op0, "iret")) {
		strcpy (str, "return a");
		return true;
	}
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = *w4 = '\0';
		ptr = strchr (buf, ' ');
		if (ptr) {
			*ptr = '\0';
			ptr = (char *)r_str_trim_head_ro (ptr + 1);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);
			optr = ptr;
			if (ptr && *ptr == '[') {
				ptr = strchr (ptr + 1, ']');
			}
			if (!ptr) {
				R_LOG_ERROR ("Unbalanced bracket");
				free (buf);
				return false;
			}
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				ptr = (char *)r_str_trim_head_ro (ptr + 1);
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					ptr = (char *)r_str_trim_head_ro (ptr + 1);
					strncpy (w2, optr, sizeof (w2) - 1);
					strncpy (w3, ptr, sizeof (w3) - 1);
					optr = ptr;
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						ptr = (char *)r_str_trim_head_ro (ptr + 1);
						strncpy (w3, optr, sizeof (w3) - 1);
						strncpy (w4, ptr, sizeof (w4) - 1);
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 5; i++) {
				if (wa[i][0]) {
					nw++;
				}
			}
			replace (nw, wa, str);
		}
	}
	free (buf);
	r_str_fixspaces (str);
	return true;
}

RParsePlugin r_parse_plugin_stm8_pseudo = {
	.name = "stm8.pseudo",
	.desc = "STM8 pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_stm8_pseudo,
	.version = R2_VERSION
};
#endif
