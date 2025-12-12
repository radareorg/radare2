/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_util.h>

// Generic AT&T to Intel syntax conversion
// This handles the common cases that work across architectures:
// - Remove % prefix from registers
// - Remove $ prefix from immediates
// - Swap operand order (AT&T: src, dst -> Intel: dst, src)
// - Convert memory addressing ( ) to [ ]

// instructions that take 2 operands and need swap (src, dst -> dst, src)
static const char *ops_2swap[] = {
	"mov", "movl", "movq", "movb", "movw", "movabs",
	"add", "addl", "addq", "addb", "addw",
	"sub", "subl", "subq", "subb", "subw",
	"and", "andl", "andq", "andb", "andw",
	"or", "orl", "orq", "orb", "orw",
	"xor", "xorl", "xorq", "xorb", "xorw",
	"cmp", "cmpl", "cmpq", "cmpb", "cmpw",
	"test", "testl", "testq", "testb", "testw",
	"lea", "leal", "leaq",
	"imul", "imull", "imulq",
	"shl", "shll", "shlq", "shlb", "shlw",
	"shr", "shrl", "shrq", "shrb", "shrw",
	"sar", "sarl", "sarq", "sarb", "sarw",
	"sal", "sall", "salq", "salb", "salw",
	"rol", "roll", "rolq", "rolb", "rolw",
	"ror", "rorl", "rorq", "rorb", "rorw",
	"adc", "adcl", "adcq", "adcb", "adcw",
	"sbb", "sbbl", "sbbq", "sbbb", "sbbw",
	"bt", "btl", "btq",
	"bts", "btsl", "btsq",
	"btr", "btrl", "btrq",
	"btc", "btcl", "btcq",
	"xchg", "xchgl", "xchgq", "xchgb", "xchgw",
	"movzx", "movzxl", "movzxq", "movzxb", "movzxw",
	"movsx", "movsxl", "movsxq", "movsxb", "movsxw",
	"movzbl", "movzbq", "movzbw",
	"movsbl", "movsbq", "movsbw",
	"movzwl", "movzwq",
	"movswl", "movswq",
	"movslq",
	"cmova", "cmovae", "cmovb", "cmovbe", "cmovc",
	"cmove", "cmovg", "cmovge", "cmovl", "cmovle",
	"cmovna", "cmovnae", "cmovnb", "cmovnbe", "cmovnc",
	"cmovne", "cmovng", "cmovnge", "cmovnl", "cmovnle",
	"cmovno", "cmovnp", "cmovns", "cmovnz",
	"cmovo", "cmovp", "cmovpe", "cmovpo", "cmovs", "cmovz",
	NULL
};

// instructions that take 1 operand (no swap needed)
static const char *ops_1[] = {
	"push", "pushl", "pushq", "pushw",
	"pop", "popl", "popq", "popw",
	"inc", "incl", "incq", "incb", "incw",
	"dec", "decl", "decq", "decb", "decw",
	"neg", "negl", "negq", "negb", "negw",
	"not", "notl", "notq", "notb", "notw",
	"mul", "mull", "mulq", "mulb", "mulw",
	"div", "divl", "divq", "divb", "divw",
	"idiv", "idivl", "idivq", "idivb", "idivw",
	"call", "calll", "callq",
	"jmp", "jmpl", "jmpq",
	"ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jrcxz",
	"je", "jg", "jge", "jl", "jle",
	"jna", "jnae", "jnb", "jnbe", "jnc",
	"jne", "jng", "jnge", "jnl", "jnle",
	"jno", "jnp", "jns", "jnz",
	"jo", "jp", "jpe", "jpo", "js", "jz",
	"loop", "loope", "loopne", "loopz", "loopnz",
	"seta", "setae", "setb", "setbe", "setc",
	"sete", "setg", "setge", "setl", "setle",
	"setna", "setnae", "setnb", "setnbe", "setnc",
	"setne", "setng", "setnge", "setnl", "setnle",
	"setno", "setnp", "setns", "setnz",
	"seto", "setp", "setpe", "setpo", "sets", "setz",
	"int",
	NULL
};

// instructions that take 0 operands
static const char *ops_0[] = {
	"ret", "retl", "retq",
	"leave", "leavel", "leaveq",
	"nop", "nopl", "nopq", "nopw",
	"hlt",
	"int3",
	"syscall",
	"sysret",
	"clc", "stc", "cmc",
	"cld", "std",
	"cli", "sti",
	"pushf", "pushfl", "pushfq",
	"popf", "popfl", "popfq",
	"cbw", "cwde", "cdqe",
	"cwd", "cdq", "cqo",
	"lahf", "sahf",
	NULL
};

static bool is_in_list(const char *op, const char **list) {
	int i;
	for (i = 0; list[i]; i++) {
		if (!strcmp (list[i], op)) {
			return true;
		}
	}
	return false;
}

// strip AT&T size suffix (l, q, b, w) from instruction if not in known lists
static void strip_size_suffix(char *op) {
	size_t len = strlen (op);
	if (len > 1) {
		char last = op[len - 1];
		if (last == 'l' || last == 'q' || last == 'b' || last == 'w') {
			// check if stripping would give a valid base instruction
			char base[32];
			r_str_ncpy (base, op, sizeof (base));
			base[len - 1] = '\0';
			// only strip if it's a known suffixed instruction pattern
			if (is_in_list (op, ops_2swap) || is_in_list (op, ops_1) || is_in_list (op, ops_0)) {
				// keep as is, it's already recognized
			} else {
				// try to see if base form exists
				char suffixed[32];
				snprintf (suffixed, sizeof (suffixed), "%sl", base);
				if (is_in_list (suffixed, ops_2swap) || is_in_list (suffixed, ops_1)) {
					op[len - 1] = '\0';
				}
			}
		}
	}
}

static int replace(int argc, const char *argv[], char *newstr) {
	if (argc < 1 || !argv[0]) {
		return false;
	}
	char op[32];
	r_str_ncpy (op, argv[0], sizeof (op));
	r_str_case (op, false);
	strip_size_suffix (op);

	if (is_in_list (argv[0], ops_0) || is_in_list (op, ops_0)) {
		// 0 operand instruction
		if (newstr) {
			strcpy (newstr, op);
		}
		return true;
	}

	if (argc >= 2 && (is_in_list (argv[0], ops_1) || is_in_list (op, ops_1))) {
		// 1 operand instruction
		if (newstr) {
			snprintf (newstr, 256, "%s %s", op, argv[1]);
		}
		return true;
	}

	if (argc >= 3 && (is_in_list (argv[0], ops_2swap) || is_in_list (op, ops_2swap))) {
		// 2 operand instruction - swap operands (ATT: src, dst -> Intel: dst, src)
		if (newstr) {
			snprintf (newstr, 256, "%s %s, %s", op, argv[2], argv[1]);
		}
		return true;
	}

	// fallback: swap operands for unknown 2-operand instructions
	if (argc >= 3 && newstr) {
		snprintf (newstr, 256, "%s %s, %s", op, argv[2], argv[1]);
		return true;
	}

	// single operand fallback
	if (argc == 2 && newstr) {
		snprintf (newstr, 256, "%s %s", op, argv[1]);
		return true;
	}

	// no operands fallback
	if (argc == 1 && newstr) {
		strcpy (newstr, op);
		return true;
	}

	return false;
}

/**
 * \brief Convert AT&T assembly syntax to Intel syntax
 * \param att_str The AT&T syntax assembly string
 * \return Newly allocated Intel syntax string, or NULL on failure. Caller must free.
 *
 * This function handles the common AT&T to Intel conversion rules:
 * - Removes % prefix from register names
 * - Removes $ prefix from immediate values
 * - Swaps operand order (AT&T: src, dst -> Intel: dst, src)
 * - Converts memory addressing from offset(base) to [base+offset]
 * - Strips AT&T size suffixes (l, q, b, w) from instructions
 */
R_API char *r_str_att2intel(const char *att_str) {
	char w0[64], w1[64], w2[64], w3[64];
	int i;

	if (R_STR_ISEMPTY (att_str)) {
		return NULL;
	}

	char *buf = strdup (att_str);
	if (!buf) {
		return NULL;
	}
	r_str_trim_head (buf);

	// handle comments
	char *ptr = strchr (buf, '#');
	if (ptr) {
		*ptr = 0;
		r_str_trim (buf);
	}

	// skip directives and labels
	if (*buf == '.' || (strlen (buf) > 0 && buf[strlen (buf) - 1] == ':')) {
		free (buf);
		return strdup (att_str);
	}

	// remove AT&T prefixes: $ for immediates, % for registers
	r_str_replace_char (buf, '$', 0);
	r_str_replace_char (buf, '%', 0);
	r_str_replace_char (buf, '\t', ' ');

	// handle memory addressing: convert ( ) to [ ]
	// ATT: offset(base,index,scale) -> Intel: [base+index*scale+offset]
	r_str_replace_char (buf, '(', '[');
	r_str_replace_char (buf, ')', ']');

	// handle displacement in memory operands like 8(%rsp) -> [rsp+8]
	ptr = strchr (buf, '[');
	if (ptr) {
		// find the displacement before the bracket
		char *start = ptr;
		while (start > buf && (isdigit ((unsigned char)*(start - 1)) || *(start - 1) == '-' || *(start - 1) == '+')) {
			start--;
		}
		if (start < ptr && start > buf && *(start - 1) != ' ' && *(start - 1) != ',') {
			// skip this case, it's part of an operand name
		} else if (start < ptr) {
			// there's a displacement
			int disp = atoi (start);
			if (disp != 0) {
				// find the closing bracket
				char *close = strchr (ptr, ']');
				if (close) {
					char inner[64] = {0};
					size_t inner_len = close - ptr - 1;
					if (inner_len < sizeof (inner)) {
						strncpy (inner, ptr + 1, inner_len);
						inner[inner_len] = '\0';
						char *rest = strdup (close + 1);
						// rebuild: [inner+disp]rest
						size_t avail = strlen (att_str) + 64 - (start - buf);
						snprintf (start, avail, "[%s%+d]%s", inner, disp, rest ? rest : "");
						free (rest);
					}
				}
			}
		}
	}

	char *str = NULL;
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = 0;

		// find instruction
		ptr = buf;
		while (*ptr && !isspace ((unsigned char)*ptr)) {
			ptr++;
		}
		size_t oplen = ptr - buf;
		if (oplen >= sizeof (w0)) {
			oplen = sizeof (w0) - 1;
		}
		strncpy (w0, buf, oplen);
		w0[oplen] = '\0';

		// skip whitespace after instruction
		while (*ptr && isspace ((unsigned char)*ptr)) {
			ptr++;
		}

		// parse operands
		if (*ptr) {
			// find first comma
			char *comma = strchr (ptr, ',');
			if (comma) {
				size_t len = comma - ptr;
				if (len >= sizeof (w1)) {
					len = sizeof (w1) - 1;
				}
				strncpy (w1, ptr, len);
				w1[len] = '\0';
				r_str_trim (w1);

				// move to second operand
				ptr = comma + 1;
				while (*ptr && isspace ((unsigned char)*ptr)) {
					ptr++;
				}

				// find second comma for potential third operand
				comma = strchr (ptr, ',');
				if (comma) {
					len = comma - ptr;
					if (len >= sizeof (w2)) {
						len = sizeof (w2) - 1;
					}
					strncpy (w2, ptr, len);
					w2[len] = '\0';
					r_str_trim (w2);

					// third operand
					ptr = comma + 1;
					while (*ptr && isspace ((unsigned char)*ptr)) {
						ptr++;
					}
					r_str_ncpy (w3, ptr, sizeof (w3));
					r_str_trim (w3);
				} else {
					r_str_ncpy (w2, ptr, sizeof (w2));
					r_str_trim (w2);
				}
			} else {
				// single operand
				r_str_ncpy (w1, ptr, sizeof (w1));
				r_str_trim (w1);
			}
		}

		const char *wa[] = { w0, w1, w2, w3 };
		int nw = 0;
		for (i = 0; i < 4; i++) {
			if (wa[i][0] != '\0') {
				nw++;
			}
		}
		str = malloc (strlen (att_str) + 256);
		if (str) {
			str[0] = '\0';
			replace (nw, wa, str);
		}
	}
	free (buf);
	return str;
}
