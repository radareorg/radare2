/* radare - LGPL - Copyright 2002-2025 - pancake, condret, unlogic */
/* Based on work from Bas Wijnen <wijnen@debian.org>, Jan Wilmans <jw@dds.nl> */

#include <r_arch.h>
#include "z80_tab.h"

#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "asm.z80"

#include "z80asm.h"

static const char *delspc(const char *ptr);
static int rd_expr(PluginData *pd, const char **p, char delimiter, int *valid, int level, bool print_errors);
static int rd_label(PluginData *pd, const char **p, bool *exists, struct label **previous, int level, bool print_errors);
static int rd_character(PluginData *pd, const char **p, int *valid, bool print_errors);
static int compute_ref(PluginData *pd, struct reference *ref, int allow_invalid);

#define write_one_byte(x, y) pd->obuf[pd->obuflen++] = x
#define wrtb(x) pd->obuf[pd->obuflen++] = x

/* Z80 opcode encoding constants */
#define Z80_HL_ENCODING 6 /* [hl] register encoding for bit/res/set/shift ops */
#define Z80_BIT_BASE 0x40 /* Base opcode for BIT instruction */
#define Z80_RES_BASE 0x80 /* Base opcode for RES instruction */
#define Z80_SET_BASE 0xC0 /* Base opcode for SET instruction */
#define Z80_INDEXED_PREFIX_CB 0xCB /* Indexed addressing CB prefix */
#define Z80_INDEXED_PREFIX_ED 0xED /* Extended instructions prefix */
#define Z80_RL_HL 0x16 /* RL [hl] opcode */
#define Z80_SLA_HL 0x26 /* SLA [hl] opcode */
#define Z80_SLL_HL 0x36 /* SLL [hl] opcode */

/* Helper function to emit indexed bit/shift operation */
static inline void emit_indexed_bitop(PluginData *pd, int base_opcode, int bit_num) {
	char n = r_num_math (NULL, pd->indexjmp);
	wrtb (pd->indexed);
	wrtb (Z80_INDEXED_PREFIX_CB);
	wrtb (n);
	wrtb (base_opcode + (bit_num << 3) + Z80_HL_ENCODING);
	pd->indexed = 0;
}

/* Helper function to emit indexed shift operation */
static inline void emit_indexed_shift(PluginData *pd, int hl_opcode) {
	char n = r_num_math (NULL, pd->indexjmp);
	wrtb (pd->indexed);
	wrtb (Z80_INDEXED_PREFIX_CB);
	wrtb (n);
	wrtb (hl_opcode);
	pd->indexed = 0;
}

/* global variables */
/* mnemonics, used as argument to indx () in assemble */
static const char *mnemonics[] = {
	"call", "cpdr", "cpir", "djnz", "halt", "indr", "inir", "lddr", "ldir",
	"otdr", "otir", "outd", "outi", "push", "reti", "retn", "rlca", "rrca",
	"defb", "defw", "defs", "defm",
	"adc", "add", "and", "bit", "ccf", "cpd", "cpi", "cpl", "daa", "dec", "equ",
	"exx", "inc", "ind", "ini", "ldd", "ldi", "neg", "nop", "out", "pop",
	"res", "ret", "rla", "rlc", "rld", "rra", "rrc", "rrd", "rst", "sbc",
	"scf", "set", "sla", "sll", "sli", "sra", "srl", "sub", "xor", "org",
	"cp", "di", "ei", "ex", "im", "in", "jp", "jr", "ld", "or", "rl", "rr",
	"db", "dw", "ds", "dm",
	"include", "incbin", "if", "else", "endif", "end", "macro", "endm",
	"seek", NULL
};

/* reading expressions. The following operators are supported
 * in order of precedence, with function name:
 * expr? expr: expr do_rd_expr
 * |              rd_expr_or
 * ^              rd_expr_xor
 * &              rd_expr_and
 * == !=          rd_expr_equal
 * >= <= > <      rd_expr_unequal
 * << >>          rd_expr_shift
 * + - (binary)   rd_term
 * * / %          rd_factor
 * ~ + - (unary)  rd_factor
 */

static int do_rd_expr(PluginData *pd, const char **p, char delimiter, int *valid, int level,
	int *check, bool print_errors);

static int
rd_number(PluginData *pd, const char **p, const char **endp, int base) {
	int result = 0, i;
	char *c, num[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	num[base] = '\0';
	*p = delspc (*p);
	while (**p && (c = strchr (num, tolower ((const unsigned char)**p)))) {
		i = c - num;
		result = result * base + i;
		(*p)++;
	}
	if (endp) {
		*endp = *p;
	}
	*p = delspc (*p);
	return result;
}

static int
rd_otherbasenumber(PluginData *pd, const char **p, int *valid, bool print_errors) {
	(*p)++;
	if (!**p) {
		if (valid) {
			*valid = 0;
		}
		return 0;
	}
	if (**p == '0' || !isalnum ((const unsigned char)**p)) {
		if (valid) {
			*valid = 0;
		}
		return 0;
	}
	char c = **p;
	(*p)++;
	if (isalpha ((const unsigned char)**p)) {
		return rd_number (pd, p, NULL, tolower ((unsigned char)c) - 'a' + 1);
	}
	return rd_number (pd, p, NULL, c - '0' + 1);
}

static int rd_character(PluginData *pd, const char **p, int *valid, bool print_errors) {
	int i = **p;
	if (!i) {
		if (valid) {
			*valid = 0;
		}
		return 0;
	}
	if (i == '\\') {
		(*p)++;
		if (**p >= '0' && **p <= '7') {
			int b, num_digits;
			i = 0;
			if ((*p)[1] >= '0' && (*p)[1] <= '7') {
				if (**p <= '3' && (*p)[2] >= '0' && (*p)[2] <= '7') {
					num_digits = 3;
				} else {
					num_digits = 2;
				}
			} else {
				num_digits = 1;
			}
			for (b = 0; b < num_digits; b++) {
				int bit = (*p)[num_digits - 1 - b] - '0';
				i += (1 << (b * 3)) * bit;
			}
			*p += num_digits;
		} else {
			switch (**p) {
			case 'n':
				i = 10;
				break;
			case 'r':
				i = 13;
				break;
			case 't':
				i = 9;
				break;
			case 'a':
				i = 7;
				break;
			case '\'':
				if (valid) {
					*valid = 0;
				}
				return 0;
			case 0:
				if (valid) {
					*valid = 0;
				}
				return 0;
			default:
				i = **p;
			}
			(*p)++;
		}
	} else {
		(*p)++;
	}
	return i;
}

static int
check_label(PluginData *pd, struct label *labels, const char **p, struct label **ret,
	struct label **previous, int force_skip) {
	*p = delspc (*p);
	const char *c;
	for (c = *p; isalnum ((const unsigned char)*c) || *c == '_' || *c == '.'; c++) {
	}
	unsigned s2 = c - *p;
	struct label *l;
	for (l = labels; l; l = l->next) {
		unsigned s1 = strlen (l->name);
		unsigned s = s1 < s2? s1: s2;
		int cmp = strncmp (l->name, *p, s);
		if (cmp > 0 || (cmp == 0 && s1 > s)) {
			if (force_skip) {
				*p = c;
			}
			return 0;
		}
		if (cmp < 0 || s2 > s) {
			if (previous) {
				*previous = l;
			}
			continue;
		}
		*p = c;
		/* if label is not valid, compute it */
		if (l->ref) {
			compute_ref (pd, l->ref, 1);
			if (!l->ref->done) {
				/* label was not valid, and isn't computable.  tell the
				 * caller that it doesn't exist, so it will try again later.
				 * Set ret to show actual existence.  */
				*ret = l;
				return 0;
			}
		}
		*ret = l;
		return 1;
	}
	if (force_skip) {
		*p = c;
	}
	return 0;
}

static int rd_label(PluginData *pd, const char **p, bool *exists, struct label **previous, int level, bool print_errors) {
	struct label *l = NULL;
	int s;
	if (exists) {
		*exists = false;
	}
	if (previous) {
		*previous = NULL;
	}
	for (s = level; s >= 0; s--) {
		if (check_label (pd, pd->stack[s].labels, p, &l,
			(**p == '.' && s == pd->sp)? previous: NULL, 0)) {
			break;
		}
	}
	if (s < 0) {
		/* label does not exist, or is invalid */
		return (int) (bool)l;
	}
	if (exists) {
		*exists = true;
	}
	return l->value;
}

static inline int rd_suffixed_number(PluginData *pd, const char **p, int base, int *valid, bool print_errors) {
	const char *p0 = *p, *p1, *p2;
	int v;
	rd_number (pd, p, &p1, 36); /* Advance to end of numeric string */
	p1--; /* Last character in numeric string */
	switch (*p1) {
	case 'h':
	case 'H':
		base = 16;
		break;
	case 'b':
	case 'B':
		base = 2;
		break;
	case 'o':
	case 'O':
	case 'q':
	case 'Q':
		base = 8;
		break;
	case 'd':
	case 'D':
		base = 10;
		break;
	default:
		p1++;
		break;
	}
	v = rd_number (pd, &p0, &p2, base);
	if (p1 != p2) {
		if (valid) {
			*valid = 0;
		}
	}
	return v;
}

static inline int rd_ampersand_number(PluginData *pd, const char **p, int *valid, bool print_errors) {
	int base;
	(*p)++;
	switch (**p) {
	case 'h':
	case 'H':
		base = 0x10;
		break;
	case 'o':
	case 'O':
		base = 010;
		break;
	case 'b':
	case 'B':
		base = 2;
		break;
	default:
		if (valid) {
			*valid = 0;
		}
		return 0;
	}
	(*p)++;
	return rd_number (pd, p, NULL, base);
}

static int rd_value(PluginData *pd, const char **p, int *valid, int level, int *check, bool print_errors) {
	int sign = 1, not= 0, v;
	const char *p0, *p2;
	*p = delspc (*p);
	while (**p && strchr ("+-~", **p)) {
		if (**p == '-') {
			sign = -sign;
		} else if (**p == '~') {
			not= ~not;
		}
		(*p)++;
		*p = delspc (*p);
	}
	int base = 10; /* Default base for suffixless numbers */

	/* Check for parenthesis around full expression: not if no parenthesis */
	if (**p != '(') {
		*check = 0;
	}

	bool exist;
	int retval;
	char quote;
	int dummy_check;
	switch (**p) {
	case '(':
		(*p)++;
		dummy_check = 0;
		retval = not ^ (sign *do_rd_expr (pd, p, ')', valid, level, &dummy_check,
			print_errors));
		++*p;
		return retval;
	case '0':
		if ((*p)[1] == 'x') {
			(*p) += 2;
			return not ^ (sign *rd_number (pd, p, NULL, 0x10));
		}
		base = 8; /* If first digit it 0, assume octal unless suffix */
		/* fall through */
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return not ^ (sign *rd_suffixed_number (pd, p, base, valid, print_errors));
	case '$':
		++*p;
		*p = delspc (*p);
		p0 = *p;
		v = rd_number (pd, &p0, &p2, 0x10);
		if (p2 == *p) {
			v = pd->baseaddr;
		} else {
			*p = p2;
		}
		return not ^ (sign *v);
	case '%':
		(*p)++;
		return not ^ (sign *rd_number (pd, p, NULL, 2));
	case '\'':
	case '"':
		quote = **p;
		++*p;
		retval = not ^ (sign *rd_character (pd, p, valid, print_errors));
		if (**p != quote) {
			if (valid) {
				*valid = 0;
			}
			return 0;
		}
		++*p;
		return retval;
	case '@':
		return not ^ (sign *rd_otherbasenumber (pd, p, valid, print_errors));
	case '?':
		rd_label (pd, p, &exist, NULL, level, 0);
		return not ^ (sign *exist);
	case '&':
		return not ^ (sign *rd_ampersand_number (pd, p, valid, print_errors));
	default:
		exist = 1;
		int value = rd_label (pd, p, valid? &exist: NULL, NULL, level, print_errors);
		if (!exist) {
			*valid = 0;
		}
		return not ^ (sign *value);
	}
}

static int
rd_factor(PluginData *pd, const char **p, int *valid, int level, int *check, int print_errors) {
	/* read a factor of an expression */
	int result = rd_value (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	while (**p == '*' || **p == '/') {
		*check = 0;
		if (**p == '*') {
			(*p)++;
			result *= rd_value (pd, p, valid, level, check, print_errors);
		} else if (**p == '/') {
			(*p)++;
			int value = rd_value (pd, p, valid, level, check, print_errors);
			if (value == 0) {
				return -1;
			}
			result /= value;
		}
		*p = delspc (*p);
	}
	return result;
}

static int rd_term(PluginData *pd, const char **p, int *valid, int level, int *check, int print_errors) {
	/* read a term of an expression */
	int result = rd_factor (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	while (**p == '+' || **p == '-') {
		*check = 0;
		if (**p == '+') {
			(*p)++;
			result += rd_factor (pd, p, valid, level, check, print_errors);
		} else if (**p == '-') {
			(*p)++;
			result -= rd_factor (pd, p, valid, level, check, print_errors);
		}
		*p = delspc (*p);
	}
	return result;
}

static int rd_expr_shift(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_term (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	while ((**p == '<' || **p == '>') && (*p)[1] == **p) {
		*check = 0;
		if (**p == '<') {
			(*p) += 2;
			result <<= rd_term (pd, p, valid, level, check, print_errors);
		} else if (**p == '>') {
			(*p) += 2;
			result >>= rd_term (pd, p, valid, level, check, print_errors);
		}
		*p = delspc (*p);
	}
	return result;
}

static int rd_expr_unequal(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_expr_shift (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '<' && (*p)[1] == '=') {
		*check = 0;
		(*p) += 2;
		return result <= rd_expr_unequal (pd, p, valid, level, check, print_errors);
	} else if (**p == '>' && (*p)[1] == '=') {
		*check = 0;
		(*p) += 2;
		return result >= rd_expr_unequal (pd, p, valid, level, check, print_errors);
	}
	if (**p == '<' && (*p)[1] != '<') {
		*check = 0;
		(*p)++;
		return result < rd_expr_unequal (pd, p, valid, level, check, print_errors);
	} else if (**p == '>' && (*p)[1] != '>') {
		*check = 0;
		(*p)++;
		return result > rd_expr_unequal (pd, p, valid, level, check, print_errors);
	}
	return result;
}

static int
rd_expr_equal(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_expr_unequal (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '=') {
		*check = 0;
		++*p;
		if (**p == '=') {
			++*p;
		}
		return result == rd_expr_equal (pd, p, valid, level, check, print_errors);
	} else if (**p == '!' && (*p)[1] == '=') {
		*check = 0;
		(*p) += 2;
		return result != rd_expr_equal (pd, p, valid, level, check, print_errors);
	}
	return result;
}

static int
rd_expr_and(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_expr_equal (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '&') {
		*check = 0;
		(*p)++;
		result &= rd_expr_and (pd, p, valid, level, check, print_errors);
	}
	return result;
}

static int
rd_expr_xor(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_expr_and (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '^') {
		*check = 0;
		(*p)++;
		result ^= rd_expr_xor (pd, p, valid, level, check, print_errors);
	}
	return result;
}

static int
rd_expr_or(PluginData *pd, const char **p, int *valid, int level, int *check,
	bool print_errors) {
	int result = rd_expr_xor (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '|') {
		*check = 0;
		(*p)++;
		result |= rd_expr_or (pd, p, valid, level, check, print_errors);
	}
	return result;
}

static int
do_rd_expr(PluginData *pd, const char **p, char delimiter, int *valid, int level, int *check,
	bool print_errors) {
	/* read an expression. delimiter can _not_ be '?' */
	*p = delspc (*p);
	if (!**p || **p == delimiter) {
		if (valid) {
			*valid = 0;
		}
		return 0;
	}
	int result = 0;
	result = rd_expr_or (pd, p, valid, level, check, print_errors);
	*p = delspc (*p);
	if (**p == '?') {
		*check = 0;
		(*p)++;
		if (result) {
			result = do_rd_expr (pd, p, ':', valid, level, check, print_errors);
			if (**p) {
				(*p)++;
			}
			do_rd_expr (pd, p, delimiter, valid, level, check, print_errors);
		} else {
			do_rd_expr (pd, p, ':', valid, level, check, print_errors);
			if (**p) {
				(*p)++;
			}
			result = do_rd_expr (pd, p, delimiter, valid, level, check,
				print_errors);
		}
	}
	*p = delspc (*p);
	if (**p && **p != delimiter) {
		if (valid) {
			*valid = 0;
		}
	}
	return result;
}

static int
rd_expr(PluginData *pd, const char **p, char delimiter, int *valid, int level,
	bool print_errors) {
	int check = 1;
	if (valid) {
		*valid = 1;
	}
	int result = do_rd_expr (pd, p, delimiter, valid, level, &check, print_errors);
	return result;
}

/* skip over spaces in string */
static inline const char *delspc(const char *ptr) {
	ptr = r_str_trim_head_ro (ptr);
	if (*ptr == ';') {
		ptr = "";
	}
	return ptr;
}

/* read away a comma, error if there is none */
static inline void rd_comma(const char **p) {
	*p = delspc (*p);
	if (**p != ',') {
		R_LOG_ERROR ("`,' expected. Remainder of line: %s", *p);
		return;
	}
	*p = delspc ((*p) + 1);
}

/* look ahead for a comma, no error if not found */
static inline int has_argument(const char **p) {
	const char *q = delspc (*p);
	return *q == ',';
}

/* During assembly, many literals are not parsed.  Instead, they are saved
 * until all labels are read.  After that, they are parsed.  This function
 * is used during assembly, to find the place where the command continues. */
static void skipword(PluginData *pd, const char **pos, char delimiter) {
	/* rd_expr will happily read the expression, and possibly return
	 * an invalid result.  It will update pos, which is what we need.  */
	/* Pass valid to allow using undefined labels without errors.  */
	int valid;
	rd_expr (pd, pos, delimiter, &valid, pd->sp, 0);
}

/* find any of the list[] entries as the start of ptr and return index */
static int indx(PluginData *pd, const char **ptr, const char **list, int error, const char **expr) {
	int i;
	*ptr = delspc (*ptr);
	if (!**ptr) {
		if (error) {
			R_LOG_ERROR ("unexpected end of line");
			return 0;
		} else {
			return 0;
		}
	}
	if (pd->comma > 1) {
		rd_comma (ptr);
	}
	for (i = 0; list[i]; i++) {
		const char *input = *ptr;
		const char *check = list[i];
		int had_expr = 0;
		if (!list[i][0]) {
			continue;
		}
		while (*check) {
			if (*check == ' ') {
				input = delspc (input);
			} else if (*check == '*') {
				*expr = input;
				pd->mem_delimiter = check[1];
				rd_expr (pd, &input, pd->mem_delimiter, NULL, pd->sp, 0);
				had_expr = 1;
			} else if (*check == '+') {
				if (*input == '+' || *input == '-') {
					*expr = input;
					pd->mem_delimiter = check[1];
					rd_expr (pd, &input, pd->mem_delimiter, NULL, pd->sp, 0);
				}
			} else if (*check == *input || (*check >= 'a' && *check <= 'z' && *check - 'a' + 'A' == *input)) {
				++input;
			} else {
				break;
			}

			++check;
		}
		if (*check || (isalnum ((const unsigned char)check[-1]) && isalnum ((const unsigned char)input[0]))) {
			continue;
		}
		if (had_expr) {
			input = delspc (input);
			if (*input && *input != ',') {
				continue;
			}
		}
		*ptr = input;
		pd->comma++;
		return i + 1;
	}
	return 0;
}

/* read a mnemonic */
static inline int readcommand(PluginData *pd, const char **p) {
	return indx (pd, p, mnemonics, 0, NULL);
}

/* try to read a label and optionally store it in the list */
static void readlabel(PluginData *pd, const char **p, int store) {
	const char *c, *d, *pos, *dummy;
	bool i;
	int j;
	struct label *previous;
	for (d = *p; *d && *d != ';'; d++) {
		;
	}
	for (c = *p; !strchr (" \r\n\t", *c) && c < d; c++) {
		;
	}
	pos = strchr (*p, ':');
	if (!pos || pos >= c) {
		return;
	}
	if (pos == *p) {
		R_LOG_ERROR ("`:' found without a label");
		return;
	}
	if (!store) {
		*p = pos + 1;
		return;
	}
	c = pos + 1;
	dummy = *p;
	j = rd_label (pd, &dummy, &i, &previous, pd->sp, 0);
	if (i || j) {
		R_LOG_ERROR ("duplicate definition of label %s", *p);
		*p = c;
		return;
	}

	*p = c;
}

static int compute_ref(PluginData *pd, struct reference *ref, int allow_invalid) {
	const char *ptr;
	int valid = 0;
	int backup_addr = pd->addr;
	int backup_baseaddr = pd->baseaddr;
	int backup_comma = pd->comma;
	int backup_file = pd->file;
	int backup_sp = pd->sp;
	pd->sp = ref->level;
	pd->addr = ref->addr;
	pd->baseaddr = ref->baseaddr;
	pd->comma = ref->comma;
	pd->file = ref->infile;
	ptr = ref->input;
	if (!ref->done) {
		ref->computed_value = rd_expr (pd, &ptr, ref->delimiter,
			allow_invalid? &valid: NULL,
			ref->level, 1);
		if (valid) {
			ref->done = 1;
		}
	}
	pd->sp = backup_sp;
	pd->addr = backup_addr;
	pd->baseaddr = backup_baseaddr;
	pd->comma = backup_comma;
	pd->file = backup_file;
	return ref->computed_value;
}

/* read a word from input and store it in readword. return 1 on success */
static int rd_word(PluginData *pd, const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	pd->readword = *p;
	pd->mem_delimiter = delimiter;
	skipword (pd, p, delimiter);
	return 1;
}

/* read a byte from input and store it in readbyte. return 1 on success */
static int rd_byte(PluginData *pd, const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	pd->readbyte = *p;
	pd->writebyte = 1;
	pd->mem_delimiter = delimiter;
	skipword (pd, p, delimiter);
	return 1;
}

/* read (SP), DE, or AF */
static inline int rd_ex1(PluginData *pd, const char **p) {
#define DE 2
#define AF 3
	const char *list[] = {
		"( sp )", "de", "af", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read first argument of IN */
static inline int rd_in(PluginData *pd, const char **p) {
#define A 8
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "f", "a", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read second argument of out (c),x */
static inline int rd_out(PluginData *pd, const char **p) {
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "0", "a", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read (c) or (nn) */
static int rd_nnc(PluginData *pd, const char **p) {
#define C 1
	int i;
	const char *list[] = {
		"( c )", "(*)", "a , (*)", NULL
	};
	i = indx (pd, p, list, 1, &pd->readbyte);
	if (i < 2) {
		return i;
	}
	return 2;
}

/* read (C) */
static inline int rd_c(PluginData *pd, const char **p) {
	const char *list[] = {
		"( c )", "( bc )", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read a or hl */
static inline int rd_a_hl(PluginData *pd, const char **p) {
#define HL 2
	const char *list[] = {
		"a", "hl", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read first argument of ld */
static int rd_ld(PluginData *pd, const char **p) {
#define ldBC 1
#define ldDE 2
#define ldHL 3
#define ldSP 4
#define ldIX 5
#define ldIY 6
#define ldB 7
#define ldC 8
#define ldD 9
#define ldE 10
#define ldH 11
#define ldL 12
#define ld_HL 13
#define ldA 14
#define ldI 15
#define ldR 16
#define ld_BC 17
#define ld_DE 18
#define ld_IX 19
#define ld_IY 20
#define ld_NN 21
	int i;
	const char *list[] = {
		"ixh", "ixl", "iyh", "iyl", "bc", "de", "hl", "sp", "ix",
		"iy", "b", "c", "d", "e", "h", "l", "( hl )", "a", "i",
		"r", "( bc )", "( de )", "( ix +)", "(iy +)", "(*)", NULL
	};
	const char *nn;
	i = indx (pd, p, list, 1, &nn);
	if (!i) {
		return 0;
	}
	if (i <= 2) {
		pd->indexed = 0xdd;
		return ldH + (i == 2);
	}
	if (i <= 4) {
		pd->indexed = 0xfd;
		return ldH + (i == 4);
	}
	i -= 4;
	if (i == ldIX || i == ldIY) {
		pd->indexed = i == ldIX? 0xDD: 0xFD;
		return ldHL;
	}
	if (i == ld_IX || i == ld_IY) {
		pd->indexjmp = nn;
		pd->indexed = i == ld_IX? 0xDD: 0xFD;
		return ld_HL;
	}
	if (i == ld_NN) {
		pd->readword = nn;
	}
	return i;
}

/* read first argument of JP */
static int rd_jp(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"nz", "z", "nc", "c", "po", "pe", "p", "m", "( ix )", "( iy )",
		"(hl)", NULL
	};
	i = indx (pd, p, list, 0, NULL);
	if (i < 9) {
		return i;
	}
	if (i == 11) {
		return -1;
	}
	pd->indexed = 0xDD + 0x20 *(i - 9);
	return -1;
}

/* read first argument of JR */
static inline int rd_jr(PluginData *pd, const char **p) {
	const char *list[] = {
		"nz", "z", "nc", "c", NULL
	};
	return indx (pd, p, list, 0, NULL);
}

/* read A */
static inline int rd_a(PluginData *pd, const char **p) {
	const char *list[] = {
		"a", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read bc,de,hl,af */
static int rd_stack(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"bc", "de", "hl", "af", "ix", "iy", NULL
	};
	i = indx (pd, p, list, 1, NULL);
	if (i < 5) {
		return i;
	}
	pd->indexed = 0xDD + 0x20 *(i - 5);
	return 3;
}

/* read b,c,d,e,h,l, (hl),a, (ix+nn), (iy+nn),nn
 * but now with extra hl or i[xy] (15) for add-instruction
 * and set variables accordingly */
static int rd_r_add(PluginData *pd, const char **p) {
#define addHL 15
	int i;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l",
		"( hl )", "a", "( ix +)", "( iy +)", "hl", "ix", "iy", "*", NULL
	};
	const char *nn;
	i = indx (pd, p, list, 0, &nn);
	if (i == 18) { /* expression */
		pd->readbyte = nn;
		pd->writebyte = 1;
		return 7;
	}
	if (i > 14) { /* hl, ix, iy */
		if (i > 15) {
			pd->indexed = 0xDD + 0x20 *(i - 16);
		}
		return addHL;
	}
	if (i <= 4) { /* i[xy][hl]  */
		pd->indexed = 0xdd + 0x20 *(i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9) {
		return i;
	}
	pd->indexed = 0xDD + 0x20 *(i - 9); /*(i[xy] +) */
	pd->indexjmp = nn;
	return 7;
}

/* read bc,de,hl, or sp */
static inline int rd_rr_(PluginData *pd, const char **p) {
	const char *list[] = {
		"bc", "de", "hl", "sp", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read bc,de,hl|ix|iy,sp. hl|ix|iy only if it is already indexed the same. */
static int rd_rrxx(PluginData *pd, const char **p) {
	const char *listx[] = {
		"bc", "de", "ix", "sp", NULL
	};
	const char *listy[] = {
		"bc", "de", "iy", "sp", NULL
	};
	const char *list[] = {
		"bc", "de", "hl", "sp", NULL
	};
	if (pd->indexed == 0xdd) {
		return indx (pd, p, listx, 1, NULL);
	}
	if (pd->indexed == 0xfd) {
		return indx (pd, p, listy, 1, NULL);
	}
	return indx (pd, p, list, 1, NULL);
}

/* read b,c,d,e,h,l, (hl),a, (ix+nn), (iy+nn),nn
 * and set variables accordingly */
static int rd_r(PluginData *pd, const char **p) {
	int i;
	const char *nn;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l", "( hl )",
		"a", "( ix +)", "( iy +)", "*", NULL
	};
	i = indx (pd, p, list, 0, &nn);
	if (i == 15) { /* expression */
		pd->readbyte = nn;
		pd->writebyte = 1;
		return 7;
	}
	if (i <= 4) {
		pd->indexed = 0xdd + 0x20 *(i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9) {
		return i;
	}
	pd->indexed = 0xDD + 0x20 *(i - 9);
	pd->indexjmp = nn;
	return 7;
}

/* like rd_r (), but without nn */
static int rd_r_(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx (pd, p, list, 1, &pd->indexjmp);
	if (i < 9) {
		return i;
	}
	pd->indexed = 0xDD + 0x20 *(i - 9);
	return 7;
}

/* read a number from 0 to 7, for bit, set or res */
static int rd_0_7(PluginData *pd, const char **p) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	int bit_num = **p - '0';
	if (bit_num < 0 || bit_num > 7) {
		return 0;
	}
	pd->bitsetres = *p;
	skipword (pd, p, ',');
	return bit_num + 1; /* return 1-8 to indicate bit 0-7 */
}

/* read long condition. do not error if not found. */
static inline int rd_cc(PluginData *pd, const char **p) {
	const char *list[] = {
		"nz", "z", "nc", "c", "po", "pe", "p", "m", NULL
	};
	return indx (pd, p, list, 0, NULL);
}

/* read long or short register */
static int rd_r_rr(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"iy", "ix", "sp", "hl", "de", "bc", "", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx (pd, p, list, 1, &pd->indexjmp);
	if (!i) {
		return 0;
	}
	if (i < 16 && i > 2) {
		return 7 - i;
	}
	if (i > 15) {
		pd->indexed = 0xDD + (i - 16) * 0x20;
		return -7;
	}
	pd->indexed = 0xDD + (2 - i) * 0x20;
	return 3;
}

/* read hl */
static inline int rd_hl(PluginData *pd, const char **p) {
	const char *list[] = {
		"hl", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read hl, ix, or iy */
static int rd_hlx(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"hl", "ix", "iy", NULL
	};
	i = indx (pd, p, list, 1, NULL);
	if (i < 2) {
		return i;
	}
	pd->indexed = 0xDD + 0x20 *(i - 2);
	return 1;
}

/* read af' */
static inline int rd_af_(PluginData *pd, const char **p) {
	const char *list[] = {
		"af'", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read 0 (1), 1 (3), or 2 (4) */
static inline int rd_0_2(PluginData *pd, const char **p) {
	const char *list[] = {
		"0", "", "1", "2", NULL
	};
	return indx (pd, p, list, 1, NULL);
}

/* read argument of ld (hl), */
static int rd_ld_hl(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "", "a", "*", NULL
	};
	i = indx (pd, p, list, 0, &pd->readbyte);
	if (i < 9) {
		return i;
	}
	pd->writebyte = 1;
	return 7;
}

/* read argument of ld (nnnn), */
static int rd_ld_nn(PluginData *pd, const char **p) {
#define ld_nnHL 5
#define ld_nnA 6
	int i;
	const char *list[] = {
		"bc", "de", "", "sp", "hl", "a", "ix", "iy", NULL
	};
	i = indx (pd, p, list, 1, NULL);
	if (i < 7) {
		return i;
	}
	pd->indexed = 0xdd + 0x20 *(i == 8);
	return ld_nnHL;
}

/* read argument of ld a, */
static int rd_lda(PluginData *pd, const char **p) {
#define A_N 7
#define A_I 9
#define A_R 10
#define A_NN 11
	int i;
	const char *list[] = {
		"( sp )", "( iy +)", "( de )", "( bc )", "( ix +)", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "i", "r", "(*)", "[iy*]", "[ix*]", "*", NULL
	};
	const char *nn;
	i = indx (pd, p, list, 0, &nn);
	if (i == 2 || i == 5) {
		pd->indexed = (i == 2)? 0xFD: 0xDD;
		pd->indexjmp = nn;
		return 7;
	}
	if (i == 17) {
		pd->indexed = 0xFD;
		pd->indexjmp = nn;
		return 7;
	}
	if (i == 18) {
		pd->indexed = 0xDD;
		pd->indexjmp = nn;
		return 7;
	}
	if (i == 19) {
		/* wildcard: numeric constant */
		pd->readbyte = nn;
		return A_N;
	}
	if (i == 16) {
		pd->readword = nn;
	}
	return i - 5;
}

/* read argument of ld b|c|d|e|h|l */
static int rd_ldbcdehla(PluginData *pd, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", "ixh",
		"ixl", "iyh", "iyl", "*", NULL
	};
	const char *nn;
	i = indx (pd, p, list, 0, &nn);
	if (i == 15) {
		pd->readbyte = nn;
		pd->writebyte = 1;
		return 7;
	}
	if (i > 10) {
		int x;
		x = 0xdd + 0x20 *(i > 12);
		if (pd->indexed && pd->indexed != x) {
			R_LOG_ERROR ("illegal use of index registers");
			return 0;
		}
		pd->indexed = x;
		return 6 - (i & 1);
	}
	if (i > 8) {
		if (pd->indexed) {
			R_LOG_ERROR ("illegal use of index registers");
			return 0;
		}
		pd->indexed = 0xDD + 0x20 *(i == 10);
		pd->indexjmp = nn;
		return 7;
	}
	return i;
}

/* read nnnn, or (nnnn) */
static inline int rd_nn_nn(PluginData *pd, const char **p) {
#define _NN 1
	const char *list[] = {
		"(*)", "*", NULL
	};
	return 2 - indx (pd, p, list, 0, &pd->readword);
}

/* read {HL|IX|IY},nnnn, or (nnnn) */
static int rd_sp(PluginData *pd, const char **p) {
#define SPNN 0
#define SPHL 1
	int i;
	const char *list[] = {
		"hl", "ix", "iy", "(*)", "*", NULL
	};
	const char *nn;
	i = indx (pd, p, list, 0, &nn);
	if (i > 3) {
		pd->readword = nn;
		return i == 4? 2: 0;
	}
	if (i != 1) {
		pd->indexed = 0xDD + 0x20 *(i - 2);
	}
	return 1;
}

static int assemble(PluginData *pd, const char *str, unsigned char *_obuf) {
	const char *ptr;
	char *bufptr;
	int r, s; /* registers */

	pd->obuflen = 0;
	pd->obuf = _obuf;
	int cmd, cont = 1;
	pd->z80buffer = strdup (str);
	if (!cont) {
		free (pd->z80buffer);
		return pd->obuflen;
	}
	for (bufptr = pd->z80buffer; (bufptr = strchr (bufptr, '\n'));) {
		*bufptr = ' ';
	}
	for (bufptr = pd->z80buffer; (bufptr = strchr (bufptr, '\r'));) {
		*bufptr = ' ';
	}
	ptr = pd->z80buffer;
	pd->baseaddr = pd->addr;
	++pd->stack[pd->sp].line;
	ptr = delspc (ptr);
	if (!*ptr) {
		free (pd->z80buffer);
		return pd->obuflen;
	}
	if (!pd->define_macro) {
		readlabel (pd, &ptr, 1);
	} else {
		readlabel (pd, &ptr, 0);
	}
	ptr = delspc (ptr);
	if (!*ptr) {
		free (pd->z80buffer);
		return pd->obuflen;
	}
	pd->comma = 0;
	pd->indexed = 0;
	pd->indexjmp = 0;
	pd->writebyte = 0;
	pd->readbyte = 0;
	pd->readword = 0;
	cmd = readcommand (pd, &ptr) - 1;
	int i, have_quote;
	switch (cmd) {
	case Z80_ADC:
		if (! (r = rd_a_hl (pd, &ptr))) {
			break;
		}
		if (r == HL) {
			if (! (r = rd_rr_(pd, &ptr))) {
				break;
			}
			wrtb (0xED);
			r--;
			wrtb (0x4A + 0x10 * r);
			break;
		}
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0x88 + r);
		break;
	case Z80_ADD:
		if (! (r = rd_r_add (pd, &ptr))) {
			break;
		}
		if (r == addHL) {
			if (! (r = rd_rrxx (pd, &ptr))) {
				break;
			}
			r--;
			wrtb (0x09 + 0x10 * r); /* ADD HL/IX/IY, qq  */
			break;
		}
		if (has_argument (&ptr)) {
			if (r != A) {
				R_LOG_ERROR ("parse error before: %s", ptr);
				break;
			}
			if (! (r = rd_r (pd, &ptr))) {
				break;
			}
			r--;
			wrtb (0x80 + r);
			break;
		}
		r--;
		wrtb (0x80 + r);
		break;
	case Z80_AND:
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xA0 + r);
		break;
	case Z80_BIT:
		if (! (r = rd_0_7 (pd, &ptr))) {
			break;
		}
		int bit_num = r - 1; /* rd_0_7 returns 1-8, convert to 0-7 */
		rd_comma (&ptr);
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		/* handle indexed addressing with displacement */
		if (r == 7 && pd->indexed) {
			emit_indexed_bitop (pd, Z80_BIT_BASE, bit_num);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			wrtb (Z80_BIT_BASE + (bit_num << 3) + (r - 1));
		}
		break;
	case Z80_CALL:
		if ((r = rd_cc (pd, &ptr))) {
			r--;
			wrtb (0xC4 + 8 * r);
			rd_comma (&ptr);
		} else {
			wrtb (0xCD);
		}
		break;
	case Z80_CCF:
		wrtb (0x3F);
		break;
	case Z80_CP:
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xB8 + r);
		break;
	case Z80_CPD:
		wrtb (0xED);
		wrtb (0xA9);
		break;
	case Z80_CPDR:
		wrtb (0xED);
		wrtb (0xB9);
		break;
	case Z80_CPI:
		wrtb (0xED);
		wrtb (0xA1);
		break;
	case Z80_CPIR:
		wrtb (0xED);
		wrtb (0xB1);
		break;
	case Z80_CPL:
		wrtb (0x2F);
		break;
	case Z80_DAA:
		wrtb (0x27);
		break;
	case Z80_DEC:
		if (! (r = rd_r_rr (pd, &ptr))) {
			break;
		}
		if (r < 0) {
			r--;
			wrtb (0x05 - 8 * r);
			break;
		}
		r--;
		wrtb (0x0B + 0x10 * r);
		break;
	case Z80_DI:
		wrtb (0xF3);
		break;
	case Z80_DJNZ:
		wrtb (0x10);
		break;
	case Z80_EI:
		wrtb (0xFB);
		break;
	case Z80_EX:
		if (! (r = rd_ex1 (pd, &ptr))) {
			break;
		}
		switch (r) {
		case DE:
			if (!rd_hl (pd, &ptr)) {
				break;
			}
			wrtb (0xEB);
			break;
		case AF:
			if (!rd_af_(pd, &ptr)) {
				break;
			}
			wrtb (0x08);
			break;
		default:
			if (!rd_hlx (pd, &ptr)) {
				break;
			}
			wrtb (0xE3);
		}
		break;
	case Z80_EXX:
		wrtb (0xD9);
		break;
	case Z80_HALT:
		wrtb (0x76);
		break;
	case Z80_IM:
		if (! (r = rd_0_2 (pd, &ptr))) {
			break;
		}
		wrtb (0xED);
		r--;
		wrtb (0x46 + 8 * r);
		break;
	case Z80_IN:
		if (! (r = rd_in (pd, &ptr))) {
			break;
		}
		if (r == A) {
			if (! (r = rd_nnc (pd, &ptr))) {
				break;
			}
			if (r == C) {
				wrtb (0xED);
				wrtb (0x40 + 8 *(A - 1));
				break;
			}
			wrtb (0xDB);
			break;
		}
		if (!rd_c (pd, &ptr)) {
			break;
		}
		wrtb (0xED);
		r--;
		wrtb (0x40 + 8 * r);
		break;
	case Z80_INC:
		if (! (r = rd_r_rr (pd, &ptr))) {
			break;
		}
		if (r < 0) {
			r++;
			wrtb (0x04 - 8 * r);
			break;
		}
		r--;
		wrtb (0x03 + 0x10 * r);
		break;
	case Z80_IND:
		wrtb (0xED);
		wrtb (0xAA);
		break;
	case Z80_INDR:
		wrtb (0xED);
		wrtb (0xBA);
		break;
	case Z80_INI:
		wrtb (0xED);
		wrtb (0xA2);
		break;
	case Z80_INIR:
		wrtb (0xED);
		wrtb (0xB2);
		break;
	case Z80_JP:
		r = rd_jp (pd, &ptr);
		if (r < 0) {
			wrtb (0xE9);
			break;
		}
		if (r) {
			r--;
			wrtb (0xC2 + 8 * r);
			rd_comma (&ptr);
		} else {
			wrtb (0xC3);
		}
		break;
	case Z80_JR:
		r = rd_jr (pd, &ptr);
		if (r) {
			rd_comma (&ptr);
		}
		wrtb (0x18 + 8 * r);
		break;
	case Z80_LD:
		if (! (r = rd_ld (pd, &ptr))) {
			break;
		}
		switch (r) {
		case ld_BC:
		case ld_DE:
			if (!rd_a (pd, &ptr)) {
				break;
			}
			wrtb (0x02 + 0x10 *(r == ld_DE? 1: 0));
			break;
		case ld_HL:
			r = rd_ld_hl (pd, &ptr) - 1;
			wrtb (0x70 + r);
			break;
		case ld_NN:
			if (! (r = rd_ld_nn (pd, &ptr))) {
				break;
			}
			if (r == ld_nnA || r == ld_nnHL) {
				wrtb (0x22 + 0x10 *(r == ld_nnA? 1: 0));
				break;
			}
			wrtb (0xED);
			wrtb (0x43 + 0x10 * --r);
			break;
		case ldA:
			if (! (r = rd_lda (pd, &ptr))) {
				break;
			}
			if (r == A_NN) {
				wrtb (0x3A);
				break;
			}
			if (r == A_I || r == A_R) {
				wrtb (0xED);
				wrtb (0x57 + 8 *(r == A_R? 1: 0));
				break;
			}
			if (r == A_N) {
				char n = r_num_math (NULL, pd->readbyte);
				wrtb (0x3E);
				wrtb (n);
				break;
			}
			if (r == 7 && pd->indexed) {
				/* indexed addressing: ld a, [ix+n] or ld a, [iy+n] */
				char n = r_num_math (NULL, pd->indexjmp);
				wrtb (pd->indexed);
				wrtb (0x7E);
				wrtb (n);
				pd->indexed = 0;
				break;
			}
			if (r < 0) {
				r++;
				wrtb (0x0A - 0x10 * r);
				break;
			}
			wrtb (0x78 + --r);
			break;
		case ldB:
		case ldC:
		case ldD:
		case ldE:
		case ldH:
		case ldL:
			if (! (s = rd_ldbcdehla (pd, &ptr))) {
				break;
			}
			if (s == 7) {
				char n = r_num_math (NULL, pd->readbyte);
				wrtb (0x08 *(r - 7) + 0x6);
				wrtb (n);
			} else {
				wrtb (0x40 + 0x08 *(r - 7) + (s - 1));
			}
			break;
		case ldBC:
		case ldDE:
			s = rd_nn_nn (pd, &ptr);
			if (s == _NN) {
				wrtb (0xED);
				wrtb (0x4B + 0x10 *(r == ldDE? 1: 0));
				break;
			}
			wrtb (0x01 + (r == ldDE? 1: 0) * 0x10);
			break;
		case ldHL:
			r = rd_nn_nn (pd, &ptr);
			wrtb (0x21 + (r == _NN? 1: 0) * 9);
			break;
		case ldI:
		case ldR:
			if (!rd_a (pd, &ptr)) {
				break;
			}
			wrtb (0xED);
			wrtb (0x47 + 0x08 *(r == ldR? 1: 0));
			break;
		case ldSP:
			r = rd_sp (pd, &ptr);
			if (r == SPHL) {
				wrtb (0xF9);
				break;
			}
			if (r == SPNN) {
				wrtb (0x31);
				break;
			}
			wrtb (0xED);
			wrtb (0x7B);
			break;
		}
		break;
	case Z80_LDD:
		wrtb (0xED);
		wrtb (0xA8);
		break;
	case Z80_LDDR:
		wrtb (0xED);
		wrtb (0xB8);
		break;
	case Z80_LDI:
		wrtb (0xED);
		wrtb (0xA0);
		break;
	case Z80_LDIR:
		wrtb (0xED);
		wrtb (0xB0);
		break;
	case Z80_NEG:
		wrtb (0xED);
		wrtb (0x44);
		break;
	case Z80_NOP:
		wrtb (0x00);
		break;
	case Z80_OR:
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xB0 + r);
		break;
	case Z80_OTDR:
		wrtb (0xED);
		wrtb (0xBB);
		break;
	case Z80_OTIR:
		wrtb (0xED);
		wrtb (0xB3);
		break;
	case Z80_OUT:
		if (! (r = rd_nnc (pd, &ptr))) {
			break;
		}
		if (r == C) {
			if (! (r = rd_out (pd, &ptr))) {
				break;
			}
			wrtb (0xED);
			r--;
			wrtb (0x41 + 8 * r);
			break;
		}
		if (!rd_a (pd, &ptr)) {
			break;
		}
		wrtb (0xD3);
		break;
	case Z80_OUTD:
		wrtb (0xED);
		wrtb (0xAB);
		break;
	case Z80_OUTI:
		wrtb (0xED);
		wrtb (0xA3);
		break;
	case Z80_POP:
		if (! (r = rd_stack (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xC1 + 0x10 * r);
		break;
	case Z80_PUSH:
		if (! (r = rd_stack (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xC5 + 0x10 * r);
		break;
	case Z80_RES:
		if (! (r = rd_0_7 (pd, &ptr))) {
			break;
		}
		int bit_num_res = r - 1; /* rd_0_7 returns 1-8, convert to 0-7 */
		rd_comma (&ptr);
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		/* handle indexed addressing with displacement */
		if (r == 7 && pd->indexed) {
			emit_indexed_bitop (pd, Z80_RES_BASE, bit_num_res);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			wrtb (Z80_RES_BASE + (bit_num_res << 3) + (r - 1));
		}
		break;
	case Z80_RET:
		if (! (r = rd_cc (pd, &ptr))) {
			wrtb (0xC9);
			break;
		}
		r--;
		wrtb (0xC0 + 8 * r);
		break;
	case Z80_RETI:
		wrtb (0xED);
		wrtb (0x4D);
		break;
	case Z80_RETN:
		wrtb (0xED);
		wrtb (0x45);
		break;
	case Z80_RL:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			emit_indexed_shift (pd, Z80_RL_HL);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			r--;
			wrtb (0x10 + r);
		}
		break;
	case Z80_RLA:
		wrtb (0x17);
		break;
	case Z80_RLC:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			char n = r_num_math (NULL, pd->indexjmp);
			wrtb (pd->indexed);
			wrtb (0xCB);
			wrtb (n);
			wrtb (0x06);
			pd->indexed = 0;
		} else {
			wrtb (0xCB);
			r--;
			wrtb (0x00 + r);
		}
		break;
	case Z80_RLCA:
		wrtb (0x07);
		break;
	case Z80_RLD:
		wrtb (0xED);
		wrtb (0x6F);
		break;
	case Z80_RR:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			char n = r_num_math (NULL, pd->indexjmp);
			wrtb (pd->indexed);
			wrtb (0xCB);
			wrtb (n);
			wrtb (0x1E);
			pd->indexed = 0;
		} else {
			wrtb (0xCB);
			r--;
			wrtb (0x18 + r);
		}
		break;
	case Z80_RRA:
		wrtb (0x1F);
		break;
	case Z80_RRC:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			char n = r_num_math (NULL, pd->indexjmp);
			wrtb (pd->indexed);
			wrtb (0xCB);
			wrtb (n);
			wrtb (0x0E);
			pd->indexed = 0;
		} else {
			wrtb (0xCB);
			r--;
			wrtb (0x08 + r);
		}
		break;
	case Z80_RRCA:
		wrtb (0x0F);
		break;
	case Z80_RRD:
		wrtb (0xED);
		wrtb (0x67);
		break;
	case Z80_RST:
		ptr = "";
		break;
	case Z80_SBC:
		if (! (r = rd_a_hl (pd, &ptr))) {
			break;
		}
		if (r == HL) {
			if (! (r = rd_rr_(pd, &ptr))) {
				break;
			}
			wrtb (0xED);
			r--;
			wrtb (0x42 + 0x10 * r);
			break;
		}
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0x98 + r);
		break;
	case Z80_SCF:
		wrtb (0x37);
		break;
	case Z80_SET:
		if (! (r = rd_0_7 (pd, &ptr))) {
			break;
		}
		int bit_num_set = r - 1; /* rd_0_7 returns 1-8, convert to 0-7 */
		rd_comma (&ptr);
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		/* handle indexed addressing with displacement */
		if (r == 7 && pd->indexed) {
			emit_indexed_bitop (pd, Z80_SET_BASE, bit_num_set);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			wrtb (Z80_SET_BASE + (bit_num_set << 3) + (r - 1));
		}
		break;
	case Z80_SLA:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			emit_indexed_shift (pd, Z80_SLA_HL);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			r--;
			wrtb (0x20 + r);
		}
		break;
	case Z80_SLI:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			emit_indexed_shift (pd, Z80_SLL_HL);
		} else {
			wrtb (Z80_INDEXED_PREFIX_CB);
			r--;
			wrtb (0x30 + r);
		}
		break;
	case Z80_SRA:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			char n = r_num_math (NULL, pd->indexjmp);
			wrtb (pd->indexed);
			wrtb (0xCB);
			wrtb (n);
			wrtb (0x2E);
			pd->indexed = 0;
		} else {
			wrtb (0xCB);
			r--;
			wrtb (0x28 + r);
		}
		break;
	case Z80_SRL:
		if (! (r = rd_r_(pd, &ptr))) {
			break;
		}
		if (r == 7 && pd->indexed) {
			char n = r_num_math (NULL, pd->indexjmp);
			wrtb (pd->indexed);
			wrtb (0xCB);
			wrtb (n);
			wrtb (0x3E);
			pd->indexed = 0;
		} else {
			wrtb (0xCB);
			r--;
			wrtb (0x38 + r);
		}
		break;
	case Z80_SUB:
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		if (has_argument (&ptr)) { /* SUB A,r? */
			if (r != A) {
				R_LOG_ERROR ("parse error before: %s", ptr);
				break;
			}
			if (! (r = rd_r (pd, &ptr))) {
				break;
			}
		}
		r--;
		wrtb (0x90 + r);
		break;
	case Z80_XOR:
		if (! (r = rd_r (pd, &ptr))) {
			break;
		}
		r--;
		wrtb (0xA8 + r);
		break;
	case Z80_DEFB:
	case Z80_DB:
	case Z80_DEFM:
	case Z80_DM:
		ptr = delspc (ptr);
		while (1) {
			have_quote = (*ptr == '"' || *ptr == '\'');
			if (have_quote) {
				/* Read string.  */
				int quote = *ptr;
				++ptr;
				while (*ptr != quote) {
					write_one_byte (rd_character (pd, &ptr, NULL, 1), 0);
					if (*ptr == 0) {
						R_LOG_ERROR ("end of line in quoted string");
						break;
					}
				}
				++ptr;
			} else {
				/* Read expression.  */
				skipword (pd, &ptr, ',');
			}
			ptr = delspc (ptr);
			if (*ptr == ',') {
				++ptr;
				continue;
			}
			if (*ptr != 0) {
				R_LOG_ERROR ("junk in byte definition: %s", ptr);
			}
			break;
		}
		break;
	case Z80_DEFW:
	case Z80_DW:
		if (!rd_word (pd, &ptr, ',')) {
			R_LOG_ERROR ("No data for word definition");
			break;
		}
		while (1) {
			ptr = delspc (ptr);
			if (*ptr != ',') {
				break;
			}
			++ptr;
			if (!rd_word (pd, &ptr, ',')) {
				R_LOG_ERROR ("Missing expression in defw");
			}
		}
		break;
	case Z80_DEFS:
	case Z80_DS:
		r = rd_expr (pd, &ptr, ',', NULL, pd->sp, 1);
		if (r < 0) {
			R_LOG_ERROR ("ds should have its first argument >=0 (not -0x%x)", -r);
			break;
		}
		ptr = delspc (ptr);
		if (*ptr) {
			rd_comma (&ptr);
			pd->readbyte = 0;
			rd_byte (pd, &ptr, '\0');
			pd->writebyte = 0;
			break;
		}
		for (i = 0; i < r; i++) {
			write_one_byte (0, 0);
		}
		break;
	case Z80_END:
		break;
	case Z80_ORG:
		pd->addr = rd_expr (pd, &ptr, '\0', NULL, pd->sp, 1) & 0xffff;
		break;
	case Z80_IF:
		break;
	case Z80_ELSE:
		R_LOG_ERROR ("else without if");
		break;
	case Z80_ENDIF:
		R_LOG_ERROR ("endif without if");
		break;
	case Z80_ENDM:
		if (pd->stack[pd->sp].file) {
			R_LOG_ERROR ("endm outside macro definition");
		}
		break;
	case Z80_SEEK:
		R_LOG_ERROR ("seek error");
		break;
	default:
		R_LOG_DEBUG ("command or comment expected (was %s)", ptr);
		free (pd->z80buffer);
		return 0;
	}

	free (pd->z80buffer);
	return pd->obuflen;
}

R_IPI int z80asm(PluginData *pd, unsigned char *outbuf, const char *s) {
	return assemble (pd, s, outbuf);
}
