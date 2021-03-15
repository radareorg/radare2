/* radare - LGPL - Copyright 2009-2019 - hmht */
#include"8051_ass.h"

/*****************************************************************************\
 *              Architecture
 *
 * File Contents:
 * ## Section 1. Token parsers
 * ## Section 2: some weird datastructure
 * ## Section 3: token classifiers
 * ## Section 4: Generic instruction emitters
 * ## Section 5: Specific instruction parsing
 * ## Section 6: mnemonic token dispatcher
 * ## Section 7: radare2 glue and mnemonic tokenization
 *
 * documentation date: 2019-10-04
 * documentation date: 2019-10-14
 *
 * 1. Token parsers
 *
 * I'm sure most of this is re-inventing the wheel, (poorly, too), this is
 * because I didn't take enough time to find a proper implementation.
 * If you know a r2lib function that does the job it should be used instead.
 *
 *
 * 2. Some weird datastructure
 *
 * Started out for matching strings whitespace-independently, and uses c99s
 * (struct literal){} notation and is zero-terminated.
 * I wrote this thing in the late hours of r2con2019 while jetlagged.
 *
 * Currently the last place it's used in is mnemonic matching, since I hacked
 * in a nr-of-arguments field into the table. Whitespace-independence is
 * currently a bug since it'll accept "n o p" as "nop"... also functions need
 * to be renamed.
 *
 * One pitfall is that the match is lazy (non-greedy?) in other words, "reti"
 * is matched by "ret", but not the other way around, so the most-specific match
 * must come first in the list.
 *
 *
 * 3. token classifiers
 *
 * right now mostly has functions to distinguish between argument types, and
 * parses their data. (Some argument types, such as relative addresses and bits,
 * require parsing to asses their validity.)
 *
 *
 * 4. Generic instruction parsing
 *
 * I started out just writing specific parser for each
 * mnemonic(-variant), and halfway through I started noticing a lot of
 * code duplication, so extracted some of it.
 *	Their basic operation is simple: dump whatever you're given into the out
 * parameter, and move the write pointer forward.
 *
 *
 * 5. Specific instruction parsing
 *
 * Of course, in the very beginning I started out with the idea to
 * completely generalize everything, but there were more edge cases than
 * my small brain could handle, so I scrapped that and started punching
 * out special parsers for each instruction variant mindlessly.
 *	The result of this approach is really glaring. Lots of duplication.
 * There's lots of easy deduplication opportunity, and now that it's finished I
 * have some ideas on how to do it better, but eh.
 *
 *
 * 6. mnemonic token dispatcher
 *
 * The weird datastructure returns! with macros! it's basically just a jump
 * table with one bit of validation.
 *
 *
 * 7. Radare2 glue and mnemonic tokenization
 *
 * Had one look at the gb glue code and copied the lot of it without really
 * understanding what I'm doing.
 *
 * also splits out the first word (asserted mnemonic) for the token dispatcher,
 * and splits up the arguments
 *
\*****************************************************************************/
#include<r_util.h>
#include<string.h>

/******************************************************************************
 * ## Section 1. Generic Token parsers
 *               ------- -------------*/

static bool parse_hexadecimal(char const* hexstr, ut16* out) {
	if ( !hexstr || hexstr[0] != '0'
		|| !(hexstr[1] == 'x' || hexstr[1] == 'X')) {
		return false;
	}
	*out = 0;
	char const*p;
	for (p = hexstr + 2; p < hexstr + 6 && *p ; p += 1) {
		*out <<= 4;
		if ( '0' <= *p && *p <= '9' ) {
			*out |= *p - '0';
		} else if ( 'a' <= *p && *p <= 'f' ) {
			*out |= *p - 'a' + 10;
		} else if ( 'A' <= *p && *p <= 'F' ) {
			*out |= *p - 'A' + 10;
		} else {
			return false;
		}
	}
	return ! *p;
}

// FIXME: may write outside buffer
/**
 * splits up the given string into multiple chucks, separated by unquoted
 * commas. It will then copy chunk n-1 into dest, with the leading and trailing
 * whitespace stripped.
 *
 * if chunk n-1 does not exist or is empty, it will return false;
 *
 * only text before newlines, NUL, and unquoted semicolons is chunked.
 *
 * any text after a single-quote and before the next single-quote is considered
 * quoted. There is no escaping.
 */
static bool get_arg(char const*multi, int n, char * dest)
{
	char* lastnonws = dest;
	bool anynonws = false;
	bool in_string = false;
	n -= 1;
	if (!multi) return false;
	while (n && *multi && *multi != '\n' && *multi != '\r') {
		if (*multi == '\'') in_string = !in_string;
		if (!in_string) {
			if (*multi == ';') {
				return false;
			}
			if (*multi == ',') {
				multi += 1;
				n -= 1;
				continue;
			}
		}
		multi += 1;
	}
	if (!*multi || *multi == '\n' || *multi == '\r' || in_string) {
		return false;
	}

	while (*multi && (*multi == ' ' || *multi == '\t')) {
		multi += 1;
	}

	while (*multi && *multi != '\n' && *multi != '\r') {
		if (*multi == '\'') in_string = !in_string;
		if (!in_string) {
			if (*multi == ';' ||  *multi == ',') {
				break;
			}
			if (*multi != ' ' && *multi != '\t') {
				lastnonws = dest;
				anynonws = true;
			}
			*dest = *multi;
			dest += 1;
			multi += 1;
		}
	}

	if (in_string) return false;

	if (!anynonws) {
		*dest = '\0';
		return false;
	}
	*(lastnonws + 1) = '\0';
	return true;
}

/**
 * tokenizes the argument list
 * arg parameter must be 3 char pointers wide.
 * TODO: merge with get_arg, as this is now the only user
 */
static int get_arguments (char**arg, char const*arguments) {
	size_t arglen = strlen (arguments) + 1;
	char*tmp = malloc (arglen);
	if (!get_arg (arguments, 1, tmp)) {
		free (tmp); tmp = 0;
		return 0;
	} else {
		arg[0] = realloc (tmp, strlen (tmp) + 1); tmp = 0;
		tmp = malloc (arglen);
		if (!get_arg (arguments, 2, tmp)) {
			free (tmp); tmp = 0;
			return 1;
		} else {
			arg[1] = realloc (tmp, strlen (tmp) + 1); tmp = 0;
			tmp = malloc (arglen + 1);
			if (!get_arg (arguments, 3, tmp)) {
				free (tmp); tmp = 0;
				return 2;
			} else {
				arg[2] = realloc (tmp, strlen (tmp) + 1); tmp = 0;
				tmp = malloc (arglen + 1);
				if (get_arg (arguments, 4, tmp)) {
					free (tmp); tmp = 0;
					free (arg[0]); arg[0] = 0;
					free (arg[1]); arg[1] = 0;
					free (arg[2]); arg[2] = 0;
					return 4;
				}
				free (tmp); tmp = 0;
				return 3;
			}
		}
	}
}

/**
 * returns true if there is no more valid assembly code after this character
 */
static bool terminates_asm_line(char c) {
	return c == '\0' || c == '\n' || c == '\r' || c == ';' ;
}

/**
 * Like r_str_casecmp, but ignores all isspace characters
 */
static int str_iwhitecasecmp(char const*a, char const*b) {
	if (!a && !b) {
		return *a - *b;
	}
	while (a && b) {
		if (!*a && !*b) {
			break;
		}
		if (!*a || !*b) {
			break;
		}
		if (isspace ((unsigned char)*a)) {
			a += 1;
			continue;
		}
		if (isspace ((unsigned char)*b)) {
			b += 1;
			continue;
		}
		if (tolower ((unsigned char)*a) == tolower ((unsigned char)*b)) {
			a += 1;
			b += 1;
			continue;
		}
		break;
	}
	return *a - *b;
}

/******************************************************************************
 * ## Section 2: some weird datastructure
                 ------------------------*/

typedef bool (*parse_mnem_args)(char const*const*, ut16, ut8**);

typedef struct {
	char const*const pattern;
	parse_mnem_args res;
	int args;
} ftable[];

static bool pattern_match(char const*str, char const*pattern) {
	int si = 0;
	int ti = 0;
	if (!pattern) {
		return true;
	}

	while (pattern[ti] != '\0') {
		while (isspace ((unsigned char)str[si]) && !isspace ((unsigned char)pattern[ti])) {
			si += 1;
		}
		if (isspace ((unsigned char)pattern[ti])) {
			ti += 1;
			continue;
		}
		if (tolower ((unsigned char)pattern[ti]) == tolower ((unsigned char)str[si])) {
			si += 1;
			ti += 1;
		}
		else {
			return false;
		}
	}
	return true;
}

static parse_mnem_args match_prefix_f(int*args, char const*str, ftable const tbl) {
	int row = 0;
	while (tbl[row].pattern) {
		if (pattern_match (str, tbl[row].pattern)) {
			*args = tbl[row].args;
			return tbl[row].res;
		}
		else {
			row += 1;
		}
	}
	*args = tbl[row].args;
	return tbl[row].res;
}

/******************************************************************************
 * ## Section 3: token classifiers
                 -----------------*/

/**
 * matches registers r0 and r1 when they are indirectly-addressed.
 * 8051-style syntax @r0, but also r2 defacto [r0]
 */
static bool is_indirect_reg(char const*str)
{
	if ( !str) {
		return false;
	}

	if (str[0] == '@' ) {
		return r_str_ansi_nlen (str, 4) == 3
			&& tolower ((unsigned char)str[1]) == 'r'
			&& (str[2] == '0' || str[2] == '1');
	}

	if (str[0] == '[' ) {
		return r_str_ansi_nlen (str, 5) == 4
			&& tolower ((unsigned char)str[1]) == 'r'
			&& (str[2] == '0' || str[2] == '1')
			&& str[3] == ']';
	}

	return false;
}

/**
 * returns true if the given string denotes an 'r'-register
 */
static bool is_reg(char const*str)
{
	return str && tolower ((unsigned char)str[0]) == 'r' && r_str_ansi_nlen (str, 3) == 2
		&& '0' <= str[1] && str[1] <= '7';
}

/**
 * returns true if the given number is a valid relative address from the given
 *	pc, the relative address is stored in the *out parameter.
 */
static bool relative_address(ut16 pc, ut16 address, ut8 *out)
{
	st16 diff = address - (pc + 2);
	if (diff < INT8_MIN || INT8_MAX < diff) {
		return false;
	}
	else {
		*out = diff;
		return true;
	}
}

static bool resolve_immediate(char const* imm_str, ut16* imm_out) {
	// rasm2 resolves symbols, so does this really only need to parse hex?
	// maybe TODO: skip leading '#' if exists?
	return parse_hexadecimal (imm_str, imm_out);
}

static bool to_address(char const* addr_str, ut16* addr_out) {
	// rasm2 resolves symbols, so does this really only need to parse hex?
	// maybe TODO: check address bounds?
	return parse_hexadecimal (addr_str, addr_out);
}

/**
 * attempts to parse the given string as an 8bit-wide address
 */
static bool address_direct(char const* addr_str, ut8* addr_out) {
	ut16 addr_big;
	// rasm2 resolves symbols, so does this really only need to parse hex?
	// maybe TODO: check address bounds?
	if ( !parse_hexadecimal (addr_str, &addr_big)
		|| (0xFF < addr_big)) {
		return false;
	}
	*addr_out = addr_big;
	return true;
}

/**
 * attempts to parse the given string as a bit-address
 */
static bool address_bit(char const* addr_str, ut8* addr_out) {
	char *bitpart = malloc (strlen (addr_str) + 1);
	char *bytepart = malloc (strlen (addr_str) + 1);
	char const *separator = r_str_lchr (addr_str, '.');
	ut8 byte;
	int bit;
	bool ret = false;
	// TODO: check if symbols are resolved properly in all cases:
	// - symbol.2
	// - 0x25.symbol
	// - symbol.symbol
	// - symbol
	if (!separator) {
		goto end;
	}
	r_str_ncpy (bytepart, addr_str, separator - addr_str + 1);
	bytepart[separator - addr_str + 1] = '\0';
	r_str_ncpy (bitpart, separator + 1, strlen (separator));
	if (!address_direct (bytepart, &byte)) {
		goto end;
	}
	if (1 < strlen (bitpart)
		|| bitpart[0] < '0' || '7' < bitpart[0]) {
		ret = false;
		goto end;
	}
	bit = bitpart[0] - '0';
	if (0x20 <= byte && byte < 0x30) {
		*addr_out = (byte - 0x20) * 8 + bit;
		ret = true;
	} else if (0x80 <= byte && !(byte%8)) {
		*addr_out = byte + bit;
		ret = true;
	}
end:
	free (bitpart); bitpart = 0;
	free (bytepart); bytepart = 0;
	return ret;
}

/**
 * figures out which register is denoted by the given string
 * returns 8 if invalid
 */
static int register_number(char const*reg) {
	if (is_reg (reg)) {
		return reg[1] - '0';
	}
	if (is_indirect_reg (reg)) {
		return reg[2] - '0';
	}
	return 8; // not register 0-7, so...
}

/******************************************************************************
 * ## Section 4: Generic instruction emmiters
                 ----------------------------*/

static bool single_byte_instr(ut8 const instr, ut8 **out) {
	(*out)[0] = instr;
	*out += 1;
	return true;
}

static bool singlearg_bit(ut8 const firstbyte, char const* arg, ut8 **out) {
	ut8 address;
	if (!address_bit (arg, &address)) {
		return false;
	}
	(*out)[0] = firstbyte;
	(*out)[1] = address;
	*out += 2;
	return true;
}

static bool singlearg_reladdr(ut8 const firstbyte, char const* arg
	, ut16 const pc, ut8 **out)
{
	ut16 address;
	if (!to_address (arg, &address)
		|| !relative_address (pc, address, (*out)+1)) {
		return false;
	}
	(*out)[0] = firstbyte;
	*out += 2;
	return true;
}

static bool singlearg_direct(ut8 const firstbyte, char const* arg
	, ut8 **out)
{
	ut8 address;
	if (!address_direct (arg, &address)) {
		return false;
	}
	(*out)[0] = firstbyte;
	(*out)[1] = address;
	*out += 2;
	return true;
}

static bool singlearg_immediate(ut8 firstbyte, char const* imm_str, ut8**out) {
	ut16 imm;
	if (imm_str[0] != '#'
		|| !resolve_immediate (imm_str + 1, &imm)) {
		return false;
	}
	(*out)[0] = firstbyte;
	(*out)[1] = imm & 0x00FF;
	*out += 2;
	return true;
}

static bool singlearg_register(ut8 firstbyte, char const*reg, ut8**out) {
	return single_byte_instr (firstbyte | register_number (reg), out);
}

static bool single_a_arg_instr(ut8 const firstbyte, char const*arg
	, ut8 **out)
{
	if (r_str_casecmp ("a", arg)) {
		return false;
	}
	return single_byte_instr (firstbyte, out);
}

/******************************************************************************
 * ## Section 5: Specific instruction parsing
                 ----------------------------*/

static bool mnem_acall(char const*const*arg, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (arg[0], &address)) {
		return false;
	}
	(*out)[0] = ((address & 0x0700) >> 3) | 0x11;
	(*out)[1] = address & 0x00FF;
	*out += 2;
	return true;
}

static bool mnem_add(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	switch (arg[1][0]) {
	case '@':
	case '[':
		return singlearg_register (0x26, arg[1], out);
	case '#':
		return singlearg_immediate (0x24, arg[1], out);
	}
	if (is_reg (arg[1])) {
		return singlearg_register (0x28, arg[1], out);
	} else {
		return singlearg_direct (0x25, arg[1], out);
	}
}

static bool mnem_addc(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	if (is_indirect_reg (arg[1])) {
		return singlearg_register (0x36, arg[1], out);
	}
	if (arg[1][0] == '#') {
		return singlearg_immediate (0x34, arg[1], out);
	}
	if (is_reg (arg[1])) {
		return singlearg_register (0x38, arg[1], out);
	}
	return singlearg_direct (0x35, arg[1], out);
}

static bool mnem_ajmp(char const*const*arg, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (arg[0], &address)) {
		return false;
	}
	(*out)[0] = ((address & 0x0700) >> 3 ) | 0x01;
	(*out)[1] = address & 0x00FF;
	*out += 2;
	return true;
}

static bool mnem_anl(char const*const*arg, ut16 pc, ut8**out) {
	if (!strcmp (arg[0], "c")) {
		if (arg[1][0] == '/') {
			return singlearg_bit (0xb0, arg[1] + 1, out);
		}
		return singlearg_bit (0x82, arg[1], out);
	}
	if (!strcmp (arg[0], "a")) {
		if (is_indirect_reg (arg[1])) {
			return singlearg_register (0x56, arg[1], out);
		}
		if (arg[1][0] == '#') {
			return singlearg_immediate (0x54, arg[1], out);
		}
		if (is_reg (arg[1])) {
			return singlearg_register (0x58, arg[1], out);
		}
		return singlearg_direct (0x55, arg[1], out);
	}

	ut8 address;
	if (!address_direct (arg[0], &address)) {
		return false;
	}
	if (!r_str_casecmp (arg[1], "a")) {
		return singlearg_direct (0x52, arg[0], out);
	}
	ut16 imm;
	if (arg[1][0] != '#' || !resolve_immediate (arg[1] + 1, &imm)) {
		return false;
	}
	(*out)[0] = 0x53;
	(*out)[1] = address;
	(*out)[2] = imm & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_cjne(char const*const*arg, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (arg[2], &address)
		|| !relative_address (pc+1, address, (*out)+2)) {
		return false;
	}
	if (!r_str_casecmp (arg[0], "a")) {
		if (arg[1][0] == '#') {
			ut16 imm;
			if (!resolve_immediate (arg[1] + 1, &imm)) {
				return false;
			}
			(*out)[0] = 0xb4;
			(*out)[1] = imm & 0x00FF;
			// out[2] set earlier
			*out += 3;
			return true;
		}
		ut8 address;
		if (!address_direct (arg[1], &address)) {
			return false;
		}
		(*out)[0] = 0xb5;
		(*out)[1] = address;
		// out[2] set earlier
		*out += 3;
		return true;
	}
	if (is_reg (arg[0])) {
		ut16 imm;
		if (!resolve_immediate (arg[1] + 1, &imm)) {
			return false;
		}
		(*out)[0] = 0xbf | register_number (arg[0]) ;
		(*out)[1] = imm & 0x00FF;
		// out[2] set earlier
		*out += 3;
		return true;
	}
	if (is_indirect_reg (arg[0])) {
		ut16 imm;
		if (!resolve_immediate (arg[1] + 1, &imm)) {
			return false;
		}
		(*out)[0] = 0xb6 | register_number (arg[0]) ;
		(*out)[1] = imm & 0x00FF;
		// out[2] set earlier
		*out += 3;
		return true;
	}
	return false;
}

static bool mnem_clr(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp  ("a", arg[0])) {
		return single_byte_instr (0xe4, out);
	}
	if (!r_str_casecmp  ("c", arg[0])) {
		return single_byte_instr (0xc3, out);
	}
	return singlearg_bit (0xc2, arg[0], out);
}

static bool mnem_cpl(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp  ("a", arg[0])) {
		return single_byte_instr (0xf4, out);
	}
	if (!r_str_casecmp  ("c", arg[0])) {
		return single_byte_instr (0xb3, out);
	}
	return singlearg_bit (0xb2, arg[0], out);
}

static bool mnem_da(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0xd4, arg[0], out);
}

static bool mnem_dec(char const*const*arg, ut16 pc, ut8**out) {
	if (is_indirect_reg (arg[0])) {
		return singlearg_register (0x16, arg[0], out);
	}
	if (is_reg (arg[0])) {
		return singlearg_register (0x18, arg[0], out);
	}
	if (!r_str_casecmp ("a", arg[0])) {
		return single_byte_instr (0x14, out);
	}
	return singlearg_direct (0x15, arg[0], out);
}

static bool mnem_div(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp  ("ab", arg[0])) {
		return false;
	}
	return single_byte_instr (0x84, out);
}

static bool mnem_djnz(char const*const*arg, ut16 pc, ut8**out) {
	ut16 jmp_address;
	if (!to_address (arg[1], &jmp_address)) {
		return false;
	}
	if (!relative_address (pc, jmp_address, (*out) + 2)) {
		return false;
	}

	if (is_reg (arg[0])) {
		(*out)[0] = 0xd8 | register_number (arg[0]);
		(*out)[1] = (*out)[2];
		*out += 2;
		return true;
	}
	ut8 dec_address;
	if (!address_direct (arg[0], &dec_address))  {
		return false;
	}
	(*out)[0] = 0xd5;
	(*out)[1] = dec_address;
	(*out)[2] -= 1;
	*out += 3;
	return true;
}

static bool mnem_inc(char const*const*arg, ut16 pc, ut8**out) {
	if (is_reg (arg[0])) {
		return singlearg_register (0x08, arg[0], out);
	}
	if (is_indirect_reg (arg[0])) {
		return singlearg_register (0x06, arg[0], out);
	}
	if (!r_str_casecmp  ("a", arg[0])) {
		return single_byte_instr (0x04, out);
	}
	if (!r_str_casecmp ("dptr", arg[0])) {
		return single_byte_instr (0xa3, out);
	}
	return singlearg_direct (0x05, arg[0], out);
}

static bool mnem_jb(char const*const*arg, ut16 pc, ut8**out) {
	ut8 cmp_addr;
	if (!address_bit (arg[0], &cmp_addr)) {
		return false;
	}
	ut16 jmp_addr;
	if (!to_address (arg[1], &jmp_addr)
		|| !relative_address (pc + 1, jmp_addr, (*out) + 2)) {
		return false;
	}
	(*out)[0] = 0x20;
	(*out)[1] = cmp_addr;
	// out[2] set earlier
	*out += 3;
	return true;
}

static bool mnem_jbc(char const*const*arg, ut16 pc, ut8**out) {
	ut8 cmp_addr;
	if (!address_bit (arg[0], &cmp_addr)) {
		return false;
	}
	ut16 jmp_addr;
	if (!to_address (arg[1], &jmp_addr)
		|| !relative_address (pc + 1, jmp_addr, (*out) + 2)) {
		return false;
	}
	(*out)[0] = 0x10;
	(*out)[1] = cmp_addr;
	// out[2] set earlier
	*out += 3;
	return true;
}

static bool mnem_jc(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x40, arg[0], pc, out);
}

static bool mnem_jnb(char const*const*arg, ut16 pc, ut8**out) {
	ut8 cmp_addr;
	if (!address_bit (arg[0], &cmp_addr)) {
		return false;
	}
	ut16 jmp_addr;
	if (!to_address (arg[1], &jmp_addr)
		|| !relative_address (pc + 1, jmp_addr, (*out) + 2)) {
		return false;
	}
	(*out)[0] = 0x30;
	(*out)[1] = cmp_addr;
	// out[2] set earlier
	*out += 3;
	return true;
}

static bool mnem_jnc(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x50, arg[0], pc, out);
}

static bool mnem_jnz(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x70, arg[0], pc, out);
}

static bool mnem_jz(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x60, arg[0], pc, out);
}

static bool mnem_lcall(char const*const*arg, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (arg[0], &address)) {
		return false;
	}
	(*out)[0] = 0x12;
	(*out)[1] = ((address & 0xFF00) >> 8) & 0x00FF;
	(*out)[2] = address & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_ljmp(char const*const*arg, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (arg[0], &address)) {
		return false;
	}
	(*out)[0] = 0x02;
	(*out)[1] = ((address & 0xFF00) >> 8) & 0x00FF;
	(*out)[2] = address & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_mov_c(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_bit (0xa2, arg[1], out);
}

static bool mnem_mov(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp (arg[0], "dptr")) {
		ut16 imm;
		if (!resolve_immediate (arg[1] + 1, &imm)) {
			return false;
		}
		(*out)[0] = 0x90;
		(*out)[1] = imm >> 8;
		(*out)[2] = imm;
		*out += 3;
		return true;
	}
	if (is_indirect_reg (arg[0])) {
		if (!r_str_casecmp (arg[1], "a")) {
			return singlearg_register (0xf6, arg[0], out);
		}
		if (arg[1][0] != '#' ) {
			return singlearg_direct (
				0xa6 | register_number (arg[0])
				, arg[1]
				, out);
		}
		return singlearg_immediate (0x76 | register_number (arg[0])
			, arg[1]
			, out);
	}
	if (!r_str_casecmp (arg[0], "a")) {
		if (is_indirect_reg (arg[1])) {
			return singlearg_register (0xe6, arg[1], out);
		}
		if (is_reg (arg[1])) {
			return singlearg_register (0xe8, arg[1], out);
		}
		if (arg[1][0] == '#') {
			return singlearg_immediate (0x74, arg[1], out);
		}
		return singlearg_direct (0xe5, arg[1], out);
	}
	if (is_reg (arg[0])) {
		if (!r_str_casecmp (arg[1], "a")) {
			return singlearg_register (0xf8, arg[0], out);
		}
		if (arg[1][0] == '#') {
			return singlearg_immediate (
				0x78 | register_number (arg[0])
				, arg[1]
				, out);
		}
		return singlearg_direct (0xa8 | register_number (arg[0])
			, arg[1]
			, out);
	}
	if (!r_str_casecmp (arg[1], "c")) {
		return singlearg_bit (0x92, arg[0], out);
	}
	if (!r_str_casecmp (arg[1], "a")) {
		return singlearg_direct (0xf5,  arg[0], out);
	}
	if (is_reg (arg[1])) {
		return singlearg_direct (0x88 | register_number (arg[1])
			, arg[0]
			, out);
	}
	if (is_indirect_reg (arg[1])) {
		return singlearg_direct (0x86 | register_number (arg[1])
			, arg[0]
			, out);
	}
	ut8 dest_addr;
	if (!address_direct (arg[0], &dest_addr)) {
		return false;
	}
	if (arg[1][0] == '#') {
		ut16 imm;
		if (!resolve_immediate (arg[1] + 1, &imm)) {
			return false;
		}
		(*out)[0] = 0x75;
		(*out)[1] = dest_addr;
		(*out)[2] = imm & 0x00FF;
		*out += 3;
		return true;
	}
	ut8 src_addr;
	if (!address_direct (arg[1], &src_addr)) {
		return false;
	}
	(*out)[0] = 0x85;
	(*out)[1] = src_addr;
	(*out)[2] = dest_addr;
	*out += 3;
	return true;
}

static bool mnem_movc(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	if (!str_iwhitecasecmp (arg[1], "@a+dptr")
		|| !str_iwhitecasecmp (arg[1], "[a+dptr]")) {
		return single_byte_instr (0x93, out);
	}
	if (!str_iwhitecasecmp (arg[1], "@a+pc")
		|| !str_iwhitecasecmp (arg[1], "[a+pc]")) {
		return single_byte_instr (0x83, out);
	}
	return false;
}

static bool mnem_movx(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp (arg[0], "a")) {
		if (is_indirect_reg (arg[1])) {
			return singlearg_register (0xe2, arg[1], out);
		}
		if (!str_iwhitecasecmp (arg[1], "@dptr")
			|| !str_iwhitecasecmp (arg[1], "[dptr]")) {
			return single_byte_instr (0xe0, out);
		}
	}
	if (r_str_casecmp (arg[1], "a")) {
		return false;
	}
	if (is_indirect_reg (arg[0])) {
		return singlearg_register (0xf2, arg[0], out);
	}
	if (!str_iwhitecasecmp (arg[0], "@dptr")
		|| !str_iwhitecasecmp (arg[0], "[dptr]")) {
		return single_byte_instr (0xf0, out);
	}
	return false;
}

static bool mnem_mul(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_ncasecmp ("ab", arg[0], 3)) {
		return false;
	}
	return single_byte_instr (0xa4, out);
}

static bool mnem_nop(char const*const*arg, ut16 pc, ut8**out) {
	return single_byte_instr (0x00, out);
}

static bool mnem_orl(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp (arg[0], "c")) {
		if (arg[1][0] == '/') {
			return singlearg_bit (0xa0, arg[1] + 1, out);
		}
		return singlearg_bit (0x72, arg[1], out);
	}
	if (!r_str_casecmp (arg[0], "a")) {
		if (is_indirect_reg (arg[1])) {
			return singlearg_register (0x46, arg[1], out);
		}
		if (arg[1][0] == '#') {
			return singlearg_immediate (0x44, arg[1], out);
		}
		if (is_reg (arg[1])) {
			return singlearg_register (0x48, arg[1], out);
		}
		return singlearg_direct (0x45, arg[1], out);
	}

	if (arg[1][0] != '#') {
		return singlearg_direct (0x42, arg[0], out);
	}

	ut8 dest_addr;
	if (!address_direct (arg[0], &dest_addr)) {
		return false;
	}
	ut16 imm;
	if (!resolve_immediate (arg[1] + 1, &imm)) {
		return false;
	}
	(*out)[0] = 0x43;
	(*out)[1] = dest_addr;
	(*out)[2] = imm & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_pop(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_direct (0xd0, arg[0], out);
}

static bool mnem_push(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_direct (0xc0, arg[0], out);
}

static bool mnem_ret(char const*const*arg, ut16 pc, ut8**out) {
	return single_byte_instr (0x22, out);
}

static bool mnem_reti(char const*const*arg, ut16 pc, ut8**out) {
	return single_byte_instr (0x32, out);
}

static bool mnem_rl(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x23, arg[0], out);
}

static bool mnem_rlc(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x33, arg[0], out);
}

static bool mnem_rr(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x03, arg[0], out);
}

static bool mnem_rrc(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x13, arg[0], out);
}

static bool mnem_setb(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp  ("c", arg[0])) {
		return single_byte_instr (0xd3, out);
	}
	return singlearg_bit (0xd2, arg[0], out);
}

static bool mnem_sjmp(char const*const*arg, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x80, arg[0], pc, out);
}

static bool mnem_jmp(char const*const*arg, ut16 pc, ut8**out) {
	if (!str_iwhitecasecmp (arg[0], "@a+dptr")
		|| !str_iwhitecasecmp (arg[0], "[a+dptr]")) {
		return single_byte_instr (0x73, out);
	}

	ut16 address;
	if (!to_address (arg[0], &address)) {
		return false;
	}
	ut16 reladdr;
	if ( pc < address ) {
		reladdr = address - pc;
	}
	else {
		reladdr = pc - address;
	}

	if ( reladdr < 0x100 ) {
		return mnem_sjmp (arg, pc, out);
	}
	else if ( reladdr < 0x08FF ) {
		return mnem_ajmp (arg, pc, out);
	}
	else {
		return mnem_ljmp (arg, pc, out);
	}
}

static bool mnem_subb(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	if (is_indirect_reg (arg[1])) {
		return singlearg_register (0x96, arg[1], out);
	}
	if (arg[1][0] == '#') {
		return singlearg_immediate (0x94, arg[1], out);
	}
	if (is_reg (arg[1])) {
		return singlearg_register (0x98, arg[1], out);
	}
	return singlearg_direct (0x95, arg[1], out);
}

static bool mnem_swap(char const*const*arg, ut16 pc, ut8**out) {
	return single_a_arg_instr (0xc4, arg[0], out);
}

static bool mnem_xrl(char const*const*arg, ut16 pc, ut8**out) {
	if (!r_str_casecmp (arg[0], "a")) {
		if (is_indirect_reg (arg[1])) {
			return singlearg_register (0x66, arg[1], out);
		}
		if (arg[1][0] == '#') {
			return singlearg_immediate (0x64, arg[1], out);
		}
		if (is_reg (arg[1])) {
			return singlearg_register (0x68, arg[1], out);
		}
		return singlearg_direct (0x65, arg[1], out);
	}
	if (arg[1][0] != '#') {
		if (r_str_casecmp (arg[1], "a")) {
			return false;
		}
		return singlearg_direct (0x62, arg[0], out);
	}
	ut8 dest_addr;
	if (!address_direct (arg[0], &dest_addr)) {
		return false;
	}
	ut16 imm;
	if (!resolve_immediate (arg[1] + 1, &imm)) {
		return false;
	}
	(*out)[0] = 0x63;
	(*out)[1] = dest_addr;
	(*out)[2] = imm & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_xch(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	if (is_indirect_reg (arg[1])) {
		return singlearg_register (0xc6, arg[1], out);
	}
	if (is_reg (arg[1])) {
		return singlearg_register (0xc8, arg[1], out);
	}
	return singlearg_direct (0xc5, arg[1], out);
}

static bool mnem_xchd(char const*const*arg, ut16 pc, ut8**out) {
	if (r_str_casecmp (arg[0], "a")) {
		return false;
	}
	if (!is_indirect_reg (arg[1])) {
		return false;
	}
	return singlearg_register (0xd6, arg[1], out);
}

/******************************************************************************
 * ## Section 6: mnemonic token dispatcher
                 -------------------------*/

static parse_mnem_args mnemonic(char const *user_asm, int*nargs) {
	return match_prefix_f (nargs, user_asm, (ftable){
	#define mnem(n, mn) { #mn " ", &mnem_ ## mn, n },
	#define zeroarg_mnem(mn) { #mn , &mnem_ ## mn, 0 },
		mnem (1, acall)
		mnem (2, addc)
		mnem (2, add)
		mnem (1, ajmp)
		mnem (2, anl)
		mnem (3, cjne)
		mnem (1, clr)
		mnem (1, cpl)
		mnem (1, da)
		mnem (1, dec)
		mnem (1, div)
		mnem (2, djnz)
		mnem (1, inc)
		mnem (2, jbc)
		mnem (2, jb)
		mnem (1, jc)
		mnem (1, jmp)
		mnem (2, jnb)
		mnem (1, jnc)
		mnem (1, jz)
		mnem (1, jnz)
		mnem (1, lcall)
		mnem (1, ljmp)
/* so uh, the whitespace-independent matching sees movc and mov c as the same
 * thing...
 * My first thought was to add an exception for mov c, but later I saw that it'd
 * be better to match the space after each instruction, but the exception is
 * still here
 */
		{ "mov c,", &mnem_mov_c, 2 },
		mnem (2, movc)
		mnem (2, movx)
		mnem (2, mov)
		mnem (1, mul)
		mnem (2, orl)
		mnem (1, pop)
		mnem (1, push)
		mnem (2, xchd)
		mnem (2, xch)
		mnem (2, xrl)
		mnem (1, rlc)
		mnem (1, rl)
		mnem (1, rrc)
		mnem (1, rr)
		mnem (1, setb)
		mnem (1, sjmp)
		mnem (2, subb)
		mnem (1, swap)
		zeroarg_mnem (nop)
		zeroarg_mnem (reti)
		zeroarg_mnem (ret)
	#undef mnem
		{0}});
}

/******************************************************************************
 * ## Section 7: radare2 glue and mnemonic tokenization
                 --------------------------------------*/

int assemble_8051(RAsm *a, RAsmOp *op, char const *user_asm) {
	if (!a || !op || !user_asm) {
		return 0;
	}
	r_strbuf_set (&op->buf_asm, user_asm);
	while (!terminates_asm_line (*user_asm)
		&& (*user_asm == ' ' || *user_asm == '\t')) {
		user_asm += 1;
	}
	char const *arguments = user_asm;
	while (!terminates_asm_line (*arguments)
		&& (('a' <= *arguments && *arguments <= 'z')
		|| ('A' <= *arguments && *arguments <= 'Z'))) {
		arguments += 1;
	}
	while (!terminates_asm_line (*arguments)
		&& (*arguments == ' ' || *arguments == '\t')) {
		arguments += 1;
	}
	char*arg[3] = {0};
	int nr_of_arguments = get_arguments (arg, arguments);
	char const*carg[3] = { arg[0], arg[1], arg[2] }; /* aliasing pointers...
		I need to pass char const *s, but I can't free char const *s
		not without compiler warnings, at least */
	int wants_arguments;
	parse_mnem_args mnem = mnemonic (user_asm, &wants_arguments);
	if (!mnem || nr_of_arguments != wants_arguments) {
		free (arg[2]); arg[2] = 0; carg[2] = 0;
		free (arg[1]); arg[1] = 0; carg[1] = 0;
		free (arg[0]); arg[0] = 0; carg[0] = 0;
		return 0;
	}
	ut8 instr[4] = {0};
	ut8 *binp = instr;
	if (!mnem (carg, a->pc, &binp)) {
		free (arg[0]); arg[0] = 0; carg[2] = 0;
		free (arg[1]); arg[1] = 0; carg[1] = 0;
		free (arg[2]); arg[2] = 0; carg[0] = 0;
		return 0;
	} else {
		free (arg[0]); arg[0] = 0; carg[2] = 0;
		free (arg[1]); arg[1] = 0; carg[1] = 0;
		free (arg[2]); arg[2] = 0; carg[0] = 0;
		size_t len = binp - instr;
		r_strbuf_setbin (&op->buf, instr, len);
		return binp - instr;
	}
}
