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
 * Basically it's for matching strings whitespace-independently, and uses c99s
 * (struct literal){} notation and is zero-terminated.
 * I wrote this thing in the late hours of r2con2019 while jetlagged.
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
 * Pretty much each instruction variant tokenizes its own instruction list,
 * which really isn't necessary because the number of arguments is constant for
 * each instruction, a fact that eventually even made it into the dispatcher, so
 * the dispatcher really could do the argument tokenization and save ~500 lines.
 *
 *
 * 6. mnemonic token dispatcher
 *
 * The weird datastructure returns! with macros! it's basically just a jump
 * table with one bit of validation, I'm planning to move more validation and
 * parsing to here to deduplicate.
 *
 *
 * 7. Radare2 glue and mnemonic tokenization
 *
 * Had one look at the gb glue code and copied the lot of it without really
 * understanding what I'm doing.
 *
 * also splits out the first word (asserted mnemonic) for the token dispatcher.
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
 * returns true if the number of arguments in the args string is less than n
 */
static bool n_args_lt(char const*args, int n) {
	char *dest = malloc (strlen (args) + 1);
	if (!args || n < 0) {
		return false;
	}
	if (n == 0 && args[0] == '\0') {
		return true;
	}
	if (args[0] == '\0') {
		return false;
	}
	dest[0] = ',';
	get_arg (args, n + 1, dest);
	bool ret = dest[0] == ',';
	free (dest);
	return ret;
}

/**
 * returns true if there is no more valid assembly code after this character
 */
static bool terminates_asm_line(char c) {
	return c == '\0' || c == '\n' || c == '\r' || c == ';' ;
}

/******************************************************************************
 * ## Section 2: some weird datastructure
                 ------------------------*/

typedef struct {
	char const*const pattern;
	int res;
} table[];

typedef bool (*parse_mnem_args)(char const*args, ut16 pc, ut8**out);

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
		while (isspace (str[si]) && !isspace (pattern[ti])) {
			si += 1;
		}
		if (isspace (pattern[ti])) {
			ti += 1;
			continue;
		}
		if (tolower (pattern[ti]) == tolower (str[si])) {
			si += 1;
			ti += 1;
		}
		else {
			return false;
		}
	}
	return true;
}

static int match_prefix(char const*str, table const tbl) {
	int row = 0;
	while (tbl[row].pattern) {
		if (pattern_match (str, tbl[row].pattern)) {
			return tbl[row].res;
		}
		else {
			row += 1;
		}
	}
	return tbl[row].res;
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
 * returns true if the given string is either @r0 or @r1, case insensitive
 */
static bool is_indirect_reg(char const*str)
{
	return str && str[0] == '@' && r_str_ansi_nlen (str, 4) == 3
		&& tolower (str[1]) == 'r'
		&& (str[2] == '0' || str[2] == '1');
}

/**
 * returns true if the given string denotes an 'r'-register
 */
static bool is_reg(char const*str)
{
	return str && tolower (str[0]) == 'r' && r_str_ansi_nlen (str, 3) == 2
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
	// FIXME: accept symbols as well as hex
	return parse_hexadecimal (imm_str, imm_out);
}

static bool to_address(char const* addr_str, ut16* addr_out) {
	// FIXME: accept symbols as well as hex
	return parse_hexadecimal (addr_str, addr_out);
}

/**
 * attempts to parse the given string as an 8bit-wide address
 */
static bool address_direct(char const* addr_str, ut8* addr_out) {
	ut16 addr_big;
	// FIXME: accept symbols as well as hex
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
	if (!separator) {
		// FIXME: accept symbols as well as dot-notation
		goto end;
	}
	r_str_ncpy (bytepart, addr_str, separator - addr_str + 1);
	bytepart[separator - addr_str + 1] = '\0';
	r_str_ncpy (bitpart, separator + 1, strlen(separator));
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
	free (bitpart);
	free (bytepart);
	return ret;
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

static bool single_a_arg_instr(ut8 const firstbyte, char const*arg
	, ut8 **out)
{
	if (r_str_ncasecmp ("a", arg, 2)) {
		return false;
	}
	return single_byte_instr (firstbyte, out);
}

/******************************************************************************
 * ## Section 5: Specific instruction parsing
                 ----------------------------*/

static bool mnem_acall(char const*args, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (args, &address)) {
		return false;
	}
	(*out)[0] = ((address & 0x0700) >> 3) | 0x11;
	(*out)[1] = address & 0x00FF;
	*out += 2;
	return true;
}

static bool mnem_add(char const*args, ut16 pc, ut8**out) {
	enum add_class {
		add_indirect,
		add_immediate,
		add_direct_or_register,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "a,@r",add_indirect },
		{ "a,#", add_immediate },
		{ "a,", add_direct_or_register },
		{ 0, -1 }})) {
	default: ret = false;
	break; case add_indirect: {
		if(!get_arg (args, 2 , arg) || !is_indirect_reg(arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0x26 | (arg[2] - '0'), out);
		}
	}
	break; case add_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x24, arg, out);
		}
	}
	break; case add_direct_or_register: {
		get_arg (args, 2, arg);
		if (is_reg (arg)) {
			ret = single_byte_instr (0x28 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0x25, arg, out);
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_addc(char const*args, ut16 pc, ut8**out) {
	enum addc_class {
		addc_indirect,
		addc_immediate,
		addc_direct_or_register,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table){
		{ "a,@r", addc_indirect },
		{ "a,#", addc_immediate },
		{ "a,", addc_direct_or_register },
		{ 0, -1 }})) {
	default: ret = false;
	break; case addc_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0x36 | (arg[2] - '0'), out);
		}
	}
	break; case addc_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x34, arg, out);
		}
	}
	break; case addc_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
			break;
		}
		if (is_reg (arg)) {
			ret = single_byte_instr(0x38 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0x35, arg, out);
		}
	} }
	return ret;
}

static bool mnem_ajmp(char const*args, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (args, &address)) {
		return false;
	}
	(*out)[0] = ((address & 0x0700) >> 3 ) | 0x01;
	(*out)[1] = address & 0x00FF;
	*out += 2;
	return true;
}

static bool mnem_anl(char const*args, ut16 pc, ut8**out) {
	enum anl_class {
		anl_indirect,
		anl_immediate,
		anl_direct_or_register,
		anl_carry_inverted,
		anl_carry,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch(match_prefix(args, (table){
		{ "a,@r", anl_indirect },
		{ "a,#", anl_immediate },
		{ "a,", anl_direct_or_register },
		{ "c,/", anl_carry_inverted },
		{ "c,", anl_carry },
		{ 0, -1 }})) {
	default: ret = false;
	break; case anl_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr(0x56 | (arg[2] - '0'), out);
		}
	}
	break; case anl_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x54, arg, out);
		}
	}
	break; case anl_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if(is_reg (arg)) {
			ret = single_byte_instr(0x58 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0x55, arg, out);
		}
	}
	break; case anl_carry_inverted: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_bit (0xb0, arg + 1, out);
		}
	}
	break; case anl_carry: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_bit (0x82, arg, out);
		}
	}
	break; case -1: {
		char *firstarg = malloc (strlen (args) + 1);
		ut8 address;
		if (!get_arg (args, 1, firstarg)
			|| !address_direct (firstarg, &address)) {
			ret = false;
		}
		char *secondarg = malloc (strlen (args) + 1);
		if (!get_arg (args, 2, secondarg)) {
			ret = false;
			free (firstarg);
			free (secondarg);
			goto end;
		}
		free (firstarg);
		if (r_str_ncasecmp ("a", secondarg, 2)) {
			ut16 imm;
			if (secondarg[0] != '#'
				|| !resolve_immediate (secondarg + 1, &imm)) {
				ret = false;
			} else {
				(*out)[0] = 0x53;
				(*out)[1] = address;
				(*out)[2] = imm & 0x00FF;
				*out += 3;
				ret = true;
			}
		} else {
			(*out)[0] = 0x52;
			(*out)[1] = address;
			*out += 2;
			ret = true;
		}
	} }
end:
	free (arg);
	return ret;
}

static bool mnem_cjne(char const*args, ut16 pc, ut8**out) {
	enum cjne_class {
		cjne_indirect,
		cjne_immediate,
		cjne_direct,
		cjne_register,
	};

	char *arg = malloc (strlen (args) + 1);
	bool ret;
	ut16 address;
	if (!get_arg (args, 3, arg) || !to_address (arg, &address)
		|| !relative_address (pc+1, address, (*out)+2)) {
		free (arg);
		return false;
	}
	switch(match_prefix(args, (table) {
	{ "@r", cjne_indirect },
	{ "a,#", cjne_immediate },
	{ "a,", cjne_direct },
	{ "r", cjne_register },
	{ 0, -1 }})) {
	default: ret = false;
	break; case cjne_indirect: {
		ut16 imm;
		if (!get_arg (args, 1, arg) || !is_indirect_reg (arg)) {
			ret = false;
			break;
		}
		(*out)[0] = 0xb6 | (arg[2] - '0');
		get_arg (args, 2, arg);
		if (!resolve_immediate (arg + 1, &imm)) {
			ret = false;
		} else {
			(*out)[1] = imm & 0x00FF;
			*out += 3;
			ret = true;
		}
	}
	break; case cjne_immediate: {
		ut16 imm;
		if (!get_arg (args, 2, arg)
			|| !resolve_immediate (arg + 1, &imm)) {
			ret = false;
		} else {
			(*out)[0] = 0xb4;
			(*out)[1] = imm & 0x00FF;
			*out += 3;
			ret = true;
		}
	}
	break; case cjne_direct: {
		ut8 address;
		if (!get_arg (args, 2, arg) || !address_direct (arg, &address)) {
			ret = false;
		} else {
			(*out)[0] = 0xb5;
			(*out)[1] = address;
			*out += 3;
			ret = true;
		}
	}
	break; case cjne_register: {
		ut16 imm;
		if (!get_arg (args, 2, arg) || !resolve_immediate (arg + 1, &imm)) {
			ret = false;
			break;
		}
		(*out)[0] = 0xbf | (arg[1] - '0');
		if (!get_arg (args, 1, arg) || !is_reg(arg)) {
			ret = false;
		} else {
			(*out)[1] = imm & 0x00FF;
			*out += 3;
			ret = true;
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_clr(char const*args, ut16 pc, ut8**out) {
	if (!r_str_ncasecmp  ("a", args, 2)) {
		return single_byte_instr (0xe4, out);
	}
	if (!r_str_ncasecmp  ("c", args, 2)) {
		return single_byte_instr (0xc3, out);
	}
	return singlearg_bit (0xc2, args, out);
}

static bool mnem_cpl(char const*args, ut16 pc, ut8**out) {
	if (!r_str_ncasecmp  ("a", args, 2)) {
		return single_byte_instr (0xf4, out);
	}
	if (!r_str_ncasecmp  ("c", args, 2)) {
		return single_byte_instr (0xb3, out);
	}
	return singlearg_bit (0xb2, args, out);
}

static bool mnem_da(char const*args, ut16 pc, ut8**out) {
	if (r_str_ncasecmp ("a", args, 2)) {
		return false;
	}
	return single_byte_instr (0xd4, out);
}

static bool mnem_dec(char const*args, ut16 pc, ut8**out) {
	if (is_indirect_reg (args)) {
		return single_byte_instr(0x16 | (args[2] - '0'), out);
	}
	if (is_reg (args)) {
		return single_byte_instr(0x18 | (args[1] - '0'), out);
	}
	if (!r_str_ncasecmp ("a", args, 2)) {
		return single_byte_instr(0x14, out);
	}
	return singlearg_direct (0x15, args, out);
}

static bool mnem_div(char const*args, ut16 pc, ut8**out) {
	if (r_str_ncasecmp  ("ab", args, 3)) {
		return false;
	}
	return single_byte_instr (0x84, out);
}

static bool mnem_djnz(char const*args, ut16 pc, ut8**out) {
	char *secondarg = malloc (strlen (args) + 1);
	bool ret = true;
	{
		ut16 address;
		if (!get_arg (args, 2, secondarg)) {
			ret = false;
		} else if (!to_address (secondarg, &address)) {
			ret = false;
		} else if (! relative_address (pc, address, (*out) + 2)) {
			ret = false;
		}
	}
	free (secondarg);
	if (!ret) {
		return ret;
	}
	char *firstarg = malloc (strlen (args) + 1);
	ut8 address;
	if (!get_arg (args, 1, firstarg)) {
		ret = false;
	} else if (is_reg (firstarg)) {
		(*out)[0] = 0xd8 | (firstarg[1] - '0');
		(*out)[1] = (*out)[2];
		*out += 2;
		ret = true;
	} else if (!address_direct (firstarg, &address)) {
		ret = false;
	} else {
		(*out)[0] = 0xd5;
		(*out)[1] = address;
		(*out)[2] -= 1;
		*out += 3;
		ret = true;
	}
	free (firstarg);
	return ret;
}

static bool mnem_inc(char const*args, ut16 pc, ut8**out) {
	if (is_reg (args)) {
		return single_byte_instr(0x08 | (args[1] - '0'), out);
	}
	if (is_indirect_reg (args)) {
		return single_byte_instr(0x06 | (args[2] - '0'), out);
	}
	if (!r_str_ncasecmp  ("a", args, 2)) {
		return single_byte_instr(0x04, out);
	}
	if (!r_str_ncasecmp  ("dptr", args, 5)) {
		return single_byte_instr(0xa3, out);
	}
	return singlearg_direct (0x05, args, out);
}

static bool mnem_jb(char const*args, ut16 pc, ut8**out) {
	char *secondarg = malloc (strlen (args) + 1);
	{ ut16 address;
	if (!get_arg (args, 2, secondarg)
		|| !to_address (secondarg, &address)
		|| !relative_address (pc + 1, address, (*out) + 2)) {
		free (secondarg);
		return false;
	} }
	free (secondarg);
	char *firstarg = malloc (strlen (args) + 1);
	ut8 address;
	if (!get_arg (args, 1, firstarg)
		|| !address_bit (firstarg, &address)) {
		free (firstarg);
		return false;
	}
	free (firstarg);
	(*out)[0] = 0x20;
	(*out)[1] = address;
	*out += 3;
	return true;
}

static bool mnem_jbc(char const*args, ut16 pc, ut8**out) {
	char *secondarg = malloc (strlen (args) + 1);
	{ ut16 address;
	if (!get_arg (args, 2, secondarg)) {
		free (secondarg);
		return false;
	}
	if (!to_address (secondarg, &address)
		|| !relative_address (pc + 1, address, (*out) + 2)) {
		free (secondarg);
		return false;
	} }
	free (secondarg);
	char *firstarg = malloc (strlen (args) + 1);
	ut8 address;
	if (!get_arg (args, 1, firstarg)
		|| !address_bit (firstarg, &address)) {
		free (firstarg);
		return false;
	}
	(*out)[0] = 0x10;
	(*out)[1] = address;
	*out += 3;
	free (firstarg);
	return true;
}

static bool mnem_jc(char const*args, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x40, args, pc, out);
}

static bool mnem_jnb(char const*args, ut16 pc, ut8**out) {
	char *secondarg = malloc (strlen (args) + 1);
	{
		ut16 address;
		if (!get_arg (args, 2, secondarg)
			|| !to_address (secondarg, &address)
			|| !relative_address (pc + 1, address, (*out) + 2)) {
			free (secondarg);
			return false;
		}
	}
	free (secondarg);
	char *firstarg = malloc (strlen (args) + 1);
	ut8 address;
	if( !get_arg (args, 1, firstarg)
		|| !address_bit (firstarg, &address)) {
		free (firstarg);
		return false;
	}
	free (firstarg);
	(*out)[0] = 0x30;
	(*out)[1] = address; //FIXME: may not be 16 bit
	*out += 3;
	return true;
}

static bool mnem_jnc(char const*args, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x50, args, pc, out);
}

static bool mnem_jnz(char const*args, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x70, args, pc, out);
}

static bool mnem_jz(char const*args, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x60, args, pc, out);
}

static bool mnem_lcall(char const*args, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (args, &address)) {
		return false;
	}
	(*out)[0] = 0x12;
	(*out)[1] = ((address & 0xFF00) >> 8) & 0x00FF;
	(*out)[2] = address & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_ljmp(char const*args, ut16 pc, ut8**out) {
	ut16 address;
	if (!to_address (args, &address)) {
		return false;
	}
	(*out)[0] = 0x02;
	(*out)[1] = ((address & 0xFF00) >> 8) & 0x00FF;
	(*out)[2] = address & 0x00FF;
	*out += 3;
	return true;
}

static bool mnem_mov_c(char const*args, ut16 pc, ut8**out) {
	char *arg;
	arg = malloc (strlen (args) + 1);
	if (!get_arg (args, 2, arg)) {
		return false;
	}
	return singlearg_bit (0xa2, arg, out);
}

static bool mnem_mov(char const*args, ut16 pc, ut8**out) {
	enum mov_class {
		mov_c_bit,
		mov_dptr,
		mov_a_indirect,
		mov_a_immidiate,
		mov_a_direct_or_register,
		mov_indirect_any,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "dptr,#", mov_dptr },
		{ "@r", mov_indirect_any },
		{ "a,@r", mov_a_indirect },
		{ "a,#", mov_a_immidiate },
		{ "a,", mov_a_direct_or_register },
		{ 0, -1 }})) {
	default: ret = false;
	break; case mov_dptr: {
		ut16 imm;
		if (!get_arg (args, 2, arg)
			|| !resolve_immediate (arg + 1, &imm)) {
			ret = false;
		} else {
			(*out)[0] = 0x90;
			(*out)[1] = imm >> 8;
			(*out)[2] = imm;
			*out += 3;
			ret = true;
		}
	}
	break; case mov_a_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr(0xe6 | (arg[2] - '0'), out);
		}
	}
	break; case mov_indirect_any: {
		if (!get_arg (args, 1, arg) || !is_indirect_reg (arg)) {
			ret = false;
			break;
		}
		(*out)[0] = 0x06 | (arg[2] - '0');
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (!r_str_ncasecmp ("a", arg, 2)) {
			ret = single_byte_instr(0xf0 | (*out)[0], out);
		} else if (arg[0] != '#') {
			ret = singlearg_direct(0xa0 | (*out)[0], arg, out);
		} else {
			ret = singlearg_immediate ((*out)[0] | 0x70, arg, out);
		}
	}
	break; case mov_a_immidiate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x74, arg, out);
		}
	}
	break; case mov_a_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (is_reg (arg)) {
			ret = single_byte_instr (0xe8 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0xe5, arg, out);
		}
	}
	break; case -1: {
		char *firstarg = malloc (strlen (args) + 1);
		char *secondarg = malloc (strlen (args) + 1);
		if (!get_arg (args, 1, firstarg)
			|| !get_arg (args, 2, secondarg)) {
			ret = false;
		} else if (is_reg (firstarg)) {
			if (!r_str_ncasecmp ("a", secondarg, 2)) {
				ret = single_byte_instr ( 0xf8 | (firstarg[1] - '0'), out);
			} else if (secondarg[0] == '#') {
				ret = singlearg_immediate (0x78 | (firstarg[1] - '0'), secondarg, out);
			} else {
				ret = singlearg_direct (0xa8 | (firstarg[1] - '0')
					, secondarg, out);
			}
		} else if (!r_str_ncasecmp  ("c", secondarg, 2)) {
			ret = singlearg_bit (0x92, firstarg, out);
		} else if (!r_str_ncasecmp ("a", secondarg, 2)) {
			ret = singlearg_direct (0xf5, firstarg, out);
		} else if (is_reg (secondarg)) {
			ret = singlearg_direct (0x88 | (secondarg[1] - '0')
				, firstarg, out);
		} else if (is_indirect_reg (secondarg)) {
			ret = singlearg_direct (0x86 | (secondarg[2] - '0')
				, firstarg, out);
		} else {
			ut8 dest_addr;
			ut16 imm;
			ut8 src_addr;
			if (!address_direct (firstarg, &dest_addr)) {
				ret = false;
			} else if (secondarg[0] == '#'
				&& resolve_immediate (secondarg + 1, &imm)) {
				(*out)[0] = 0x75;
				(*out)[1] = dest_addr;
				(*out)[2] = imm & 0x00FF;
				*out += 3;
				ret = true;
			} else if (!address_direct (secondarg, &src_addr)) {
				ret = false;
			} else {
				(*out)[0] = 0x85;
				(*out)[1] = src_addr;
				(*out)[2] = dest_addr;
				*out += 3;
				ret = true;
			}
		}
		free (firstarg);
		free (secondarg);
	} }
	free (arg);
	return ret;
}

static bool mnem_movc(char const*args, ut16 pc, ut8**out) {
	enum movc_class {
		movc_dptr,
		movc_pc,
	};

	switch (match_prefix (args, (table) {
		{ "a,@a+dptr", movc_dptr },
		{ "a,@a+pc", movc_pc, },
		{ 0, -1 }})) {
	default: return false;
	break; case movc_dptr:
		if (r_str_casestr (args, "dptr")[4] != '\0') {
			return false;
		}
		return single_byte_instr (0x93, out);
	break; case movc_pc: {
		char const* pcp = r_str_casestr (args, "pc");
		if (pcp[2] != '\0') {
			return false;
		}
		return single_byte_instr (0x83, out);
	} }
}

static bool mnem_movx(char const*args, ut16 pc, ut8**out) {
	enum movx_class {
		movx_indirect_read,
		movx_dptr_read,
		movx_indirect_write,
		movx_dptr_write,
	};
	char *arg;
	arg = malloc (strlen (args) + 1);
	bool ret;

	switch (match_prefix (args, (table){
		{ "a,@r", movx_indirect_read },
		{ "a,@dptr", movx_dptr_read },
		{ "@r", movx_indirect_write },
		{ "@dptr,a", movx_dptr_write },
		{ 0, -1 }})) {
	default: ret = false;
	break; case movx_dptr_read: {
		if (!get_arg (args, 1, arg) || strcmp (arg, "a")) {
			ret = false;
		} else {
			ret = single_byte_instr (0xe0, out);
		}
	}
	break; case movx_dptr_write: {
		if (!get_arg (args, 2, arg) || strcmp (arg, "a")) {
			ret = false;
		} else {
			ret = single_byte_instr (0xf0, out);
		}
	}
	break; case movx_indirect_read: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0xe2 | (arg[2] - '0'), out);
		}
	}
	break; case movx_indirect_write: {
		if (!get_arg (args, 1, arg) || !is_indirect_reg(arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0xf2 | (arg[2] - '0'), out);
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_mul(char const*args, ut16 pc, ut8**out) {
	if (r_str_ncasecmp ("ab", args, 3)) {
		return false;
	}
	return single_byte_instr (0xa4, out);
}

static bool mnem_nop(char const*args, ut16 pc, ut8**out) {
	if (args[0] != '\0') {
		return false;
	}
	return single_byte_instr (0x00, out);
}

static bool mnem_orl(char const*args, ut16 pc, ut8**out) {
	enum orl_class {
		orl_indirect,
		orl_immediate,
		orl_direct_or_register,
		orl_carry_inverted,
		orl_carry,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "a,@r", orl_indirect },
		{ "a,#", orl_immediate },
		{ "a,", orl_direct_or_register },
		{ "c,/", orl_carry_inverted },
		{ "c,", orl_carry },
		{ 0, -1 }})) {
	default: ret = false;
	break; case orl_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0x46 | (arg[2] - '0'), out);
		}
	}
	break; case orl_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x44, arg, out);
		}
	}
	break; case orl_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (is_reg (arg)) {
			ret = single_byte_instr (0x48 | (arg[1] - '0' ), out);
		} else {
			ret = singlearg_direct (0x45, arg, out);
		}
	}
	break; case orl_carry_inverted: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_bit (0xa0, arg + 1, out);
		}
	}
	break; case orl_carry: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_bit (0x72, arg, out);
		}
	}
	break; case -1: {
		char *firstarg = malloc (strlen (args) + 1);
		ut8 address;
		if (!get_arg (args, 1, firstarg)
			|| !address_direct (firstarg, &address)) {
			free (firstarg);
			free (arg);
			return false;
		}
		char *secondarg = malloc (strlen (args) + 1);
		if (!get_arg (args, 2, secondarg)) {
			free (firstarg);
			free (secondarg);
			free (arg);
			return false;
		}
		free (firstarg);
		if (secondarg[0] == '#' ) {
			ut16 imm;
			if (!resolve_immediate (secondarg + 1, &imm)) {
				ret = false;
			} else {
				(*out)[0] = 0x43;
				(*out)[1] = address; //FIXME: may not be 16 bit
				(*out)[2] = imm & 0x00FF;
				*out += 3;
				ret = true;
			}
		} else {
			(*out)[0] = 0x42;
			(*out)[1] = address; //FIXME: may not be 16 bit
			*out += 2;
			ret = true;
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_pop(char const*args, ut16 pc, ut8**out) {
	return singlearg_direct(0xd0, args, out);
}

static bool mnem_push(char const*args, ut16 pc, ut8**out) {
	return singlearg_direct(0xc0, args, out);
}

static bool mnem_ret(char const*args, ut16 pc, ut8**out) {
	if (args[0] != '\0') {
		return false;
	}
	return single_byte_instr (0x22, out);
}

static bool mnem_reti(char const*args, ut16 pc, ut8**out) {
	if (args[0] != '\0') {
		return false;
	}
	return single_byte_instr (0x32, out);
}

static bool mnem_rl(char const*args, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x23, args, out);
}

static bool mnem_rlc(char const*args, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x33, args, out);
}

static bool mnem_rr(char const*args, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x03, args, out);
}

static bool mnem_rrc(char const*args, ut16 pc, ut8**out) {
	return single_a_arg_instr (0x13, args, out);
}

static bool mnem_setb(char const*args, ut16 pc, ut8**out) {
	if (!r_str_ncasecmp  ("c", args, 2)) {
		return single_byte_instr (0xd3, out);
	}
	return singlearg_bit (0xd2, args, out);
}

static bool mnem_sjmp(char const*args, ut16 pc, ut8**out) {
	return singlearg_reladdr (0x80, args, pc, out);
}

static bool mnem_jmp(char const*args, ut16 pc, ut8**out) {
	if (match_prefix (args, (table){ {"@a+dptr", true}, {0, false}})
		&& r_str_casestr (args, "dptr")[4] == '\0') {
		(*out)[0] = 0x73;
		*out += 1;
		return true;
	}
	ut16 address;
	if (!to_address (args, &address)) {
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
		return mnem_sjmp (args, pc, out);
	}
	else if ( reladdr < 0x08FF ) {
		return mnem_ajmp (args, pc, out);
	}
	else {
		return mnem_ljmp (args, pc, out);
	}
}

static bool mnem_subb(char const*args, ut16 pc, ut8**out) {
	enum subb_class {
		subb_indirect,
		subb_immediate,
		subb_direct_or_register,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "a,@r", subb_indirect },
		{ "a,#", subb_immediate },
		{ "a,", subb_direct_or_register },
		{ 0, -1 }})) {
	default: ret = false;
	break; case subb_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0x96 | (arg[2] - '0'), out);
		}
	}
	break; case subb_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x94, arg, out);
		}
	}
	break; case subb_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (is_reg (arg)) {
			ret = single_byte_instr (0x9d, out);
		} else {
			ret = singlearg_direct (0x95, arg, out);
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_swap(char const*args, ut16 pc, ut8**out) {
	return single_a_arg_instr (0xc4, args, out);
}

static bool mnem_xrl(char const*args, ut16 pc, ut8**out) {
	enum xrl_class {
		xrl_indirect,
		xrl_immediate,
		xrl_direct_or_register,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "a,@r", xrl_indirect },
		{ "a,#", xrl_immediate },
		{ "a,", xrl_direct_or_register },
		{ 0, -1 }})) {
	default: ret = false;
	break; case xrl_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0x66 | (arg[2] - '0'), out);
		}
	}
	break; case xrl_immediate: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else {
			ret = singlearg_immediate (0x64, arg, out);
		}
	}
	break; case xrl_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (is_reg (arg)) {
			ret = single_byte_instr (0x68 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0x65, arg, out);
		}
	}
	break; case -1: {
		char *firstarg = malloc (strlen (args) + 1);
		ut8 address;
		if (!get_arg (args, 1, firstarg)
			|| !address_direct (firstarg, &address)) {
			ret = false;
			break;
		}
		free (firstarg);
		(*out)[1] = address; //FIXME: may not be 16 bit
		char *secondarg = malloc (strlen (args) + 1);
		if (!get_arg (args, 2, secondarg)) {
			ret = false;
		} else if (secondarg[0] == '#') {
			ut16 imm;
			if (!resolve_immediate (secondarg + 1, &imm)) {
				ret = false;
			} else {
				(*out)[0] = 0x63;
				(*out)[2] = imm & 0x00FF;
				*out += 3;
				ret = true;
			}
		} else if (r_str_ncasecmp  ("a", secondarg, 2)) {
			ret = false;
		} else {
			(*out)[0] = 0x62;
			*out += 2;
			ret = true;
		}
		free (secondarg);
	} }
	free (arg);
	return ret;
}

static bool mnem_xch(char const*args, ut16 pc, ut8**out) {
	enum xch_class {
		xch_indirect,
		xch_direct_or_register,
	};
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	switch (match_prefix (args, (table) {
		{ "a,@r", xch_indirect },
		{ "a,", xch_direct_or_register},
		{ 0, -1 }})) {
	default: ret = false;
	break; case xch_indirect: {
		if (!get_arg (args, 2, arg) || !is_indirect_reg (arg)) {
			ret = false;
		} else {
			ret = single_byte_instr (0xc6 | (arg[1] - '0'), out);
		}
	}
	break; case xch_direct_or_register: {
		if (!get_arg (args, 2, arg)) {
			ret = false;
		} else if (is_reg (arg)) {
			ret = single_byte_instr (0xc8 | (arg[1] - '0'), out);
		} else {
			ret = singlearg_direct (0xc5, arg, out);
		}
	} }
	free (arg);
	return ret;
}

static bool mnem_xchd(char const*args, ut16 pc, ut8**out) {
	char *arg = malloc (strlen (args) + 1);
	bool ret;
	if (!match_prefix (args, (table) { {"a,@r", true}, {0, false}})
		|| !get_arg (args, 2, arg)) {
		ret = false;
	} else {
		ret = single_byte_instr (0xd6 | (arg[2] - '0'), out);
	}
	free (arg);
	return ret;
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
		mnem (2, swap)
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
	size_t arglen = strlen (arguments);
	char *arguments_buf = malloc (arglen + 1);
	r_str_ncpy (arguments_buf, arguments, arglen + 1);
	int nargs;
	parse_mnem_args mnem = mnemonic (user_asm, &nargs);
	if (!mnem || !n_args_lt(arguments_buf, nargs)) {
		free (arguments_buf);
		return 0;
	}
	ut8 instr[4] = {0};
	ut8 *binp = instr;
	if (!mnem (arguments_buf, a->pc, &binp)) {
		free (arguments_buf);
		return 0;
	} else {
		free (arguments_buf);
		size_t len = binp - instr;
		r_strbuf_setbin(&op->buf, instr, len);
		return binp - instr;
	}
}
