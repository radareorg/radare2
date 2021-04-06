/* radare - LGPL - Copyright 2010-2018 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>
#include "armass16_const.h"

// TODO: only lo registers accessible in thumb arm

typedef struct {
	ut64 off;
	ut32 o;
	char op[128];
	char opstr[128];
	char *a[16]; /* only 15 arguments can be used! */
} ArmOpcode;

typedef struct {
	const char *name;
	int code;
	int type;
} ArmOp;

enum {
	TYPE_MOV = 1,
	TYPE_TST = 2,
	TYPE_SWI = 3,
	TYPE_HLT = 4,
	TYPE_BRA = 5,
	TYPE_BRR = 6,
	TYPE_ARI = 7,
	TYPE_IMM = 8,
	TYPE_MEM = 9,
	TYPE_BKP = 10,
	TYPE_SWP = 11,
	TYPE_MOVW = 12,
	TYPE_MOVT = 13,
	TYPE_UDF = 14,
	TYPE_SHFT = 15,
	TYPE_COPROC = 16,
	TYPE_ENDIAN = 17,
	TYPE_MUL = 18,
	TYPE_CLZ = 19,
	TYPE_REV = 20,
	TYPE_NEG = 21
};

static int strcmpnull(const char *a, const char *b) {
	return (a && b) ? strcmp (a, b) : -1;
}

// static const char *const arm_shift[] = {"lsl", "lsr", "asr", "ror"};

static ArmOp ops[] = {
	{ "adc", 0xa000, TYPE_ARI },
	{ "adcs", 0xb000, TYPE_ARI },
	{ "adds", 0x9000, TYPE_ARI },
	{ "add", 0x8000, TYPE_ARI },
	{ "bkpt", 0x2001, TYPE_BKP },
	{ "subs", 0x5000, TYPE_ARI },
	{ "sub", 0x4000, TYPE_ARI },
	{ "sbcs", 0xd000, TYPE_ARI },
	{ "sbc", 0xc000, TYPE_ARI },
	{ "rsb", 0x6000, TYPE_ARI },
	{ "rsbs", 0x7000, TYPE_ARI },
	{ "rsc", 0xe000, TYPE_ARI },
	{ "rscs", 0xf000, TYPE_ARI },
	{ "bic", 0x0000c0e1, TYPE_ARI },

	{ "udf", 0xf000f000, TYPE_UDF },

	{ "push", 0x2d09, TYPE_IMM },
	{ "pop", 0xbd08, TYPE_IMM },

	{ "cps", 0xb1, TYPE_IMM },
	{ "nop", 0xa0e1, -1 },

	{ "ldrex", 0x9f0f9000, TYPE_MEM },
	{ "ldr", 0x9000, TYPE_MEM },

	{ "strexh", 0x900fe000, TYPE_MEM },
	{ "strexb", 0x900fc000, TYPE_MEM },
	{ "strex", 0x900f8000, TYPE_MEM },
	{ "strbt", 0x0000e0e4, TYPE_MEM },
	{ "strb", 0x0000c0e5, TYPE_MEM },
	{ "strd", 0xf000c0e1, TYPE_MEM },
	{ "strh", 0xb00080e1, TYPE_MEM },
	{ "str", 0x8000, TYPE_MEM },

	{ "blx", 0x30ff2fe1, TYPE_BRR },
	{ "bx", 0x10ff2fe1, TYPE_BRR },

	{ "bl", 0xb, TYPE_BRA },
// bx/blx - to register, b, bne,.. justjust  offset
//    2220:       e12fff1e        bx      lr
//    2224:       e12fff12        bx      r2
//    2228:       e12fff13        bx      r3

	//{ "bx", 0xb, TYPE_BRA },
	{ "b", 0xa, TYPE_BRA },

	//{ "mov", 0x3, TYPE_MOV },
	//{ "mov", 0x0a3, TYPE_MOV },
	{ "movw", 0x3, TYPE_MOVW },
	{ "movt", 0x4003, TYPE_MOVT },
	{ "mov", 0xa001, TYPE_MOV },
	{ "mvn", 0xe000, TYPE_MOV },
	{ "svc", 0xf, TYPE_SWI }, // ???
	{ "hlt", 0x70000001, TYPE_HLT }, // ???u

	{ "mul", 0x900000e0, TYPE_MUL},
	{ "smull", 0x9000c0e0, TYPE_MUL},
	{ "umull", 0x900080e0, TYPE_MUL},
	{ "smlal", 0x9000e0e0, TYPE_MUL},
	{ "smlabb", 0x800000e1, TYPE_MUL},
	{ "smlabt", 0xc00000e1, TYPE_MUL},
	{ "smlatb", 0xa00000e1, TYPE_MUL},
	{ "smlatt", 0xe00000e1, TYPE_MUL},
	{ "smlawb", 0x800020e1, TYPE_MUL},
	{ "smlawt", 0xc00020e1, TYPE_MUL},


	{ "ands", 0x1000, TYPE_ARI },
	{ "and", 0x0000, TYPE_ARI },
	{ "eors", 0x3000, TYPE_ARI },
	{ "eor", 0x2000, TYPE_ARI },
	{ "orrs", 0x9001, TYPE_ARI },
	{ "orr", 0x8001, TYPE_ARI },

	{ "cmp", 0x5001, TYPE_TST },
	{ "swp", 0xe1, TYPE_SWP },
	{ "cmn", 0x0, TYPE_TST },
	{ "teq", 0x0, TYPE_TST },
	{ "tst", 0xe1, TYPE_TST },

	{"lsr", 0x3000a0e1, TYPE_SHFT},
	{"asr", 0x5000a0e1, TYPE_SHFT},
	{"lsl", 0x1000a0e1, TYPE_SHFT},
	{"ror", 0x7000a0e1, TYPE_SHFT},

	{"rev16", 0xb00fbf06, TYPE_REV},
	{"revsh", 0xb00fff06, TYPE_REV},
	{"rev",   0x300fbf06, TYPE_REV},
	{"rbit",  0x300fff06, TYPE_REV},

	{"mrc", 0x100010ee, TYPE_COPROC},
	{"setend", 0x000001f1, TYPE_ENDIAN},
	{ "clz", 0x000f6f01, TYPE_CLZ},
	{ "neg", 0x7000, TYPE_NEG },

	{ NULL }
};

static const ut64 M_BIT = 0x1;
static const ut64 S_BIT = 0x2;
static const ut64 C_BITS = 0x3c;
static const ut64 DOTN_BIT = 0x40;
static const ut64 DOTW_BIT = 0x80;
static const ut64 L_BIT = 0x100;
static const ut64 X_BIT = 0x200;
static const ut64 TWO_BIT = 0x400;
static const ut64 IE_BIT = 0x800;
static const ut64 ID_BIT = 0x1000;
static const ut64 EA_BIT = 0x2000;
static const ut64 FD_BIT = 0x4000;
static const ut64 T_BIT = 0x8000;
static const ut64 B_BIT = 0x10000;
static const ut64 H_BIT = 0x20000;
static const ut64 D_BIT = 0x40000;
static const ut64 W_BIT = 0x80000;
static const ut64 EIGHT_BIT = 0x100000;
static const ut64 SIXTEEN_BIT = 0x200000;
static const ut64 BB_BIT = 0x400000;
static const ut64 BT_BIT = 0x800000;
static const ut64 TB_BIT = 0x1000000;
static const ut64 TT_BIT = 0x2000000;
static const ut64 R_BIT = 0x4000000;
static const ut64 IA_BIT = 0x8000000;
static const ut64 DB_BIT = 0x10000000;
static const ut64 SH_BIT = 0x20000000;
static const ut64 WB_BIT = 0x40000000;
static const ut64 WT_BIT = 0x80000000;
static const ut64 C_MATCH_BIT = 0x100000000;

static char *parse_hints(char *input) {
	if (!strcmpnull (input, "unst")) {
		return "6";
	}
	if (!strcmpnull (input, "un")) {
		return "7";
	}
	if (!strcmpnull (input, "st")) {
		return "14";
	}
	if (!strcmpnull (input, "sy")) {
		return "15";
	}
	return "-1";
}

static st8 iflag(char *input) {
	st8 res = 0;
	r_str_case (input, false);
	
	for (; *input; input++) {
		switch (*input) {
		case 'a':
			res |= 0x4;
			break;
		case 'i':
			res |= 0x2;
			break;
		case 'f':
			res |= 0x1;
			break;
		default:
			return -1;
		}
	}
	return res;
}

static ut64 cqcheck(char **input) {
	ut64 res = 0;
	int i;
	ut8 offset = 0;
	
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	for (i = 0; conds[i]; i++) {
		if (r_str_startswith (*input, conds[i])) {
			res |= C_MATCH_BIT;
			res |= i << 2;
			*input += 2;
			offset += 2;
			break;
		}
	}
	if (r_str_startswith (*input, ".n")) {
		res |= DOTN_BIT;
		*input += 2;
		offset += 2;
	} else
	if (r_str_startswith (*input, ".w")) {
		res |= DOTW_BIT;
		*input += 2;
		offset += 2;
	}
	
	if (**input == '\0') {
		return res;
	}
	*input -= offset;
	return 0;
}

static ut64 opmask(char *input, const char *opcode, ut64 allowed_mask) {
	ut64 res = 0;
	
	r_str_case (input, false);
	if (strlen (opcode) > strlen (input)) {
		return 0;
	}
	if (r_str_startswith (input, opcode)) {
		input += strlen (opcode);
		res |= M_BIT;
		res |= cqcheck (&input);
		
		if ((*input == 's') && (S_BIT & allowed_mask)) {
			res |= S_BIT;
			input++;
		}
		res |= cqcheck (&input);

		if ((r_str_startswith (input, "wb")) && (WB_BIT & allowed_mask)) {
			res |= WB_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "wt")) && (WT_BIT & allowed_mask)) {
			res |= WT_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if ((r_str_startswith (input, "db")) && (DB_BIT & allowed_mask)) {
			res |= DB_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "ea")) && (EA_BIT & allowed_mask)) {
			res |= EA_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "ia")) && (IA_BIT & allowed_mask)) {
			res |= IA_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "fd")) && (FD_BIT & allowed_mask)) {
			res |= FD_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if ((*input == 'l') && (L_BIT & allowed_mask)) {
			res |= L_BIT;
			input++;
		}
		res |= cqcheck (&input);
		if ((r_str_startswith (input, "bb")) && (BB_BIT & allowed_mask)) {
			res |= BB_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "tt")) && (TT_BIT & allowed_mask)) {
			res |= TT_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "bt")) && (BT_BIT & allowed_mask)) {
			res |= BT_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "tb")) && (TB_BIT & allowed_mask)) {
			res |= TB_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if ((*input == 'w') && (W_BIT & allowed_mask)) {
			res |= W_BIT;
			input++;
		}
		if ((*input == 'b') && (B_BIT & allowed_mask)) {
			res |= B_BIT;
			input++;
		} else
	        if ((*input == 'h') && (H_BIT & allowed_mask)) {
			res |= H_BIT;
			input++;
		} else
		if ((*input == 'd') && (D_BIT & allowed_mask)) {
			res |= D_BIT;
			input++;
		}
		if ((*input == 't') && (T_BIT & allowed_mask)) {
			res |= T_BIT;
			input++;
		}
		if ((*input == 's') && (S_BIT & allowed_mask)) {
			res |= S_BIT;
			input++;
		}
		res |= cqcheck (&input);
		if ((*input == 'r') && (R_BIT & allowed_mask)) {
			res |= R_BIT;
			input++;
		}
		res |= cqcheck (&input);
		if ((*input == '2') && (TWO_BIT & allowed_mask)) {
			res |= TWO_BIT;
			input++;
		}
		if ((*input == '8') && (EIGHT_BIT & allowed_mask)) {
			res |= EIGHT_BIT;
			input++;
		}
		if ((r_str_startswith (input, "16")) && (SIXTEEN_BIT & allowed_mask)) {
			res |= SIXTEEN_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if ((*input == 'l') && (L_BIT & allowed_mask)) {
			res |= L_BIT;
			input++;
		}
		if ((*input == 'x') && (X_BIT & allowed_mask)) {
			res |= X_BIT;
			input++;
		}
		res |= cqcheck (&input);
		if ((r_str_startswith (input, "id")) && (ID_BIT & allowed_mask)) {
			res |= ID_BIT;
			input += 2;
		}
		if ((r_str_startswith (input, "ie")) && (IE_BIT & allowed_mask)) {
			res |= IE_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if ((r_str_startswith (input, "sh")) && (SH_BIT & allowed_mask)) {
			res |= SH_BIT;
			input += 2;
		}
		res |= cqcheck (&input);
		if (!(res & C_MATCH_BIT)) {
			res |= 15 << 2; // nv is the default condition
		}
		if (*input == 0) {
			return res;
		}
	}
	return 0;
}

static ut32 itmask(char *input) {
	ut32 res = 0;
	ut32 i, length;
	r_str_case (input, false);
	if (2 > strlen (input)) {
		return 0;
	}
	if (r_str_startswith (input, "it")) {
		input += 2;
		res |= 1; // matched
		if (strlen(input) > 3) {
			return 0;
		}
		res |= (strlen (input) & 0x3) << 4;
		length = strlen (input);
		for (i = 0; i < length; i++, input++ ) {
			if (*input == 'e') {
				res |= 1 << (3 - i);
				continue;
			}
			if (*input == 't') {
				continue;
			}
			return 0;
		}
		return res;
	}
	return 0;
}

static bool err;
//decode str as number
static ut64 getnum(const char *str) {
	char *endptr;
	err = false;
	ut64 val;

	if (!str) {
		err = true;
		return 0;
	}
	while (*str == '$' || *str == '#') {
		str++;
	}
	val = strtoll (str, &endptr, 0);
	if (str != endptr && *endptr == '\0') {
		return val;
	}
	err = true;
	return 0;
}

static ut64 getnumbang(const char *str) {
	ut64 res;

	if (!str || !*str || !r_str_endswith (str, "!")) {
		err = true;
		return 0;
	}
	char *temp = r_str_ndup (str, strlen (str) - 1);
	if (!temp) {
		return -1;
	}
	err = false;
	res = getnum (temp);
	free (temp);
	return res; // err propagates
}
	
static ut32 getimmed8(const char *str) {
	ut32 num = getnum (str);
	if (err) {
		return 0;
	}
	ut32 rotate;
	if (num <= 0xff) {
		return num;
	} else {
		for (rotate = 1; rotate < 16; rotate++) {
			// rol 2
			num = ((num << 2) | (num >> 30));
			if (num == (num & 0xff)) {
				return (num | (rotate << 8));
			}
		}
		err = 1;
		return 0;
	}
}

static st32 firstsigdigit (ut32 num) {
	st32 f = -1;
	st32 b = -1;
	ut32 forwardmask = 0x80000000;
	ut32 backwardmask = 0x1;
	ut32 i;
	for (i = 0; i < 32; i++ ) {
		if ( (forwardmask & num) && (f == -1)) {
			f = i;
		}
		if ( (backwardmask & num) && (b == -1)) {
			b = 32-i;
		}
		forwardmask >>= 1;
		backwardmask <<= 1;
	}

	if ((b-f) < 9) {
		return f;
	}
	return -1;
}

static ut32 getthbimmed(st32 number) {
	ut32 res = 0;
	if (number < 0) {
		res |= 1 << 18;
	}
	number >>= 1;
	res |= (( number & 0xff) << 8);
	number >>= 8;
	res |= ( number & 0x07);
	number >>= 3;
	res |= (( number & 0xff) << 24);
	number >>= 8;
	res |= (( number & 0x3) << 16);
	number >>= 2;
	if (number < 0) {
		res |= (( number & 0x1) << 3);
		number >>= 1;
		res |= (( number & 0x1) << 5);
	} else {
		res |= ((!( number & 0x1)) << 3);
		number >>= 1;
		res |= ((!( number & 0x1)) << 5);
	}
	return res;
}

static ut32 getthzeroimmed12(ut32 number) {
	ut32 res = 0;
	res |= (number & 0x800) << 7;
	res |= (number & 0x700) >> 4;
	res |= (number & 0x0ff) << 8;
	return res;
}

static ut32 getthzeroimmed16(ut32 number) {
	ut32 res = 0;
	res |= (number & 0xf000) << 12;
	res |= (number & 0x0800) << 7;
	res |= (number & 0x0700) >> 4;
	res |= (number & 0x00ff) << 8;
	return res;
}

static ut32 getthimmed12(const char *str) {
	ut64 num = getnum (str);
	if (err) {
		return 0;
	}

	st32 FSD = 0;
	ut64 result = 0;
	if (num <= 0xff) {
		return num << 8;
	} else if ( ((num & 0xff00ff00) == 0) && ((num & 0x00ff0000) == ((num & 0x000000ff) << 16)) ) {
		result |= (num & 0x000000ff) << 8;
		result |= 0x00000010;
		return result;
	} else if ( ((num & 0x00ff00ff) == 0) && ((num & 0xff000000) == ((num & 0x0000ff00) << 16)) ) {
		result |= num & 0x0000ff00;
		result |= 0x00000020;
		return result;
	} else if ( ((num & 0xff000000) == ((num & 0x00ff0000) << 8)) && ((num & 0xff000000) == ((num & 0x0000ff00) << 16)) && ((num &0xff000000) == ((num & 0x000000ff) << 24)) ) {
		result |= num & 0x0000ff00;
		result |= 0x00000030;
		return result;
	} else {
		FSD = firstsigdigit(num);
		if (FSD != -1) {
		        result |= ((num >> (24-FSD)) & 0x0000007f) << 8;
			result |= ((8+FSD) & 0x1) << 15;
			result |= ((8+FSD) & 0xe) << 3;
			result |= ((8+FSD) & 0x10) << 14;
			return result;
		} else {
			err = true;
			return 0;
		}
	}
}

static char *getrange(char *s) {
	char *p = NULL;
	while (s && *s) {
		if (*s == ',') {
			p = s+1;
			*p=0;
		}
		if (*s == '[' || *s == ']') {
			memmove (s, s + 1, strlen (s + 1) + 1);
		}
		if (*s == '}') {
			*s = 0;
		}
		s++;
	}
	while (p && *p == ' ') {
		p++;
	}
	return p;
}

//ret register #; -1 if failed
static int getreg(const char *str) {
	int i;
	char *ep;
	const char *aliases[] = { "sl", "fp", "ip", "sp", "lr", "pc", NULL };
	if (!str || !*str) {
		return -1;
	}
	if (*str == 'r') {
		int reg = strtol (str + 1, &ep, 10);
		if ((ep[0] != '\0') || (str[1] == '\0')) {
			return -1;
		}
		if (reg < 16 && reg >= 0) {
			return reg;
		}
	}
	for (i=0; aliases[i]; i++) {
		if (!strcmpnull (str, aliases[i])) {
			return 10 + i;
		}
	}
	return -1;
}


static st32 getlistmask(char *input) {
	st32 tempres, res = 0;
	int i, j, start = 0, end = 0;
	char *temp = NULL;
	char *otemp = NULL;
	char *temp2 = malloc (strlen (input) + 1);
	if (!temp2) {
		res = -1;
		goto end;
	}
	temp = (char *)malloc (strlen (input) + 1);
	if (!temp) {
		res = -1;
		goto end;
	}
	otemp = temp;
	while (*input != '\0') {
		for (; *input == ' '; input++) {
			;
		}
		for (i = 0; input[i] != ',' && input[i] != '\0'; i++) {
			;
		}
		r_str_ncpy (temp, input, i + 1);

		input += i;
		if (*input != '\0') {
			input++;
		}

		for (i = 0; temp[i] != '-' && temp[i] != '\0'; i++) {
			;
		}
		if (i == strlen (temp)) {
			tempres = getreg (temp);
			if (tempres == -1 || tempres > 15) {
				res = -1;
				goto end;
			}
			res |= 1 << tempres;
		} else {
			strncpy (temp2, temp, i);
			temp2[i] = 0;
			temp += i + 1;
			start = getreg (temp2);
			if (start == -1 || start > 15) {
				res = -1;
				goto end;
			}
			end = getreg (temp);
			if (end == -1 || end > 15) {
				res = -1;
				goto end;
			}

			for (j = start; j <= end; j++ ) {
				res |= 1 << j;
			}
		}
	}
end:
	free (otemp);
	free (temp2);
	return res;
}

static st32 getregmemstart(const char *input) {
	if ((strlen (input) < 1) || (!(*input == '['))) {
		return -1;
	}
	input++;
	return getreg (input);
}
	
static st32 getregmemstartend(const char *input) {
	st32 res;
	if (!input || (strlen (input) < 2) || (*input != '[') || !r_str_endswith (input, "]")) {
		return -1;
	}
	input++;
	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		return -1;
	}
	res = getreg (temp);
	free (temp);
	return res;
}
	
static st32 getregmemend(const char *input) {
	st32 res;
	if (!input || !*input || !r_str_endswith (input, "]")) {
		return -1;
	}

	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		return -1;
	}
	res = getreg (temp);
	free (temp);
	return res;
}
	
static st32 getreglist(const char *input) {
	st32 res;
	
	if (!input || (strlen (input) < 2) || (*input != '{') || !r_str_endswith (input, "}")) {
		return -1;
	}
	if (*input) {
		input++;
	}
	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		return -1;
	}
	res = getlistmask (temp);
	free (temp);
	return res;
}

static st32 getnummemend (const char *input) {
	st32 res;
	err = false;
	if (!input || !*input || !r_str_endswith (input, "]")) {
		err = true;
		return -1;
	}
	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		err = true;
		return -1;
	}
	res = getnum (temp);
	free (temp);
	return res;
}

static st32 getnummemendbang (const char *input) {
	st32 res;
	err = false;
	if (!input || (strlen (input) < 2) || (input[strlen(input) - 2] != ']' || !r_str_endswith (input, "!"))) {
		err = true;
		return 0;
	}
	char *temp = r_str_ndup (input, strlen (input) - 2);
	if (!temp) {
		err = true;
		return 0;
	}
	res = getnum (temp);
	free (temp);
	return res;
}

static st32 getregmembang(const char *input) {
	st32 res;
	if (!input || !*input || !r_str_endswith (input, "!")) {
		return -1;
	}
	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		return -1;
	}
	res = getreg (temp);
	free (temp);
	return res;
}

static int getcoproc(const char *str) {
	char *ep;
	if (!str || !*str) {
		return -1;
	}
	if (*str == 'p') {
		int coproc = strtol (str + 1, &ep, 10);
		if ((ep[0] != '\0') || (str[1] == '\0')) {
			return -1;
		}
		if (coproc < 16 && coproc >= 0) {
			return coproc;
		}
	}
	return -1;
}

static int getcoprocreg(const char *str) {
	char *ep;
	
	if (!str || !*str) {
		return -1;
	}
	if (r_str_startswith (str, "c")) {
		int reg = strtol (str + 1, &ep, 10);
		if ((ep[0] != '\0') || (str[1] == '\0')) {
			return -1;
		}
		if (reg < 16 && reg >= 0) {
			return reg;
		}
	}
	return -1;
}

static ut8 interpret_msrbank (char *str, ut8 *spsr) {
	const char fields[] = {'c', 'x', 's', 'f', 0};
	int res = 0;
	int i, j;
	if (r_str_startswith (str, "spsr_")) {
		*spsr = 1;
	} else {
		*spsr = 0;
	}		
	
	if (r_str_startswith (str, "apsr_")) {
		if (!(strcmp (str+5, "g"))) {
			return 0x4;
		}
		if (!(strcmp (str+5, "nzcvq"))) {
			return 0x8;
		}
		if (!(strcmp (str+5, "nzcvqg"))) {
			return 0xc;
		}
	}
	if (r_str_startswith (str, "cpsr_") || r_str_startswith (str, "spsr_")) {
		for (i = 0; str[5+i]; i++) {
			for (j = 0; fields[j]; j++) {
				if (str[5+i] == fields[j]) {
					break;
				}
			}
			if (!(fields[j])) {
				return 0;
			}
			res |= 1 << j;
		}
		return res;
	}
	return 0;
}
		
static ut32 thumb_getshift(const char *str) {
	// only immediate shifts are ever used by thumb-2. Bit positions are different from ARM.
	const char *shifts[] = {
		"LSL", "LSR", "ASR", "ROR", 0, "RRX"
	};
	char *type = strdup (str);
	char *arg;
	char *space;
	ut32 res = 0;
	ut32 shift = false;
	err = false;
	ut32 argn;
	ut32 i;
	
	r_str_case (type,true);
	
	if (!strcmp (type, shifts[5])) {
		// handle RRX alias case
		res |= 3 << 12;	
		free (type);
		return res;
	}
	
	space = strchr (type, ' ');
	if (!space) {
		free (type);
		err = true;
		return 0;
	}
	*space = 0;
	arg = strdup (++space);
	
	for (i = 0; shifts[i]; i++) {
		if (!strcmp (type, shifts[i])) {
			shift = true;
			break;
		}
	}
	if (!shift) {
		err = true;
		free (type);
		free (arg);
		return 0;
	}
	res |= i << 12;
		
	argn = getnum (arg);
	if (err || argn > 32) {
		err = true;
		free (type);
		free (arg);
		return 0;
	}
	res |= ( (argn & 0x1c) << 2);
	res |= ( (argn & 0x3) << 14);

	free (type);
	free (arg);
	return res;
}

static st32 getshiftmemend(const char *input) {
	st32 res;
	if (!input || !*input || !r_str_endswith (input, "]")) {
		return -1;
	}

	char *temp = r_str_ndup (input, strlen (input) - 1);
	if (!temp) {
		return -1;
	}
	res = thumb_getshift (temp);
	free (temp);
	return res;
}

void collect_list(char *input[]) {
	if (!input || !input[0]) {
		return;
	}
	char *temp = malloc (500);
	if (!temp) {
		return;
	}
	temp[0] = 0;
	int i;
	int conc = 0;
	int start = 0, end = 0;
	int arrsz;
	for (arrsz = 1; input[arrsz] != NULL; arrsz++) {
		;
	}

	for (i = 0; input[i]; i++) {
		if (conc) {
			strcat (temp, ", ");
			strcat (temp, input[i]);
		}
		if (input[i][0] == '{') {
			conc = 1;
			strcat (temp, input[i]);
			start = i;
		}
		if ((conc) & (input[i][strlen (input[i]) - 1] == '}')) {
			conc = 0;
			end = i;
		}
	}
	if (end == 0) {
		free (temp);
		return;
	}
	input[start] = temp;
	for (i = start + 1; i < arrsz; i++) {
		input[i] = input[(end-start) + i];
	}
	input[i] = NULL;
}

static ut64 thumb_selector(char *args[]) {
	collect_list(args);
	ut64 res = 0;
	ut8 i;
	for (i = 0; i < 15; i++) {
		if (args[i] == NULL) {
			break;
		}
		if (getreg (args[i]) != -1) {
			res |= 1 << (i*4);
			continue;
		}
		err = false;
		getnum (args[i]);
		if (!err) {
			res |= 2 << (i*4);
			continue;
		}
		err = false;   	
		thumb_getshift (args[i]);
		if (!err) {
			res |= 3 << (i*4);
			continue;
		}
		if (getcoproc (args[i]) != -1) {
			res |= 4 << (i*4);
			continue;
		}
		if (getcoprocreg (args[i]) != -1) {
			res |= 5 << (i*4);
			continue;
		}
		if (getregmemstart (args[i]) != -1) {
			res |= 6 << (i*4);
			continue;
		}
		if (getregmemstartend (args[i]) != -1) {
			res |= 7 << (i*4);
			continue;
		}
		err = false;
		getnummemend(args[i]);
		if (!err) {
			res |= 8 << (i*4);
			continue;
		}
		err = false;
		getnummemendbang(args[i]);
		if (!err) {
			res |= 9 << (i*4);
			continue;
		}
		if (getregmembang (args[i]) != -1) {
			res |= 0xa << (i*4);
			continue;
		}
		if (getreglist (args[i]) != -1) {
			res |= 0xb << (i*4);
			continue;
		}
		if (getregmemend (args[i]) != -1) {
			res |= 0xc << (i*4);
			continue;
		}
		if (getshiftmemend (args[i]) != -1) {
			res |= 0xd << (i*4);
			continue;
		}
		err = false;
		getnumbang(args[i]);
		if (!err) {
			res |= 0xe << (i*4);
			continue;
		}
		res |= 0xf << (i*4);
	}
	err = false;
	return res;
}
		
static ut32 getshift(const char *str) {
	char type[128];
	char arg[128];
	char *space;
	ut32 i=0, shift=0;
	const char *shifts[] = {
		"LSL", "LSR", "ASR", "ROR",
		0, "RRX" // alias for ROR #0
	};

	strncpy (type, str, sizeof (type) - 1);
	// XXX strcaecmp is probably unportable
	if (!r_str_casecmp (type, shifts[5])) {
		// handle RRX alias case
		shift = 6;
	} else { // all other shift types
		space = strchr (type, ' ');
		if (!space) {
			return 0;
		}
		*space = 0;
		strncpy (arg, ++space, sizeof(arg) - 1);

		for (i = 0; shifts[i]; i++) {
			if (!r_str_casecmp (type, shifts[i])) {
				shift = 1;
				break;
			}
		}
		if (!shift) {
			return 0;
		}
		shift = i * 2;
		if ((i = getreg (arg)) != -1) {
			i <<= 8; // set reg
//			i|=1; // use reg
			i |= (1 << 4); // bitshift
			i |= shift << 4; // set shift mode
			if (shift == 6) {
				i |= (1 << 20);
			}
		} else {
			char *bracket = strchr (arg, ']');
			if (bracket) {
				*bracket = '\0';
			}
			// ensure only the bottom 5 bits are used
			i &= 0x1f;
			if (!i) {
				i = 32;
			}
			i = (i * 8);
			i |= shift; // lsl, ror, ...
			i = i << 4;
		}
	}

	return i;
}

static void arm_opcode_parse(ArmOpcode *ao, const char *str) {
	int i;
	memset (ao, 0, sizeof (ArmOpcode));
	if (strlen (str) + 1 >= sizeof (ao->op)) {
		return;
	}
	strncpy (ao->op, str, sizeof (ao->op)-1);
	strcpy (ao->opstr, ao->op);
	ao->a[0] = strchr (ao->op, ' ');
	for (i=0; i<15; i++) {
		if (ao->a[i]) {
			*ao->a[i] = 0;
			ao->a[i+1] = strchr (++ao->a[i], ',');
		} else {
			break;
		}
	}
	if (ao->a[i]) {
		*ao->a[i] = 0;
		ao->a[i]++;
	}
	for (i=0; i<16; i++) {
		while (ao->a[i] && *ao->a[i] == ' ') {
			ao->a[i]++;
		}
	}
}

static inline int arm_opcode_cond(ArmOpcode *ao, int delta) {
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	int i, cond = 14; // 'always' is default
	char *c = ao->op+delta;
	for (i=0; conds[i]; i++) {
		if (!strcmpnull (c, conds[i])) {
			cond = i;
			break;
		}
	}
	ao->o |= cond << 4;
	return cond;
}

static st32 thumb_getoffset(char *label, ut64 cur) {
	st32 res = r_num_math (NULL, label);
	res -= 4;
	res -= cur; // possible integer underflow
	//printf("thumb_getoffset: %s, %lld, %lld\n", label, res, cur);
	return res;
}

static st8 std_16bit_2reg(ArmOpcode *ao, ut64 m) {
	ut8 rd = getreg (ao->a[0]);
	ut8 rn = getreg (ao->a[1]);
	if ( (rd < 8) && (rn < 8) && !(m & DOTW_BIT)) {
		ao->o |= rd << 8;
		ao->o |= rn << 11;
		return 2;
	}
	return 0;
}

static st8 mem_16bit_2reg(ArmOpcode *ao, ut64 m) {
	ut8 rd = getreg (ao->a[0]);
	ut8 rn = getregmemstart (ao->a[1]);
	if ( (rd < 8) && (rn < 8) && !(m & DOTW_BIT)) {
		ao->o |= rd << 8;
		ao->o |= rn << 11;
		return 2;
	}
	return 0;
}

static st8 std_32bit_2reg(ArmOpcode *ao, ut64 m, bool shift) {
	ut8 rd = getreg (ao->a[0]);
	ut8 rn = getreg (ao->a[1]);
	if ((rd > 15) || (rn > 15) || (m & DOTN_BIT)) {
		return -1;
	}
	if (m & S_BIT) {
		ao->o |= 1 << 28;
	}
	if (shift) {
		err = false;
		ut32 shiftnum = thumb_getshift (ao->a[2]);
		if (err) {
			return -1;
		}
		ao->o |= shiftnum;
		ao->o |= rd << 24;
		ao->o |= rn << 8;
	} else {
		ao->o |= rd;
		ao->o |= rn << 24;
	}
	return 4;
}

static st8 mem_32bit_2reg(ArmOpcode *ao, ut64 m) {
	ut8 rd = getreg (ao->a[0]);
	ut8 rn = getregmemstart (ao->a[1]);
	if ((rd > 15) || (rn > 15) || (m & DOTN_BIT)) {
		return -1;
	}
	ao->o |= rd << 4;
	ao->o |= rn << 24;
	return 4;
}

static st8 std_32bit_3reg(ArmOpcode *ao, ut64 m, bool shift) {
	ut8 rd = getreg (ao->a[0]);
	ut8 rn = getreg (ao->a[1]);
	ut8 rm = getreg (ao->a[2]);
	if ((rd > 15) || (rn > 15) || (rm > 15) || (m & DOTN_BIT)) {
		return -1;
	}
	ao->o |= rd;
	ao->o |= rn << 24;
	ao->o |= rm << 8;
	if (shift) {
		err = false;
		ut32 shiftnum = thumb_getshift (ao->a[3]);
		if (err) {
			return -1;
		}
		ao->o |= shiftnum;
	}
	if (m & S_BIT) {
		ao->o |= 1 << 28;
	}
	return 4;
}

static void std_opt_2(ArmOpcode *ao) {
	ao->a[2] = ao->a[1];
	ao->a[1] = ao->a[0];
}

static void std_opt_3(ArmOpcode *ao) {
	ao->a[3] = ao->a[2];
	ao->a[2] = ao->a[1];
	ao->a[1] = ao->a[0];
}

// TODO: group similar instructions like for non-thumb
static int thumb_assemble(ArmOpcode *ao, ut64 off, const char *str) {
	ut64 m;
	ao->o = UT32_MAX;
	if (!strcmpnull (ao->op, "udf")) {
		ao->o = 0xde;
		ao->o |= getnum (ao->a[0]) << 8;
		return 2;
	} else
	if ((m = opmask (ao->op, "add", S_BIT | W_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}
			
			if (reg2 == 13) {
				if ((reg1 < 8) && (num < 1024) && (num % 4 == 0) && (!(m & DOTW_BIT)) && (!(m & W_BIT))) {
					ao->o = 0x00a8;
					ao->o |= reg1;
					ao->o |= (num >> 2) << 8;
					return 2;
				}

				if ((reg1 == 13) && (num < 512) && (num % 4 == 0) && (!(m & DOTW_BIT)) && (!(m & W_BIT))) {
					ao->o = 0x00b0;
					ao->o |= (num >> 2) << 8;
					return 2;
				}

				err = false;
				ut32 thnum = getthimmed12 (ao->a[2]);
				if (!err && (!(m & W_BIT))) {
					ao->o = 0x0df10000;
					ao->o |= reg1;
					ao->o |= thnum;
					if (m & S_BIT) {
						ao->o |= 1 << 28;
					}
					return 4;
				}

				if (num > 4095) {
					return -1;
				}

				ao->o = 0x0df20000;
				ao->o |= reg1;
				ao->o |= getthzeroimmed12 (num);
				return 4;
			}

			if (num < 8) {
				ao->o = 0x001c;
				ao->o |= (num & 0x3) << 14;
				ao->o |= (num >> 2);
				if (std_16bit_2reg (ao, m)) {
					return 2;
				}
			}

			if ((reg1 < 8) && (reg1 == reg2) && (num < 256)) {
				ao->o = 0x0030;
				ao->o |= reg1;
				ao->o |= num << 8;
				return 2;
			}

			err = false;
			ut32 thnum = getthimmed12 (ao->a[2]);
			if (!err && (!(m & W_BIT))) {
				ao->o = 0x00f10000;
				ao->o |= thnum;
				return std_32bit_2reg (ao, m, false);
			}

			if (num > 4095) {
				return -1;
			}

			ao->o = 0x00f20000;
			ao->o |= getthzeroimmed12 (num);
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15)) {
				return -1;
			}
				
			if (reg2 == 13) {
				if ((reg1 == reg3) && (!(m & DOTW_BIT)) && (shift == 0)) {
					ao->o = 0x6844;
					ao->o |= (reg1 & 0x7) << 8;
					ao->o |= (reg1 >> 3) << 15;
					return 2;
				}

				if ((reg1 == 13) && (!(m & DOTW_BIT)) && (shift == 0)) {
					ao->o = 0x8544;
					ao->o |= reg3 << 11;
					return 2;
				}

				ao->o = 0x0deb0000;
				ao->o |= reg1;
				ao->o |= reg3 << 8;
				ao->o |= shift;
				if (m & S_BIT) {
					ao->o |= 1 << 28;
				}
				return 4;
			}

			if ((reg3 < 8) && (!(m & DOTW_BIT)) && (shift == 0)) {
				ao->o = 0x0018;
				ao->o |= (reg3 >> 2);
				ao->o |= (reg3 & 0x3) << 14;
				if (std_16bit_2reg (ao, m)) {
					return 2;
				}
			}

			if ((reg1 == reg2) && (!(m & DOTW_BIT)) && (shift == 0)) {
				ao->o = 0x0044;
				ao->o |= (reg1 & 0x7) << 8;
				ao->o |= (reg1 >> 3) << 15;
				ao->o |= reg3 << 11;
				return 2;
			}

			ao->o = 0x00eb0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "adc", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ao->o = 0x40f10000;
			ao->o |= getthimmed12 (ao->a[2]);
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x4041;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x40eb0000;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			std_opt_3 (ao);
		        }
			// intentional fallthrough
			// a bit naughty, perhaps?
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x40eb0000;
			return std_32bit_3reg(ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "adr", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg = getreg (ao->a[0]);
			st32 label = getnum (ao->a[1]);
			if ( !(m & DOTW_BIT) && (reg < 8) && (label < 1024) && (label >= 0) && (label % 4 == 0)) {
				ao->o = 0x00a0;
				ao->o |= reg;
				ao->o |= (label / 4) << 8;
				return 2;
			} else if ((label < 0) && (label > -4096)) {
				if (m & DOTN_BIT) {
					// this is explicitly an error
					return -1;
				}
				ao->o = 0xaff20000;
				ao->o |= reg;
				ao->o |= getthzeroimmed12 (-label);
				return 4;
			} else if ((label > 0) && (label < 4096)) {
				if (m & DOTN_BIT) {
					// this is explicitly an error
					return -1;
				}
				ao->o = 0x0ff20000;
				ao->o |= reg;
				ao->o |= getthzeroimmed12 (label);
				return 4;
			}
			return -1;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "and", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->o = 0x0040;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x00ea0000;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ut32 imm = getthimmed12 (ao->a[2]);
			ao->o = 0x00f00000;
			ao->o |= imm;
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			std_opt_3 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x00ea0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "asr", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 imm = getnum (ao->a[2]);
			if (((int)imm < 1) && ((int)imm > 32)) {
				return -1;
			}
			ao->o = 0x0010;
			ao->o |= (imm & 0x3) << 14;
			ao->o |= (imm & 0x1c) >> 2;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			ao->o = 0x4fea2000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= (imm & 0x3) << 14;
			ao->o |= (imm & 0x1c) << 2;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x0041;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x40fa00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "b", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			st32 offset = thumb_getoffset (ao->a[0], off);
			if (offset % 2 != 0) {
				return -1;
			}

			if ((m & C_BITS) == C_BITS) {
				if ((offset >= -2048) && (offset <= 2046) && (!(m & DOTW_BIT))) {
					ao->o = 0x00e0;
					ao->o |= ((offset/2 & 0xff) << 8);
					ao->o |= ((offset/2 & 0x700) >> 8);
					return 2;
				}
				if ((offset < -16777216) || (offset > 16777214) || (offset % 2 != 0)) {
					return -1;
				}
				ao->o = 0x00f00090;
				ao->o |= getthbimmed(offset);
				return 4;
			} else {
				if ((offset >= -256) && (offset <= 254) && (!(m & DOTW_BIT))) {
					ao->o = 0x00d0;
					ao->o |= (ut16) ((offset/2) << 8);
					ao->o |= ((m & C_BITS) >> 2);
					return 2;
				}
				if ((offset < -1048576) || (offset > 1048574) || (offset % 2 != 0)) {
					return -1;
				}

				ao->o = 0x00f00080;
				ao->o |= (ut32)(offset & 0x80000) >> 16;
				ao->o |= (ut32)(offset & 0x40000) >> 13;
				ao->o |= (ut32)(offset & 0x3f000) << 12;
				ao->o |= (ut32)(offset & 0xe00) >> 9;
				ao->o |= (ut32)(offset & 0x1fe) << 7;
				if (offset < 0) {
					ao->o |= 1 << 18;
				}
				ao->o |= (((m & C_BITS) & 0xc) << 28);
				ao->o |= (((m & C_BITS) & 0x30) << 12);
				return 4;
			}
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bl", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			st32 offset = thumb_getoffset (ao->a[0], off);
			ao->o = 0x00f000d0;
			if ((offset > 16777214) || (offset < -16777216) || (offset % 2 != 0)) {
				return -1;
			}
			ao->o |= getthbimmed(offset);
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bx", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG: {
			ut32 reg1 = getreg (ao->a[0]);
			ao->o = 0x0047;
			ao->o |= reg1 << 11;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else 
	if (( m = opmask (ao->op, "blx", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG: {
			ut32 reg1 = getreg (ao->a[0]);
			ao->o = 0x8047;
			ao->o |= reg1 << 11;
			return 2;
		        }
			break;
		case THUMB_CONST: {
			st32 offset = thumb_getoffset (ao->a[0], off);
			ao->o = 0x00f000c0;
			if ((offset > 16777214) || (offset < -16777216) || (offset % 2 != 0)) {
				return -1;
			}
			offset += off & 0x2; // (Align(PC,4)
			ao->o |= getthbimmed (offset);
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bfc", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST_CONST: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut32 lsb = getnum (ao->a[1]);
			ut32 width = getnum (ao->a[2]);
			ut32 msb = lsb + width - 1;
			if ((lsb > 31) || (msb > 31)) {
				return -1;
			}
			ao->o = 0x6ff30000;
			ao->o |= reg1;
			ao->o |= ((lsb & 0x1c) << 2);
			ao->o |= ((lsb & 0x3) << 14);
			ao->o |= (msb << 8);
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bfi", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST_CONST: {
			ut32 lsb = getnum (ao->a[2]);
			ut32 width = getnum (ao->a[3]);
			ut32 msb = lsb + width - 1;
			if ((lsb > 31) || (msb > 31)) {
				return -1;
			}
			ao->o = 0x60f30000;
			ao->o |= ((lsb & 0x1c) << 2);
			ao->o |= ((lsb & 0x3) << 14);
			ao->o |= (msb << 8);
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bic", S_BIT) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->o = 0x8043;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x20ea0000;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ao->o = 0x20f00000;
			ao->o |= getthimmed12 (ao->a[2]);
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			std_opt_3 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x20ea0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bkpt", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			ut32 num = getnum (ao->a[0]);
			if (num > 255) {
				return -1;
			}
			ao->o = 0x00be;
			ao->o |= num << 8;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cbnz", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			st32 offset = thumb_getoffset (ao->a[1], off);
			if ((reg1 > 7) || (offset > 127) || (offset % 2 != 0)) {
				return -1;
			}
			ao->o = 0x00b9;
			ao->o |= reg1 << 8;
			ao->o |= (offset & 0x3e) << 10;
			ao->o |= (offset & 0x40) >> 5;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cbz", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			st32 offset = thumb_getoffset (ao->a[1], off);
			if ((reg1 > 7) || (offset > 127) || (offset % 2 != 0)) {
				return -1;
			}
			ao->o = 0x00b1;
			ao->o |= reg1 << 8;
			ao->o |= (offset & 0x3e) << 10;
			ao->o |= (offset & 0x40) >> 5;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cdp", TWO_BIT) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_COREG_COREG_COREG: {
			ao->a[5] = "0";
		        }
			//intentional fallthrough
		case THUMB_COPROC_CONST_COREG_COREG_COREG_CONST: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc1 = getnum (ao->a[1]);
			ut8 reg1 = getcoprocreg (ao->a[2]);
			ut8 reg2 = getcoprocreg (ao->a[3]);
			ut8 reg3 = getcoprocreg (ao->a[4]);
			ut32 opc2 = getnum (ao->a[5]);
		        if ((coproc > 15) || (opc1 > 15) || (opc2 > 7)) {
				return -1;
			}
			ao->o = 0x00ee0000;
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			ao->o |= coproc;
			ao->o |= opc1 << 28;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= opc2 << 13;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else 	
	if (( m = opmask (ao->op, "clrex", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			ao->o = 0xbff32f8f;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "clz", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->o = 0xb0fa80f0;
			ao->a[2] = ao->a[1];
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cmn", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 num = getthimmed12 (ao->a[1]);
			ao->o = 0x10f1000f;
			ao->o |= reg1 << 24;
			ao->o |= num;
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0xc042;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ao->o = 0x10eb000f;
			return std_32bit_2reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cmp", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 num = getnum (ao->a[1]);
			if ((num < 256) && (!(m & DOTW_BIT))) {
				ao->o = 0x0028;
				ao->o |= reg1;
				ao->o |= num << 8;
				return 2;
			}
			num = getthimmed12 (ao->a[1]);
			ao->o = 0xb0f1000f;
			ao->o |= reg1 << 24;
			ao->o |= num;
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ao->o = 0x8042;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			if (!(m & DOTW_BIT)) {
				ao->o = 0x0045;
				ao->o |= ((reg1 & 0x7) << 8);
				ao->o |= ((reg1 & 0x8) << 12);
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = thumb_getshift (ao->a[2]);
			ao->o = 0xb0eb000f;
			ao->o |= reg1 << 24;
			ao->o |= reg2 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cps", ID_BIT | IE_BIT) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_OTHER: {
			st8 aif = iflag(ao->a[0]);
			if (aif == -1) {
				return -1;
			}
			if (!(m & DOTW_BIT)) {
				ao->o = 0x60b6;
				ao->o |= aif << 8;
				if (m & ID_BIT) {
					ao->o |= 1 << 12;
				}
				return 2;
			}
			ao->a[1] = "0";
		        }
			// intentional fallthrough
		case THUMB_OTHER_CONST: {
			st8 aif = iflag(ao->a[0]);
			ut8 mode = getnum (ao->a[1]);
			if ((mode > 31) || (aif == -1)) {
				return -1;
			}
			ao->o = 0xaff30085;
			ao->o |= mode << 8;
			ao->o |= aif << 13;
			if (m & ID_BIT) {
				ao->o |= 1 << 1;
			}
			return 4;
		        }
			break;
		case THUMB_CONST: {
			ut8 mode = getnum (ao->a[0]);
			if ((m & ID_BIT) || (m & IE_BIT) || (mode > 31)) {
				return -1;
			}
			ao->o = 0xaff30081;
			ao->o |= mode << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "dbg", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			ut32 option = getnum (ao->a[0]);
			if (option > 15) {
				return -1;
			}
			ao->o = 0xaff3f080;
			ao->o |= option << 8;
			return 4;
		        }
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "dmb", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			ao->o = 0xbff35f8f;
			return 4;
		        }
			break;
		case THUMB_OTHER: {
			r_str_case (ao->a[0], false);
			if (strcmpnull (ao->a[0], "sy")) {
				return -1;
			}
			ao->a[0] = "15";
		        }
			// intentional fallthrough
		case THUMB_CONST: {
			ut32 option = getnum (ao->a[0]);
			if (option != 15) {
				return -1;
			}
			ao->o = 0xbff3508f;
			ao->o |= option << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "dsb", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			ao->o = 0xbff34f8f;
			return 4;
		        }
			// intentional fallthrough
		case THUMB_OTHER: {
			r_str_case (ao->a[0], false);
			if (!strcmpnull ((ao->a[0] = parse_hints(ao->a[0])), "-1")) {
				return -1;
			}
		        }
			// intentional fallthrough
		case THUMB_CONST: {
			ut32 option = getnum (ao->a[0]);
			if ((option != 6) && (option != 7) && (option != 14) && (option != 15)) {
				return -1;
			}
			ao->o = 0xbff3408f;
			ao->o |= option << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "eor", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST:
			std_opt_2 (ao);
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			err = false;
			ut32 imm = getthimmed12 (ao->a[2]);
			if (err) {
				return -1;
			}
			ao->o = 0x80f00000;
			ao->o |= imm;
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x4040;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG:
			ao->a[3] = "lsl 0";
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x80ea0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "isb", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			ao->o = 0xbff36f8f;
			return 4;
		        }
			// intentional fallthrough
		case THUMB_OTHER: {
			r_str_case (ao->a[0], false);
			if (strcmpnull (ao->a[0], "sy")) {
				return -1;
			}
			ao->a[0] = "15";
		        }
			// intentional fallthrough
		case THUMB_CONST: {
			ut32 option = getnum (ao->a[0]);
			if (option != 15) {
				return -1;
			}
			ao->o = 0xbff3608f;
			ao->o |= option << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = itmask (ao->op))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_OTHER: {
			ut16 cond = 0;
			ut16 i;
			
			const char *conds[] = {
				"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
				"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
			};
			r_str_case (ao->a[0], false);
			for (i = 0; conds[i]; i++) {
				if (!(strcmpnull(ao->a[0], conds[i]))) {
					cond = i;
					break;
				}
			}

			if (i == 16) {
				return -1;
			}
			ao->o = 0x00bf;
			ao->o |= cond << 12;

			ut8 nrcs = (m & 0x30) >> 4;
			ut8 thiset = 0;

			for (i = 0; i < nrcs; i++) {
				thiset = ((m & (1 << (3 - i))) >> (3 - i));
				ao->o |= ((cond & 0x1) ^ thiset) << (11 - i);
			}
			ao->o |= 1 << (11 - i);
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ldc", TWO_BIT | L_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_COREG_BRACKREG_CONSTBRACK: {
			ut8 proc = getcoproc (ao->a[0]);
			ut8 reg1 = getcoprocreg (ao->a[1]);
			ut8 reg2 = getregmemstart (ao->a[2]);
			st32 imm = getnummemend (ao->a[3]);
			ao->o = 0x10ed0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (imm < 0) {
				imm = -imm;
			} else {
				ao->o |= 1 << 31;
			}				
			if ((proc > 15) || (reg1 > 15) || (reg2 > 15) || (imm > 1024) || (imm % 4 != 0)) {
				return -1;
			}
			ao->o |= proc;
			ao->o |= reg1 << 4;
			ao->o |= (imm >> 2) << 8;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		case THUMB_COPROC_COREG_BRACKREGBRACK:
			ao->a[3] = "0";
			// intentional fallthrough
		case THUMB_COPROC_COREG_BRACKREGBRACK_CONST: {
			ut8 proc = getcoproc (ao->a[0]);
			ut8 reg1 = getcoprocreg (ao->a[1]);
			ut8 reg2 = getregmemstartend (ao->a[2]);
			st32 imm = getnum (ao->a[3]);
			ao->o = 0x30ec0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (imm < 0) {
				imm = -imm;
			} else {
				ao->o |= 1 << 31;
			}				
			if ((proc > 15) || (reg1 > 15) || (reg2 > 15) || (imm > 1024) || (imm % 4 != 0)) {
				return -1;
			}
			ao->o |= proc;
			ao->o |= reg1 << 4;
			ao->o |= (imm >> 2) << 8;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		case THUMB_COPROC_COREG_BRACKREG_CONSTBRACKBANG: {
			ut8 proc = getcoproc (ao->a[0]);
			ut8 reg1 = getcoprocreg (ao->a[1]);
			ut8 reg2 = getregmemstart (ao->a[2]);
			st32 imm = getnummemendbang (ao->a[3]);
			ao->o = 0x30ed0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (imm < 0) {
				imm = -imm;
			} else {
				ao->o |= 1 << 31;
			}				
			if ((proc > 15) || (reg1 > 15) || (reg2 > 15) || (imm > 1024) || (imm % 4 != 0)) {
				return -1;
			}
			ao->o |= proc;
			ao->o |= reg1 << 4;
			ao->o |= (imm >> 2) << 8;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ldm", DB_BIT | EA_BIT | IA_BIT | FD_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REGBANG_LIST: {
			ut8 reg1 = getregmembang (ao->a[0]);
			ut32 list = getreglist (ao->a[1]);
			if (!((m & DB_BIT) || (m & EA_BIT)) && !(list & 0xff00) && (reg1 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x00c8;
				ao->o |= reg1;
				if (list & (1 << reg1)) {
					list ^= 1 << (reg1);
				}
				ao->o |= (list & 0xff) << 8;
					
				return 2;
			}
			if (list & 0x2000) {
				return -1;
			}
			if ((m & DB_BIT) || (m & EA_BIT)) {
				ao->o = 0x30e90000;
			} else {
				// ldmia is the default!
				ao->o = 0xb0e80000;
			}
				
			ao->o |= reg1 << 24;
			ao->o |= (list & 0xff) << 8;
			ao->o |= (list & 0xff00) >> 8;
			return 4;
		        }
			break;
		case THUMB_REG_LIST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 list = getreglist (ao->a[1]);
			if (!((m & DB_BIT) || (m & EA_BIT)) && !(list & 0xff00) && (reg1 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x00c8;
				ao->o |= reg1;
				ao->o |= 1 << (reg1 + 8);
				ao->o |= (list & 0xff) << 8;
				return 2;
			}
			if (list & 0x2000) {
				return -1;
			}
			
			if ((m & DB_BIT) || (m & EA_BIT)) {
				ao->o = 0x10e90000;
			} else {
				ao->o = 0x90e80000;
			}
				
			ao->o |= reg1 << 24;
			ao->o |= (list & 0xff) << 8;
			ao->o |= (list & 0xff00) >> 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ldr", B_BIT | H_BIT | D_BIT | T_BIT | S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 ldrsel = m & (B_BIT | H_BIT | D_BIT);
		if ((m & S_BIT) && !(m & (B_BIT | H_BIT))) {
			return -1;
		}
		switch (argt) {
		case THUMB_REG_CONST:
			ao->a[2] = ao->a[1];
			strcat (ao->a[2],"]");
			ao->a[1] = "[r15";
			// intentional fallthrough
		case THUMB_REG_BRACKREGBRACK:
			if (ao->a[2] == NULL) { // double fallthrough
				ao->a[1][strlen (ao->a[1]) -1] = '\0';
				ao->a[2] = "0]";
			}
			// intentional fallthrough
		case THUMB_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			st32 num = getnummemend (ao->a[2]);
			if (ldrsel == 0) {
				if (m & T_BIT) {
					if ((num < 0) || (num > 255)) {
						return -1;
					}
					ao->o = 0x50f8000e;
					ao->o |= num << 8;
					return mem_32bit_2reg (ao, m);
				}
				if (reg2 == 15) {
					if ((num > 4095) || (num < -4095)) {
						return -1;
					}
					if ((reg1 < 8) && (num < 1024) && (num % 4 == 0)) {
						ao->o = 0x0048;
						ao->o |= reg1;
						ao->o |= (num >> 2) << 8;
						return 2;
					}
					ao->o = 0x5ff80000;
					if (num < 0) {
						num = -num;
					} else {
						ao->o |= 1 << 31;
					}
					ao->o |= reg1 << 4;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0x0f00) >> 8;
					return 4;
				}
				if ((reg2 == 13) && (reg1 < 8) && (num >= 0) && (num < 1024) && (num % 4 == 0) && (!(m & DOTW_BIT))) {
					ao->o = 0x0098;
					ao->o |= reg1;
					ao->o |= (num >> 2) << 8;
					return 2;
				}
				if ((num >= 0) && (num < 128) && (num % 4 == 0)) {
					ao->o = 0x0068;
					ao->o |= (num >> 4);
					ao->o |= ((num >> 2) & 0x3) << 14;
					if (mem_16bit_2reg (ao, m)) {
						return 2;
					}
				}
				if ((num > 4095) || (num < -1023)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0xd0f80000;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return mem_32bit_2reg (ao, m);
				}
				ao->o = 0x50f8000c;
				ao->o |= (-num & 0xff) << 8;
				return mem_32bit_2reg (ao, m);
			} else
			if (ldrsel == B_BIT) {
				if (m & T_BIT) {
					if ((num < 0) || (num > 255)) {
						return -1;
					}
					ao->o = 0x10f8000e;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= num << 8;
					return mem_32bit_2reg (ao, m);
				}
				if (reg2 == 15) {
					if ((num > 4095) || (num < -4095)) {
						return -1;
					}
					ao->o = 0x1ff80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					if (num < 0) {
						num = -num;
					} else {
						ao->o |= 1 << 31;
					}
					ao->o |= reg1 << 4;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0x0f00) >> 8;
					return 4;
				}
				if ((num >= 0) && (num < 32) && (!(m & S_BIT))) {
					ao->o = 0x0078;
					ao->o |= (num >> 2);
					ao->o |= (num & 0x3) << 14;
					if (mem_16bit_2reg (ao, m)) {
						return 2;
					}
				}
				if ((num > 4095) || (num < -255)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0x90f80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return mem_32bit_2reg (ao, m);
				}
				ao->o = 0x10f8000c;
				if (m & S_BIT) {
					ao->o |= 1 << 16;
				}
				ao->o |= -num << 8;
				return mem_32bit_2reg (ao, m);
			} else
			if (ldrsel == H_BIT) {
				if (m & T_BIT) {
					if ((num < 0) || (num > 255)) {
						return -1;
					}
					ao->o = 0x30f8000e;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= num << 8;
					return mem_32bit_2reg (ao, m);
				}
				if (reg2 == 15) {
					if ((num > 4095) || (num < -4095)) {
						return -1;
					}
					ao->o = 0x3ff80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					if (num < 0) {
						num = -num;
					} else {
						ao->o |= 1 << 31;
					}
					ao->o |= reg1 << 4;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0x0f00) >> 8;
					return 4;
				}
				if ((num >= 0) && (num < 64) && (num % 2 == 0) && (!(m & S_BIT))) {
					ao->o = 0x0088;
					ao->o |= (num >> 3);
					ao->o |= ((num >> 1) & 0x3) << 14;
					if (mem_16bit_2reg (ao, m)) {
						return 2;
					}
				}
				if ((num > 4095) || (num < -255)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0xb0f80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return mem_32bit_2reg (ao, m);
				}
				ao->o = 0x30f8000c;
				if (m & S_BIT) {
					ao->o |= 1 << 16;
				}
				ao->o |= -num << 8;
				return mem_32bit_2reg (ao, m);
			} else {
				return -1;
			}			
		        }
			break;
		case THUMB_REG_BRACKREGBRACK_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstartend (ao->a[1]);
			st32 num = getnum (ao->a[2]);
			if ((num < -255) || (num > 255)) {
				return -1;
			}
			if (ldrsel == 0) {
				ao->o = 0x50f80009;
			} else 
			if (ldrsel == B_BIT) {
				ao->o = 0x10f80009;
			} else 
			if (ldrsel == H_BIT) {
				ao->o = 0x30f80009;
			} else {
				return -1;
			}
			if (m & S_BIT) {
				ao->o |= 1 << 16;
			}
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 1;
			}
			ao->o |= num << 8;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		case THUMB_REG_BRACKREG_CONSTBRACKBANG: {
			st32 num = getnummemendbang (ao->a[2]);
			if ((num < -255) || (num > 255)) {
				return -1;
			}
			if (ldrsel == 0) {
				ao->o = 0x50f8000d;
			} else 
			if (ldrsel == B_BIT) {
				ao->o = 0x10f8000d;
			} else 
			if (ldrsel == H_BIT) {
				ao->o = 0x30f8000d;
			} else {
				return -1;
			}
			if (m & S_BIT) {
				ao->o |= 1 << 16;
			}
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 1;
			}
			ao->o |= num << 8;
			return mem_32bit_2reg (ao, m);
		        }
			break;
		case THUMB_REG_BRACKREG_REGBRACK: {
			ut8 reg3 = getregmemend (ao->a[2]);
			if (reg3 < 8) {
				if (ldrsel == 0) {
					ao->o = 0x0058;
				} else
				if (ldrsel == B_BIT) {
					if (m & S_BIT) {
						ao->o = 0x0056;
					} else {
						ao->o = 0x005c;
					}
				} else
				if (ldrsel == H_BIT) {
					if (m & S_BIT) {
						ao->o = 0x005e;
					} else {
						ao->o = 0x005a;
					}
				} else
				{
					return -1;
				}
				ao->o |= (reg3 & 0x3) << 14;
				ao->o |= (reg3 & 0x4) >> 2;
				if (mem_16bit_2reg (ao, m)) {
					return 2;
				}
			}
			ao->a[2][strlen (ao->a[2]) -1] = '\0';
			ao->a[3] = "lsl 0]";
		        }
			// intentional fallthrough
		case THUMB_REG_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = getshiftmemend (ao->a[3]);

			shift >>= 2;
			if (shift & 0xffffcfff) {
				return -1;
			}

			if (ldrsel == 0) {
				ao->o = 0x50f80000;
			} else
			if (ldrsel == B_BIT) {
				ao->o = 0x10f80000;
			} else
			if (ldrsel == H_BIT) {
				ao->o = 0x30f80000;
			} else
			{
				return -1;
			}
			if (m & S_BIT) {
				ao->o |= 1 << 16;
			}
			ao->o |= reg3 << 8;
			ao->o |= shift;
			return mem_32bit_2reg (ao, m);
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK: {
			ao->a[2][strlen (ao->a[2]) -1] = '\0';
			ao->a[3] = "0]";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstart (ao->a[2]);
			st32 num = getnummemend (ao->a[3]);

			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != D_BIT)) {
				return -1;
			}
			ao->o = 0x50e90000;
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstartend (ao->a[2]);
			st32 num = getnum (ao->a[3]);
			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != D_BIT)) {
				return -1;
			}
			ao->o = 0x70e80000;
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREG_CONSTBRACKBANG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstart (ao->a[2]);
			st32 num = getnummemendbang (ao->a[3]);
			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != D_BIT)) {
				return -1;
			}
			ao->o = 0x70e90000;
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ldrex", B_BIT | H_BIT | D_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 ldrsel = m & (B_BIT | H_BIT | D_BIT);
		switch (argt) {
		case THUMB_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstartend (ao->a[1]);
			
			if (ldrsel == B_BIT) {
				ao->o = 0xd0e84f0f;
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				return 4;
			} else
			if (ldrsel == H_BIT) {
				ao->o = 0xd0e85f0f;
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				return 4;
			} else
			if (ldrsel == 0) {
				ao->a[1][strlen (ao->a[1]) - 1] = '\0';
				ao->a[2] = "0]";
			} else {
				return -1;
			}
			}
			// intentional fallthrough
		case THUMB_REG_BRACKREG_CONSTBRACK: {
			st32 num = getnummemend (ao->a[2]);
			if ((ldrsel != 0) || (num < 0) || (num > 1020) || (num % 4 != 0)) {
				return -1;
			}
			ao->o = 0x50e8000f;
			ao->o |= (num >> 2) << 8;
			return mem_32bit_2reg (ao, m);
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstartend (ao->a[2]);
			if (!(ldrsel & D_BIT)) {
				return -1;
			}
			ao->o = 0xd0e87f00;
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			return 4;
		}
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "lsl", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);
			if (num > 32) {
				return -1;
			}
			ao->o = 0x0000;			
			if (std_16bit_2reg (ao, m)) {
				ao->o |= (num & 0x03) << 14;
				ao->o |= num >> 2;
				return 2;
			}
			ao->o = 0x4fea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= (num >> 2) << 4;
			ao->o |= (num & 0x3) << 14;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x8040;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x00fa00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else		
	if ((m = opmask (ao->op, "lsr", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);
			if (num > 32) {
				return -1;
			}
			ao->o = 0x0008;
			if (std_16bit_2reg (ao, m)) {
				ao->o |= (num & 0x03) << 14;
				ao->o |= num >> 2;
				return 2;
			}
			ao->o = 0x4fea1000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= (num >> 2) << 4;
			ao->o |= (num & 0x3) << 14;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0xc040;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x20fa00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mcr", R_BIT | TWO_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_REG_COREG_COREG: {
			ao->a[5] = "0";
		        }
			// intentional fallthrough
		case THUMB_COPROC_CONST_REG_COREG_COREG_CONST: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc1 = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 coreg1 = getcoprocreg (ao->a[3]);
			ut32 coreg2 = getcoprocreg (ao->a[4]);
			ut32 opc2 = getnum (ao->a[5]);

			if ((coproc > 15) || (opc1 > 7) || (reg1 > 15) || (coreg1 > 15) || (coreg2 > 15) || (opc2 > 7) || (m & R_BIT)) {
				return -1;
			}

			ao->o = 0x00ee1000;
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			ao->o |= coproc;
			ao->o |= opc1 << 29;
			ao->o |= reg1 << 4;
			ao->o |= coreg1 << 24;
			ao->o |= coreg2 << 8;
			ao->o |= opc2 << 13;
			return 4;
		        }
			break;
		case THUMB_COPROC_CONST_REG_REG_COREG: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 reg2 = getreg (ao->a[3]);
			ut32 coreg = getcoprocreg (ao->a[4]);

			if ((coproc > 15) || (opc > 15) || (reg1 > 15) || (reg2 > 15) || (coreg > 15) || (!(m & R_BIT))) {
				return -1;
			}

			ao->o = 0x40ec0000;
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			ao->o |= coproc;
			ao->o |= opc << 12;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= coreg << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mla", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut32 reg4 = getreg (ao->a[3]);
			if (reg4 > 15) {
				return -1;
			}
			ao->o = 0x00fb0000;
			ao->o |= reg4 << 4;

			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mls", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut32 reg4 = getreg (ao->a[3]);
			if (reg4 > 15) {
				return -1;
			}
			ao->o = 0x00fb1000;
			ao->o |= reg4 << 4;

			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mov", S_BIT | W_BIT | T_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut32 reg1 = getreg (ao->a[0]);
			err = false;
			ut32 num = getnum (ao->a[1]);

			if (reg1 > 15) {
				return -1;
			}
			
			if ((m & W_BIT) || (m & T_BIT)) {
				ut32 wnum = getnum (ao->a[1]);
				if (wnum > 65535) {
					return -1;
				}
				ao->o = 0x40f20000;
				if (m & T_BIT) {
					ao->o |= 1 << 31;
				}
				ao->o |= reg1;
				ao->o |= getthzeroimmed16 (wnum);
				return 4;
			}
			
			if (err) {
				return -1;
			}
			
			if ((num < 256) && (reg1 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x0020;
				ao->o |= reg1;
				ao->o |= num << 8;
				return 2;
			}
				
			ao->o = 0x4ff00000;
			ao->o |= reg1;
			ao->o |= getthimmed12 (ao->a[1]);
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ut32 reg1 = getreg (ao->a[0]);
			ut32 reg2 = getreg (ao->a[1]);
			
			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}

			if ((!(m & S_BIT)) && (!(m & DOTW_BIT))) {
				ao->o = 0x0046;
				ao->o |= (reg1 & 0x7) << 8;
				ao->o |= (reg1 & 0x8) << 12;
				ao->o |= reg2 << 11;
				return 2;
			}
			
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			
			ao->o = 0x4fea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else 
	if ((m = opmask (ao->op, "mrc", TWO_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_REG_COREG_COREG: {
			ao->a[5] = "0";
		        }
			// intentional fallthrough
		case THUMB_COPROC_CONST_REG_COREG_COREG_CONST: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc1 = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 coreg1 = getcoprocreg (ao->a[3]);
			ut32 coreg2 = getcoprocreg (ao->a[4]);
			ut32 opc2 = getnum (ao->a[5]);

			if ((coproc > 15) || (opc1 > 7) || (reg1 > 15) || (coreg1 > 15) || (coreg2 > 15) || (opc2 > 7)) {
				return -1;
			}

			ao->o = 0x10ee1000;
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			ao->o |= coproc;
			ao->o |= opc1 << 29;
			ao->o |= reg1 << 4;
			ao->o |= coreg1 << 24;
			ao->o |= coreg2 << 8;
			ao->o |= opc2 << 13;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mrrc", TWO_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_REG_REG_COREG: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 reg2 = getreg (ao->a[3]);
			ut32 coreg = getcoprocreg (ao->a[4]);

			if ((coproc > 15) || (opc > 15) || (reg1 > 15) || (reg2 > 15) || (coreg > 15)) {
				return -1;
			}

			ao->o = 0x50ec0000;
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			ao->o |= coproc;
			ao->o |= opc << 12;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= coreg << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mrs", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_OTHER: {
			ut32 reg1 = getreg (ao->a[0]);
			r_str_case (ao->a[1], false);

			if (reg1 > 15) {
				return -1;
			}

			if ((!strcmp(ao->a[1], "cpsr")) || (!strcmp(ao->a[1], "apsr"))) {
				ao->o = 0xeff30080;
				ao->o |= reg1;
				return 4;
			}

			if (!strcmp(ao->a[1], "spsr")) {
				ao->o = 0xfff30080;
				ao->o |= reg1;
				return 4;
			}
			
			return -1;
		        }
			break;
		default:
			return -1;
		}
	} else 
	if ((m = opmask (ao->op, "msr", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_OTHER_REG: {
			r_str_case (ao->a[0], false);
			ut8 spsr = 0;
			ut8 bank = interpret_msrbank (ao->a[0], &spsr);
			ut32 reg1 = getreg (ao->a[1]);

			if ((bank == 0) || (reg1 > 15)) {
				return -1;
			}
			
			ao->o = 0x80f30080;
			ao->o |= reg1 << 24;
			ao->o |= bank;
			if (spsr != 0) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mul", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg3 = getreg (ao->a[2]);

			ao->o = 0x4043;
			if ((reg1 == reg3) && (std_16bit_2reg (ao, m))) {
				return 2;
			}

			ao->o = 0x00fb00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mvn", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			err = false;
			ut32 num = getthimmed12 (ao->a[1]);
			
			if ((reg1 > 15) || err) {
				return -1;
			}

			ao->o = 0x6ff00000;
			ao->o |= reg1;
			ao->o |= num;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = thumb_getshift (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}
			
			ao->o = 0xc043;
			if ((shift == 0) && (std_16bit_2reg (ao, m))) {
				return 2;
			}

			ao->o = 0x6fea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= shift;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "nop", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			if (m & DOTW_BIT) {
				ao->o = 0xaff30080;
				return 4;
			}
			ao->o = 0x00bf;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "orn", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if (err) {
				return -1;
			}

			ao->o = 0x60f00000;
			ao->o |= num;
			return (std_32bit_2reg (ao, m, false));
		        }
			break;
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x60ea0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else 
	if ((m = opmask (ao->op, "orr", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if (err) {
				return -1;
			}

			ao->o = 0x40f00000;
			ao->o |= num;
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x0043;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x40ea0000;
			return (std_32bit_3reg (ao, m, true));
		        }
			break;
		default:
			return -1;
		}
	} else 
	if ((m = opmask (ao->op, "pkh", BT_BIT | TB_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & TB_BIT) {
				ao->a[3] = "asr 0";
			} else
			if (m & BT_BIT) {
				ao->a[3] = "lsl 0";
			} else {
				return -1;
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut32 shift = thumb_getshift (ao->a[3]);

			if (((m & TB_BIT) && ((shift & 0x00003000) != 0x00002000)) || ((m & BT_BIT) && ((shift & 0x00003000) != 0)) || ((m & (TB_BIT | BT_BIT)) == 0)) {	
				return -1;
			}

			ao->o = 0xc0ea0000;
			return (std_32bit_3reg (ao, m, true));
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "pld", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			st32 num = getnummemend (ao->a[1]);

			if (reg1 == 15) {
				if ((num < -4095) || (num > 4095)) {
					return -1;
				}
				ao->o = 0x1ff800f0;
				if (num > 0) {
					ao->o |= 1 << 31;
				} else {
					num = -num;
				}
				ao->o |= (num & 0x0ff) << 8;
				ao->o |= (num & 0xf00) >> 8;
				return 4;
			}

			if ((reg1 > 15) || (num < -255) || (num > 4095)) {
				return -1;
			}

			if (num > 0) {
				ao->o = 0x90f800f0;
				ao->o |= (num & 0x0ff) << 8;
				ao->o |= (num & 0xf00) >> 8;
				ao->o |= reg1 << 24;
				return 4;
			}
			num = -num;
			ao->o = 0x10f800fc;
			ao->o |= num << 8;
			ao->o |= reg1 << 24;
			return 4;
		        }
			break;
		case THUMB_BRACKREG_REGBRACK: {
			ao->a[1][strlen (ao->a[1]) - 1] = '\0';
			ao->a[2] = "lsl 0]";
		        }
			// intentional fallthrough
		case THUMB_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = getshiftmemend (ao->a[2]) >> 2;

			if ((reg1 > 15) || (reg2 > 15) || ((shift & 0xffffcfff) != 0)) {
				return -1;
			}

			ao->o = 0x10f800f0;
			ao->o |= reg1 << 24;
			ao->o |= reg2 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "pli", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			st32 num = getnummemend (ao->a[1]);

			if (reg1 == 15) {
				if ((num < -4095) || (num > 4095)) {
					return -1;
				}
				ao->o = 0x1ff900f0;
				if (num > 0) {
					ao->o |= 1 << 31;
				} else {
					num = -num;
				}
				ao->o |= (num & 0x0ff) << 8;
				ao->o |= (num & 0xf00) >> 8;
				return 4;
			}

			if ((reg1 > 15) || (num < -255) || (num > 4095)) {
				return -1;
			}

			if (num > 0) {
				ao->o = 0x90f900f0;
				ao->o |= (num & 0x0ff) << 8;
				ao->o |= (num & 0xf00) >> 8;
				ao->o |= reg1 << 24;
				return 4;
			}
			num = -num;
			ao->o = 0x10f900fc;
			ao->o |= num << 8;
			ao->o |= reg1 << 24;
			return 4;
		        }
			break;
		case THUMB_BRACKREG_REGBRACK: {
			ao->a[1][strlen (ao->a[1]) -1] = '\0';
			ao->a[2] = "lsl 0]";
		        }
			// intentional fallthrough
		case THUMB_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = getshiftmemend (ao->a[2]) >> 2;

			if ((reg1 > 15) || (reg2 > 15) || ((shift & 0xffffcfff) != 0)) {
				return -1;
			}

			ao->o = 0x10f900f0;
			ao->o |= reg1 << 24;
			ao->o |= reg2 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "pop", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_LIST: {
			st32 list = getreglist (ao->a[0]);
			if ((list <= 0) || ((list & (1 << 13)) != 0)) {
				return -1;
			}
			if ((!(m & DOTW_BIT)) && ((list & 0x00007f00) == 0)) {
				ao->o = 0x00bc;
				ao->o |= (list & 0x8000) >> 15;
				ao->o |= (list & 0xff) << 8;
				return 2;
			}
			ao->o = 0xbde80000;
			ao->o |= (list & 0xff00) >> 8;
			ao->o |= (list & 0xff) << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "push", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_LIST: {
			st32 list = getreglist (ao->a[0]);
			if ((list <= 0) || ((list & 0x0000a000) != 0)) {
				return -1;
			}
			if ((!(m & DOTW_BIT)) && ((list & 0x00001f00) == 0)) {
				ao->o = 0x00b4;
				ao->o |= (list & 0x4000) >> 14;
				ao->o |= (list & 0xff) << 8;
				return 2;
			}
			ao->o = 0x2de90000;
			ao->o |= (list & 0xff00) >> 8;
			ao->o |= (list & 0xff) << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qadd", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0x90fa10f0;
			} else
			if (m & EIGHT_BIT) {
				ao->o = 0x80fa10f0;
			} else {
				ao->o = 0x80fa80f0;
			}

			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa10f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qdadd", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x80fa90f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qdsub", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x80fab0f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qsax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa10f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "qsub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0xd0fa10f0;
			} else
			if (m & EIGHT_BIT) {
				ao->o = 0xc0fa10f0;
			} else {
				ao->o = 0x80faa0f0;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "rbit", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->a[2] = ao->a[1];
			ao->o = 0x90faa0f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "rev", SIXTEEN_BIT | SH_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0x40ba;
			} else
			if (m & SH_BIT) {
				ao->o = 0xc0ba;
			} else {
				ao->o = 0x00ba;
			}

			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			
			if (m & SIXTEEN_BIT) {
				ao->o = 0x90fa90f0;
			} else
			if (m & SH_BIT) {
				ao->o = 0x90fab0f0;
			} else {
				ao->o = 0x90fa80f0;
			}
			ao->a[2] = ao->a[1];
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "rfe", IA_BIT | FD_BIT | DB_BIT | EA_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 wb = 0;
		switch (argt) {
		case THUMB_REGBANG: {
			ao->a[0][strlen (ao->a[0]) - 1] = '\0';
			wb = 0x20000000;
		        }
			// intentional fallthrough
		case THUMB_REG: {
			ut8 reg1 = getreg (ao->a[0]);

			if (reg1 > 15) {
				return -1;
			}
			
			if ((m & DB_BIT) || (m & EA_BIT)) {
				ao->o = 0x10e800c0;
			} else {
				ao->o = 0x90e900c0;
			}

			ao->o |= reg1 << 24;
			ao->o |= wb;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ror", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15) || (num > 31) || (num < 1)) {
				return -1;
			}

			ao->o = 0x4fea3000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= (num & 0x3) << 14;
			ao->o |= (num & 0x1c) << 2;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0xc041;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x60fa00f0;
			return (std_32bit_3reg (ao, m, false));
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "rrx", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			
			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}
			
			ao->o = 0x4fea3000;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "rsb", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if (err) {
				return -1;
			}

			ao->o = 0x4042;
			if ((num == 0) && std_16bit_2reg (ao, m)) {
				return 2;
			}

			ao->o = 0xc0f10000;
			ao->o |= num;
			return (std_32bit_2reg (ao, m, false));
		        }
			break;
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0xc0eb0000;
			return (std_32bit_3reg (ao, m, true));
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sadd", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0x90fa00f0;
			} else
			if (m & EIGHT_BIT) {
				ao->o = 0x80fa00f0;
			} else {
				return -1;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sbc", S_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->o = 0x8041;
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ao->o = 0x60eb0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ao->o = 0x60f10000;
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if (err) {
				return -1;
			}
			ao->o |= num;
			
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "sbfx", 0) )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST_CONST: {
			ut32 lsb = getnum (ao->a[2]);
			ut32 width = getnum (ao->a[3]);
			ut32 msb = lsb + width - 1;
			if ((lsb > 31) || (msb > 31)) {
				return -1;
			}
			ao->o = 0x40f30000;
			ao->o |= ((lsb & 0x1c) << 2);
			ao->o |= ((lsb & 0x3) << 14);
			ao->o |= ((width - 1) << 8);
			return std_32bit_2reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sdiv", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x90fbf0f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sel", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa80f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "setend", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_OTHER: {
			r_str_case (ao->a[0], false);
			ao->o = 0x50b6;
			if (!(strcmpnull (ao->a[0], "be"))) {
				ao->o |= 1 << 11;
				return 2;
			} else
			if (!(strcmpnull (ao->a[0], "le"))) {
				return 2;
			} else {
				return -1;
			}
			break;
		        }
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sev", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE:
			if (m & DOTW_BIT) {
				ao->o = 0xaff30480;
				return 4;
			} else {
				ao->o = 0x40bf;
				return 2;
			}
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "shadd", EIGHT_BIT | SIXTEEN_BIT ))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0x90fa20f0;
			} else
			if (m & EIGHT_BIT) {
				ao->o = 0x80fa20f0;
			} else {
				return -1;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "shasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa20f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "shsax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa20f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "shsub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & SIXTEEN_BIT) {
				ao->o = 0xd0fa20f0;
			} else
			if (m & EIGHT_BIT) {
				ao->o = 0xc0fa20f0;
			} else {
				return -1;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smc", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			err = false;
			ut32 num = getnum (ao->a[0]);
			
			if (err || (num > 15)) {
				return -1;
			}

			ao->o = 0xf0f70080;
			ao->o |= num << 24;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smla", BB_BIT | BT_BIT | TB_BIT | TT_BIT | WB_BIT | WT_BIT | L_BIT | D_BIT | X_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);
			
			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15) || (m & DOTN_BIT)) {
				return -1;
			}
			if (m & L_BIT) {
				if (m & BB_BIT) {
					ao->o = 0xc0fb8000;
				} else
				if (m & BT_BIT) {
					ao->o = 0xc0fb9000;
				} else
				if (m & TB_BIT) {
					ao->o = 0xc0fba000;
				} else
				if (m & TT_BIT) {
					ao->o = 0xc0fbb000;
				} else
				if (m & D_BIT) {
					ao->o = 0xc0fbc000;
					if (m & X_BIT) {
						ao->o |= 1 << 12;
					}
				} else {
					ao->o = 0xc0fb0000;
				}
				ao->o |= reg1 << 4;
				ao->o |= reg2;
				ao->o |= reg3 << 24;
				ao->o |= reg4 << 8;
				return 4;
			}
			if (m & BB_BIT) {
				ao->o = 0x10fb0000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & BT_BIT) {
				ao->o = 0x10fb1000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & TB_BIT) {
				ao->o = 0x10fb2000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & TT_BIT) {
				ao->o = 0x10fb3000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & D_BIT) {
				ao->o = 0x20fb0000;
				if (m & X_BIT) {
					ao->o |= 1 << 12;
				}
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & WB_BIT) {
				ao->o = 0x30fb0000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			if (m & WT_BIT) {
				ao->o = 0x30fb1000;
				ao->o |= reg4 << 4;
				return std_32bit_3reg (ao, m, false);
			}
			return -1;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smlsd", X_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg4 = getreg (ao->a[3]);

			if (reg4 > 15) {
				return -1;
			}
			ao->o = 0x40fb0000;
			if (m & X_BIT) {
				ao->o |= 1 << 12;
			}
			ao->o |= reg4 << 4;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smlsld", X_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15) || (m & DOTN_BIT)) {
				return -1;
			}
			ao->o = 0xd0fbc000;

			if (m & X_BIT) {
				ao->o |= 1 << 12;
			}

			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= reg4 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smmla", R_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg4 = getreg (ao->a[3]);

			if (reg4 > 15) {
				return -1;
			}
			ao->o = 0x50fb0000;
			if (m & R_BIT) {
				ao->o |= 1 << 12;
			}
			ao->o |= reg4 << 4;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smmls", R_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg4 = getreg (ao->a[3]);

			if (reg4 > 15) {
				return -1;
			}
			ao->o = 0x60fb0000;
			if (m & R_BIT) {
				ao->o |= 1 << 12;
			}
			ao->o |= reg4 << 4;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smmul", R_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x50fb00f0;
			if (m & R_BIT) {
				ao->o |= 1 << 12;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smuad", X_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x20fb00f0;
			if (m & X_BIT) {
				ao->o |= 1 << 12;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smul", BB_BIT | BT_BIT | TB_BIT | TT_BIT | WB_BIT | WT_BIT | L_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & BB_BIT) {
				ao->o = 0x10fb00f0;
			} else
			if (m & BT_BIT) {
				ao->o = 0x10fb10f0;
			} else
			if (m & TB_BIT) {
				ao->o = 0x10fb20f0;
			} else
			if (m & TT_BIT) {
				ao->o = 0x10fb30f0;
			} else
			if (m & WB_BIT) {
				ao->o = 0x30fb00f0;
			} else
			if (m & WT_BIT) {
				ao->o = 0x30fb10f0;
			} else {
				return -1;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15) || (m & DOTN_BIT) || (!(m & L_BIT))) {
				return -1;
			}

			ao->o = 0x80fb0000;
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= reg4 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "smusd", X_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x40fb00f0;
			if (m & X_BIT) {
				ao->o |= 1 << 12;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "srs", DB_BIT | FD_BIT | IA_BIT | EA_BIT))) {
		ut32 w = 0;
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONSTBANG: {
			ao->a[0][strlen (ao->a[0]) - 1] = '\0';
			w = 1;
		        }
			// intentional fallthrough
		case THUMB_CONST: {
			ut32 num = getnum (ao->a[0]);
			if (num > 31) {
				return -1;
			}
			if ((m & DB_BIT) || (m & FD_BIT)) {
				ao->o = 0x0de800c0;
			} else {
				ao->o = 0x8de900c0;
			}				
			ao->o |= num << 8;
			ao->o |= w << 29;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ssat", SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_CONST_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 num = getnum (ao->a[1]) - 1;
			ut8 reg2 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if (err || (reg1 > 15) || (reg2 > 15) || (num > 31) || (shift & 0x00001000) || ((m & SIXTEEN_BIT) && shift)) {
				return -1;
			}

			if (shift & 0x00002000) {
				shift |= 0x20000000;
				shift &= 0xffffdfff;
			}

			if (m & SIXTEEN_BIT) {
				ao->o = 0x20f30000;
			} else {
				ao->o = 0x00f30000;
			}

			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= num << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ssax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa00f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ssub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & EIGHT_BIT) {
				ao->o = 0xc0fa00f0;
			} else
			if (m & SIXTEEN_BIT) {
				ao->o = 0xd0fa00f0;
			} else {
				return -1;
			}
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else if ((m = opmask (ao->op, "stc", L_BIT | TWO_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_COREG_BRACKREGBRACK: {
			ao->a[2][strlen (ao->a[2]) - 1] = '\0';
			ao->a[3] = "0]";
		        }
			// intentional fallthrough
		case THUMB_COPROC_COREG_BRACKREG_CONSTBRACK: {
			ut8 coproc = getcoproc (ao->a[0]);
			ut8 coreg = getcoprocreg (ao->a[1]);
			ut8 reg = getregmemstart (ao->a[2]);
			st32 num = getnummemend (ao->a[3]);

			if ((coproc > 15) || (coreg > 15) || (reg > 15) || (num > 4092) || (num < -4092) || (num % 4 != 0)) {
				return -1;
			}
		
			ao->o = 0x00ed0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}				
			ao->o |= coproc;
			ao->o |= coreg << 4;
			ao->o |= reg << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_COPROC_COREG_BRACKREGBRACK_CONST: {
			ut8 coproc = getcoproc (ao->a[0]);
			ut8 coreg = getcoprocreg (ao->a[1]);
			ut8 reg = getregmemstartend (ao->a[2]);
			st32 num = getnum (ao->a[3]);

			if ((coproc > 15) || (coreg > 15) || (reg > 15) || (num > 4092) || (num < -4092) || (num % 4 != 0)) {
				return -1;
			}
		
			ao->o = 0x20ec0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= coproc;
			ao->o |= coreg << 4;
			ao->o |= reg << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_COPROC_COREG_BRACKREG_CONSTBRACKBANG: {
			ut8 coproc = getcoproc (ao->a[0]);
			ut8 coreg = getcoprocreg (ao->a[1]);
			ut8 reg = getregmemstart (ao->a[2]);
			st32 num = getnummemendbang (ao->a[3]);

			if ((coproc > 15) || (coreg > 15) || (reg > 15) || (num > 4092) || (num < -4092) || (num % 4 != 0)) {
				return -1;
			}
		
			ao->o = 0x20ed0000;
			if (m & L_BIT) {
				ao->o |= 1 << 30;
			}
			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}
			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= coproc;
			ao->o |= coreg << 4;
			ao->o |= reg << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else if ((m = opmask (ao->op, "stm", FD_BIT | DB_BIT | IA_BIT | EA_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		bool wb = false;
		switch (argt) {
		case THUMB_REGBANG_LIST: {
			wb = true;
			ao->a[0][strlen (ao->a[0]) - 1] = '\0';
		        }
			// intentional fallthrough
		case THUMB_REG_LIST: {
			ut8 reg = getreg (ao->a[0]);
			st32 list = getreglist (ao->a[1]);
			if ((list <= 0) || ((list & 0x0000a000) != 0)) {
				return -1;
			}

			if ((!(m & DOTW_BIT)) && ((list & 0x0000ff00) == 0) && (!(m & (FD_BIT | DB_BIT))) && wb) {
				ao->o = 0x00c0;
				ao->o |= (list & 0x000000ff) << 8;
				ao->o |= reg;
				return 2;
			}

			if ((m & (FD_BIT | DB_BIT | IA_BIT | EA_BIT)) == 0) {
				return -1;
			}
			
			if (m & (FD_BIT | DB_BIT)) {
				ao->o = 0x00e90000;
			} else {
				ao->o = 0x80e80000;
			}

			if (wb) {
				ao->o |= 1 << 29;
			}

			ao->o |= reg << 24;
			ao->o |= (list & 0x000000ff) << 8;
			ao->o |= (list & 0x0000ff00) >> 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else if ((m = opmask (ao->op, "str", B_BIT | T_BIT | D_BIT | H_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 strsel = m & (B_BIT | H_BIT | D_BIT);
		switch (argt) {
		case THUMB_REG_BRACKREGBRACK:
			if (ao->a[2] == NULL) { // double fallthrough
				ao->a[1][strlen (ao->a[1]) -1] = '\0';
				ao->a[2] = "0]";
			}
			// intentional fallthrough
		case THUMB_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			st32 num = getnummemend (ao->a[2]);
			if (m & T_BIT) {
				if ((num < 0) || (num > 255)) {
					return -1;
				}
				if (strsel == 0) {
					ao->o = 0x40f8000e;
				} else
			        if (strsel == H_BIT) {
					ao->o = 0x20f8000e;
				} else
			        if (strsel == B_BIT) {
					ao->o = 0x00f8000e;
				} else {
					return -1;
				}
				ao->o |= num << 8;
				return mem_32bit_2reg (ao, m);
			}
			
			if ((strsel == 0) && (reg2 == 13) && (num >= 0) && (num < 1024) && ((num % 4) == 0) && (reg1 < 8) & (!(m & DOTW_BIT))) {
				ao->o = 0x0090;
				ao->o |= reg1;
				ao->o |= (num >> 2) << 8;
				return 2;
			}

			bool t1form = false;
			if ((strsel == 0) && (num < 128) && (num >= 0) && (num % 4 == 0)) {
				ao->o = 0x0060;
				ao->o |= (num >> 4);
				ao->o |= ((num >> 2) & 0x3) << 14;
				t1form = true;
			}
			if ((strsel == B_BIT) && (num < 32) && (num >= 0)) {
				ao->o = 0x0070;
				ao->o |= (num >> 2);
				ao->o |= (num & 0x3) << 14;
				t1form = true;
			}
			if ((strsel == H_BIT) && (num < 64) && (num >= 0) && (num % 2 == 0)) {
				ao->o = 0x0080;
				ao->o |= (num >> 3);
				ao->o |= ((num >> 1) & 0x3) << 14;
				t1form = true;
			}
			if (t1form) {
				if (mem_16bit_2reg (ao, m)) {
					return 2;
				}
			}
			
			if ((num > 4095) || (num < -255)) {
				return -1;
			}
			if (num >= 0) {
				if (strsel == 0) {
					ao->o = 0xc0f80000;
				} else
				if (strsel == B_BIT) {
					ao->o = 0x80f80000;
				} else
				if (strsel == H_BIT) {
					ao->o = 0xa0f80000;
				} else {
					return -1;
				}
				ao->o |= (num >> 8);
				ao->o |= (num & 0x000000ff) << 8;
				return mem_32bit_2reg (ao, m);
			}
			if (strsel == 0) {
				ao->o = 0x40f8000c;
			} else
			if (strsel == B_BIT) {
				ao->o = 0x00f8000c;
			} else
			if (strsel == H_BIT) {
				ao->o = 0x20f8000c;
			} else {
				return -1;
			}
			ao->o |= -num << 8;
			return mem_32bit_2reg (ao, m);
		        }
			break;
		case THUMB_REG_BRACKREGBRACK_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstartend (ao->a[1]);
			st32 num = getnum (ao->a[2]);

			if ((num > 255) || (num < -255)) {
				return -1;
			}

			if (strsel == 0) {
				ao->o = 0x40f80009;
			} else 
			if (strsel == B_BIT) {
				ao->o = 0x00f80009;
			} else 
			if (strsel == H_BIT) {
				ao->o = 0x20f80009;
			} else {
				return -1;
			}

			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 1;
			}
			ao->o |= num << 8;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		case THUMB_REG_BRACKREG_CONSTBRACKBANG: {
			st32 num = getnummemendbang (ao->a[2]);

			if ((num > 255) || (num < -255)) {
				return -1;
			}

			if (strsel == 0) {
				ao->o = 0x40f8000d;
			} else 
			if (strsel == B_BIT) {
				ao->o = 0x00f8000d;
			} else 
			if (strsel == H_BIT) {
				ao->o = 0x20f8000d;
			} else {
				return -1;
			}

			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 1;
			}
			ao->o |= num << 8;
			return mem_32bit_2reg (ao, m);
		        }
			break;
		case THUMB_REG_BRACKREG_REGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			ut8 reg3 = getregmemend (ao->a[2]);
			if ((reg1 < 8) && (reg2 < 8) && (reg3 < 8) && (!(m & DOTW_BIT))) {
				if (strsel == 0) {
					ao->o = 0x0050;
				} else
				if (strsel == B_BIT) {
					ao->o = 0x0054;
				} else
				if (strsel == H_BIT) {
					ao->o = 0x0052;
				} else {
					return -1;
				}
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				ao->o |= (reg3 & 0x3) << 14;
				ao->o |= (reg3 >> 2);
				return 2;
			}
			ao->a[2][strlen (ao->a[2]) - 1] = '\0';
			ao->a[3] = "lsl 0]";
		        }
			// intentional fallthrough
		case THUMB_REG_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = getshiftmemend (ao->a[3]) >> 2;
			
			if (((shift & 0xffffcfff) != 0) || (reg1 > 15) || (reg2 > 15) || (reg3 > 15)) {
				return -1;
			}

			if (strsel == 0) {
				ao->o = 0x40f80000;
			} else 
			if (strsel == B_BIT) {
				ao->o = 0x00f80000;
			} else 
			if (strsel == H_BIT) {
				ao->o = 0x20f80000;
			} else {
				return -1;
			}
			
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK: {
			ao->a[2][strlen (ao->a[2]) - 1] = '\0';
			ao->a[3] = "0]";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstart (ao->a[2]);
			st32 num = getnummemend (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (strsel != D_BIT) || (num > 1023) || (num < -1023) || ((num % 4) != 0)) {
				return -1;
			}

			ao->o = 0x40e90000;

			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREG_CONSTBRACKBANG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstart (ao->a[2]);
			st32 num = getnummemendbang (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (strsel != D_BIT) || (num > 1023) || (num < -1023) || ((num % 4) != 0)) {
				return -1;
			}

			ao->o = 0x60e90000;

			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstartend (ao->a[2]);
			st32 num = getnum (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (strsel != D_BIT) || (num > 1023) || (num < -1023) || ((num % 4) != 0)) {
				return -1;
			}

			ao->o = 0x60e80000;

			if (num < 0) {
				num = -num;
			} else {
				ao->o |= 1 << 31;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "strex", B_BIT | D_BIT | H_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 strsel = m & (B_BIT | H_BIT | D_BIT);
		switch (argt) {
		case THUMB_REG_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstartend (ao->a[2]);
			
			if ((strsel == D_BIT) || (reg1 > 15) || (reg2 > 15) || (reg3 > 15)) {
				return -1;
			}
			if (strsel == B_BIT) {
				ao->o = 0xc0e8400f;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 4;
				ao->o |= reg3 << 24;
				return 4;
			} else
			if (strsel == H_BIT) {
				ao->o = 0xc0e8500f;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 4;
				ao->o |= reg3 << 24;
				return 4;
			}

			ao->a[2][strlen (ao->a[2]) - 1] = '\0';
			ao->a[3] = "0]";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstart (ao->a[2]);
			st32 num = getnummemend (ao->a[3]);

			if ((strsel != 0) || (reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (num < 0) || (num > 1023) || ((num % 4) !=0)) {
				return -1;
			}

			ao->o = 0x40e80000;
			ao->o |= reg1;
			ao->o |= reg2 << 4;
			ao->o |= reg3 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getregmemstartend (ao->a[3]);

			if ((strsel != D_BIT) || (reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}

			ao->o = 0xc0e87000;
			ao->o |= reg1 << 8;
			ao->o |= reg2 << 4;
			ao->o |= reg3;
			ao->o |= reg4 << 24;
			return 4;
		        }
			break;
		}
	} else 
	if ((m = opmask (ao->op, "sub", S_BIT | W_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}

			if ((reg1 == 15) && (reg2 == 14) && (num < 256)) {
				ao->o = 0xdef3008f;
				ao->o |= num << 8;
				return 4;
			}
			if (reg2 == 13) {
				if ((reg1 == 13) && (!(m & DOTW_BIT)) && (!(m & W_BIT)) && (num <= 4096) && (num % 4 == 0)) {
					ao->o = 0x80b0;
					ao->o |= (num >> 2) << 8;
					return 2;
				}
				err = false;
				ut32 thnum = getthimmed12 (ao->a[2]);
				
				if (!err && (!(m & W_BIT))) {
					ao->o = 0xadf10000;
					ao->o |= thnum;
					ao->o |= reg1;
					if (m & S_BIT) {
						ao->o |= 1 << 28;
					}
					return 4;
				}

				if (num > 4096) {
					return -1;
				}

				ao->o = 0xadf20000;
				ao->o |= getthzeroimmed12 (num);
				ao->o |= reg1;
				return 4;
			}

			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT)) && (!(m & W_BIT)) && (num < 8)) {
				ao->o = 0x001e;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				ao->o |= (num & 0x3) << 14;
				ao->o |= (num >> 2);
				return 2;
			}

			if ((reg1 < 8) && (reg1 == reg2) && (!(m & DOTW_BIT)) && (!(m & W_BIT)) && (num < 256)) {
				ao->o = 0x0038;
				ao->o |= reg1;
				ao->o |= num << 8;
				return 2;
			}

			err = false;
			ut32 thnum = getthimmed12 (ao->a[2]);
			
			if (!err && (!(m & W_BIT))) {
				ao->o = 0xa0f10000;
				ao->o |= thnum;
				return std_32bit_2reg (ao, m, false);
			}

			if (num > 4096) {
				return -1;
			}

			ao->o = 0xa0f20000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= getthzeroimmed12 (num);
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT:
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if (reg2 == 13) {
				ao->o = 0xadeb0000;
				ao->o |= reg1;
				ao->o |= reg3 << 8;
				ao->o |= shift;
				if (m & S_BIT) {
					ao->o |= 1 << 28;
				}
				return 4;
			}

			if ((shift == 0) && (reg1 < 8) && (reg2 < 8) && (reg3 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x001a;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				ao->o |= (reg3 & 0x3) << 14;
				ao->o |= (reg3 >> 2);
				return 2;
			}
			
			ao->o = 0xa0eb0000;
			return std_32bit_3reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "svc", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_CONST: {
			ut32 num = getnum (ao->a[0]);
			if (num > 255) {
				return -1;
			}
			ao->o = 0x00df;
			ao->o |= num << 8;
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "sxta", B_BIT | H_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut32 shift = thumb_getshift (ao->a[3]);

			if ((shift != 0) && ((shift & 0x0000f010) != 0x00003000)) {
				return -1;
			}

			ut64 sufsel = m & (B_BIT | H_BIT | SIXTEEN_BIT);
			
			if (sufsel == B_BIT) {
				ao->o = 0x40fa80f0;
			} else
			if (sufsel == (B_BIT | SIXTEEN_BIT)) {
				ao->o = 0x20fa80f0;
			} else
			if (sufsel == H_BIT) {
				ao->o = 0x00fa80f0;
			} else {
				return -1;
			}

			ao->o |= (shift & 0x00000060) << 7;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		}
	} else
	if ((m = opmask (ao->op, "sxt", B_BIT | H_BIT | SIXTEEN_BIT))) {
		ut64 sufsel = m & (B_BIT | H_BIT | SIXTEEN_BIT);
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = thumb_getshift (ao->a[2]);

			if ((reg1 > 15) && (reg2 > 15) && (shift != 0) && ((shift & 0x0000f010) != 0x00003000)) {
				return -1;
			}

			if (sufsel == B_BIT) {
				ao->o = 0x40b2;
				if ((shift == 0) && std_16bit_2reg (ao, m)) {
					return 2;
				}
				ao->o = 0x4ffa80f0;
			} else
			if (sufsel == (B_BIT | SIXTEEN_BIT)) {
				ao->o = 0x2ffa80f0;
			} else
			if (sufsel == H_BIT) {
				ao->o = 0x00b2;
				if ((shift == 0) && std_16bit_2reg (ao, m)) {
					return 2;
				}
				ao->o = 0x0ffa80f0;
			} else {
				return -1;
			}

			ao->o |= (shift & 0x00000060) << 7;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			return 4;
		        }
			break;
		}
	} else
	if ((m = opmask (ao->op, "tb", B_BIT | H_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (B_BIT | H_BIT);
		switch (argt) {
		case THUMB_BRACKREG_REGBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			ut8 reg2 = getregmemend (ao->a[1]);

			if ((reg1 > 15) || (reg2 > 15)) {
				return -1;
			}

			if (sufsel == B_BIT) {
				ao->o = 0xd0e800f0;
				ao->o |= reg1 << 24;
				ao->o |= reg2 << 8;
				return 4;
			}
			ao->a[1][strlen (ao->a[1]) - 1] = '\0';
			ao->a[2] = "lsl 1]";
		        }
			// intentional fallthrough
		case THUMB_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg1 = getregmemstart (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = getshiftmemend (ao->a[2]);
			
			if ((reg1 > 15) || (reg2 > 15) || (shift != 0x00004000) || (sufsel != H_BIT)) {
				return -1;
			}

			ao->o = 0xd0e810f0;
			ao->o |= reg1 << 24;
			ao->o |= reg2 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "teq", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg = getreg (ao->a[0]);
			err = false;
			ut32 num = getthimmed12 (ao->a[1]);

			if (err || (reg > 15)) {
				return -1;
			}

			ao->o = 0x90f0000f;
			ao->o |= reg << 24;
			ao->o |= num;
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ao->o = 0x90ea000f;
			return std_32bit_2reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "tst", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			err = false;
			ut32 num = getthimmed12 (ao->a[1]);

			if (err || (reg1 > 15)) {
				return -1;
			}

			ao->o = 0x10f0000f;
			ao->o |= reg1 << 24;
			ao->o |= num;
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->o = 0x0042;
			
			if (std_16bit_2reg (ao, m)) {
				return 2;
			}

			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ao->o = 0x10ea000f;
			return std_32bit_2reg (ao, m, true);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uadd", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & EIGHT_BIT) {
				ao->o = 0x80fa40f0;
			} else
			if (m & SIXTEEN_BIT) {
				ao->o = 0x90fa40f0;
			} else {
				return -1;
			}

			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa40f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ubfx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 lsb = getnum (ao->a[2]);
			ut32 widthm1 = getnum (ao->a[3]) - 1;
			
			if ((reg1 > 15) || (reg2 > 15) || (lsb > 31) || ((31 - lsb) <= widthm1)) {
				return -1;
			}

			ao->o = 0xc0f30000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= (lsb & 0x1c) << 2;
			ao->o |= (lsb & 0x3) << 14;
			ao->o |= widthm1 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "udiv", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xb0fbf0f0;
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uhadd", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (EIGHT_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (sufsel == EIGHT_BIT) {
				ao->o = 0x80fa60f0;
			} else 
			if (sufsel == SIXTEEN_BIT) {
				ao->o = 0x90fa60f0;
			} else {
				return -1;
			}
				
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uhasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa60f0;
			
			return std_32bit_3reg (ao, m, false);
			
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uhsax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa60f0;
			
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uhsub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (EIGHT_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (sufsel == EIGHT_BIT) {
				ao->o = 0xc0fa60f0;
			} else 
			if (sufsel == SIXTEEN_BIT) {
				ao->o = 0xd0fa60f0;
			} else {
				return -1;
			}
				
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "umaal", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}
			
			ao->o = 0xe0fb6000;
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= reg4 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "umlal", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}
			
			ao->o = 0xe0fb0000;
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= reg4 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "umull", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}
			
			ao->o = 0xa0fb0000;
			ao->o |= reg1 << 4;
			ao->o |= reg2;
			ao->o |= reg3 << 24;
			ao->o |= reg4 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uqadd", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (EIGHT_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (sufsel == EIGHT_BIT) {
				ao->o = 0x80fa50f0;
			} else 
			if (sufsel == SIXTEEN_BIT) {
				ao->o = 0x90fa50f0;
			} else {
				return -1;
			}
				
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uqasx", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xa0fa50f0;
			
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uqsax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa50f0;
			
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uqsub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (EIGHT_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (sufsel == EIGHT_BIT) {
				ao->o = 0xc0fa50f0;
			} else 
			if (sufsel == SIXTEEN_BIT) {
				ao->o = 0xd0fa50f0;
			} else {
				return -1;
			}
				
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "usad8", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0x70fb00f0;
			
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "usada8", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut8 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}
			
			ao->o = 0x70fb0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= reg4 << 4;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "usat", SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST_REG: {
			if (m & SIXTEEN_BIT) {
				ut8 reg1 = getreg (ao->a[0]);
				ut32 num = getnum (ao->a[1]);
				ut8 reg2 = getreg (ao->a[2]);

				if ((reg1 > 15) || (num > 15) || (reg2 > 15)) {
					return -1;
				}

				ao->o = 0xa0f30000;
				ao->o |= reg1;
				ao->o |= reg2 << 24;
				ao->o |= num << 8;
				return 4;
			}

			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_CONST_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 num = getnum (ao->a[1]);
			ut8 reg2 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if ((reg1 > 15) || (num > 31) || (reg2 > 15) || (m & SIXTEEN_BIT) || ((shift & 0x00001000) != 0)) {
				return -1;
			}

			ao->o = 0x80f30000;
			ao->o |= reg1;
			ao->o |= (num & 0xf) << 8;
			ao->o |= (num >> 4 ) << 12;
			ao->o |= reg2 << 24;
			ao->o |= (shift & 0x00002000) << 16;
			ao->o |= (shift & 0x0000c070);
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "usax", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->o = 0xe0fa40f0;
			
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "usub", EIGHT_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (EIGHT_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (sufsel == EIGHT_BIT) {
				ao->o = 0xc0fa40f0;
			} else 
			if (sufsel == SIXTEEN_BIT) {
				ao->o = 0xd0fa40f0;
			} else {
				return -1;
			}
				
			return std_32bit_3reg (ao, m, false);
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uxta", B_BIT | H_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (B_BIT | H_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			std_opt_2 (ao);
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				std_opt_3 (ao);
			}
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut32 shift = thumb_getshift (ao->a[3]);

			if (shift && ((shift & 0x0000f010) != 0x00003000)) {
				return -1;
			}

			if (sufsel == B_BIT) {
				ao->o = 0x50fa80f0;
			} else
			if (sufsel == (B_BIT | SIXTEEN_BIT)) {
				ao->o = 0x30fa80f0;
			} else
			if (sufsel == H_BIT) {
				ao->o = 0x10fa80f0;
			} else {
				return -1;
			}

			ao->o |= (shift & 0x00000060) << 7;
			return (std_32bit_3reg (ao, m, false));
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "uxt", B_BIT | H_BIT | SIXTEEN_BIT))) {
		ut64 argt = thumb_selector (ao->a);
		ut64 sufsel = m & (B_BIT | H_BIT | SIXTEEN_BIT);
		switch (argt) {
		case THUMB_REG_REG: {
			if ((sufsel == B_BIT) || (sufsel == H_BIT)) {
				if (sufsel == B_BIT) {
					ao->o = 0xc0b2;
				} else {
					ao->o = 0x80b2;
				}
				if (std_16bit_2reg (ao, m)) {
					return 2;
				}
			}
			ao->a[2] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 shift = thumb_getshift (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15) || (shift && ((shift & 0x0000f010) != 0x00003000))) {
				return -1;
			}

			if (sufsel == B_BIT) {
				ao->o = 0x5ffa80f0;
			} else
			if (sufsel == (B_BIT | SIXTEEN_BIT)) {
				ao->o = 0x3ffa80f0;
			} else
			if (sufsel == H_BIT) {
				ao->o = 0x1ffa80f0;
			} else {
				return -1;
			}

			ao->o |= (shift & 0x00000060) << 7;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			return 4;
		        }
			break;
		default:
			return -1;

		}
	} else
	if ((m = opmask (ao->op, "wfe", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			if (m & DOTW_BIT) {
				ao->o = 0xaff30280;
				return 4;
		        } else {
				ao->o = 0x20bf;
				return 2;
		        }
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "wfi", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			if (m & DOTW_BIT) {
				ao->o = 0xaff30380;
				return 4;
		        } else {
				ao->o = 0x30bf;
				return 2;
		        }
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "yield", 0))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_NONE: {
			if (m & DOTW_BIT) {
				ao->o = 0xaff30180;
				return 4;
		        } else {
				ao->o = 0x10bf;
				return 2;
		        }
		        }
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static int findyz(int x, int *y, int *z) {
	int i, j;
	for (i = 0;i < 0xff; i++) {
		for (j = 0;j < 0xf;j++) {
			int v = i << j;
			if (v > x) {
				continue;
			}
			if (v == x) {
				*y = i;
				*z = 16 - (j / 2);
				return 1;
			}
		}
	}
	return 0;
}

static int arm_assemble(ArmOpcode *ao, ut64 off, const char *str) {
	int i, j, ret, reg, a, b;
	int coproc, opc;
	bool rex = false;
	int shift, low, high;
	for (i = 0; ops[i].name; i++) {
		if (!strncmp (ao->op, ops[i].name, strlen (ops[i].name))) {
			ao->o = ops[i].code;
			arm_opcode_cond (ao, strlen(ops[i].name));
			if (ao->a[0] || ops[i].type == TYPE_BKP) {
				switch (ops[i].type) {
				case TYPE_MEM:
					if (!strncmp (ops[i].name, "strex", 5)) {
						rex = 1;
					}
					if (!strcmp (ops[i].name, "str") || !strcmp (ops[i].name, "ldr")) {
						if (!ao->a[2]) {
							ao->a[2] = "0";
						}
					}
					getrange (ao->a[0]);
					getrange (ao->a[1]);
					getrange (ao->a[2]);
					if (ao->a[0] && ao->a[1]) {
						char rn[8];
						strncpy (rn, ao->a[1], 7);
						int r0 = getreg (ao->a[0]);
						int r1 = getreg (ao->a[1]);
						if ((r0 < 0 || r0 > 15) || (r1 > 15 || r1 < 0)) {
							return 0;
						}
						ao->o |= r0 << 20;
						if (!strcmp (ops[i].name, "strd")) {
							r1 = getreg (ao->a[2]);
							if (r1 == -1) {
								break;
							}
							ao->o |= r1 << 8;
							if (ao->a[3]) {
								char *bracket = strchr (ao->a[3], ']');
								if (bracket) {
									*bracket = '\0';
								}
								int num = getnum (ao->a[3]);
								ao->o |= (num & 0x0f) << 24;
								ao->o |= ((num >> 4) & 0x0f) << 16;
							}
							break;
						}
						if (!strcmp (ops[i].name, "strh")) {
							ao->o |= r1 << 8;
							if (ao->a[2]) {
								reg = getreg (ao->a[2]);
								if (reg != -1) {
									ao->o |= reg << 24;
								} else {
									ao->o |= 1 << 14;
									ao->o |= getnum (ao->a[2]) << 24;
								}
							} else {
								ao->o |= 1 << 14;
							}
							break;
						}
						if (rex) {
							ao->o |= r1 << 24;
						} else {
							ao->o |= r1 << 8; // delta
						}
					} else {
						return 0;
					}

					ret = getreg (ao->a[2]);
					if (ret != -1) {
						if (rex) {
							ao->o |= 1;
							ao->o |= (ret & 0x0f) << 8;
						} else {
							ao->o |= (strstr (str, "],")) ? 6 : 7;
							ao->o |= (ret & 0x0f) << 24;
						}
						if (ao->a[3]) {
							shift = getshift (ao->a[3]);
							low = shift & 0xFF;
							high = shift & 0xFF00;
							ao->o |= low << 24;
							ao->o |= high << 8;
						}
					} else {
						int num = getnum (ao->a[2]) & 0xfff;
						if (err) {
							break;
						}
						if (rex) {
							ao->o |= 1;
						} else {
							ao->o |= (strstr (str, "],")) ? 4 : 5;
						}
						ao->o |= 1;
						ao->o |= (num & 0xff) << 24;
						ao->o |= ((num >> 8) & 0xf) << 16;
					}

					break;
				case TYPE_IMM:
					if (*ao->a[0]++ == '{') {
						for (j = 0; j < 16; j++) {
							if (ao->a[j] && *ao->a[j]) {
								getrange (ao->a[j]); // XXX filter regname string
								reg = getreg (ao->a[j]);
								if (reg != -1) {
									if (reg < 8) {
										ao->o |= 1 << (24 + reg);
									} else {
										ao->o |= 1 << (8 + reg);
									}
								}
							}
						}
					} else {
						ao->o |= getnum (ao->a[0]) << 24; // ???
					}
					break;
				case TYPE_BRA:
					if ((ret = getreg (ao->a[0])) == -1) {
						// TODO: control if branch out of range
						ret = (getnum (ao->a[0]) - (int)ao->off - 8) / 4;
						if (ret >= 0x00800000 || ret < (int)0xff800000) {
							eprintf ("Branch into out of range\n");
							return 0;
						}
						ao->o |= ((ret >> 16) & 0xff) << 8;
						ao->o |= ((ret >> 8) & 0xff) << 16;
						ao->o |= ((ret)&0xff) << 24;
					} else {
						eprintf ("This branch does not accept reg as arg\n");
						return 0;
					}
					break;
				case TYPE_BKP:
					ao->o |= 0x70 << 24;
					if (ao->a[0]) {
						int n = getnum (ao->a[0]);
						ao->o |= ((n & 0xf) << 24);
						ao->o |= (((n >> 4) & 0xff) << 16);
					}
					break;
				case TYPE_BRR:
					if ((ret = getreg (ao->a[0])) == -1) {
						ut32 dst = getnum (ao->a[0]);
						dst -= (ao->off + 8);
						if (dst & 0x2) {
							ao->o = 0xfb;
						} else {
							ao->o = 0xfa;
						}
						dst /= 4;
						ao->o |= ((dst >> 16) & 0xff) << 8;
						ao->o |= ((dst >> 8) & 0xff) << 16;
						ao->o |= ((dst)&0xff) << 24;
						return 4;
					} else {
						ao->o |= (getreg (ao->a[0]) << 24);
					}
					break;
				case TYPE_HLT: {
					ut32 o = 0, n = getnum (ao->a[0]);
					o |= ((n >> 12) & 0xf) << 8;
					o |= ((n >> 8) & 0xf) << 20;
					o |= ((n >> 4) & 0xf) << 16;
					o |= ((n) & 0xf) << 24;
					ao->o |=o;
				}
				break;
			case TYPE_SWI:
				ao->o |= (getnum (ao->a[0]) & 0xff) << 24;
				ao->o |= ((getnum (ao->a[0]) >> 8) & 0xff) << 16;
				ao->o |= ((getnum (ao->a[0]) >> 16) & 0xff) << 8;
				break;
			case TYPE_UDF:
				{
					// e7f000f0 = udf 0
					// e7ffffff = udf 0xffff
					ut32 n = getnum (ao->a[0]);
					ao->o |= 0xe7;
					ao->o |= (n & 0xf) << 24;
					ao->o |= ((n >> 4) & 0xff) << 16;
					ao->o |= ((n >> 12) & 0xf) << 8;
				}
				break;
			case TYPE_ARI:
				if (!ao->a[2]) {
					ao->a[2] = ao->a[1];
					ao->a[1] = ao->a[0];
				}
				reg = getreg (ao->a[0]);
				if (reg == -1) {
					return 0;
				}
				ao->o |= reg << 20;

				reg = getreg (ao->a[1]);
				if (reg == -1) {
					return 0;
				}
				ao->o |= reg << 8;
				reg = getreg (ao->a[2]);
				if (reg == -1) {
					int imm = getnum(ao->a[2]);
					if (imm && !(imm & (imm - 1)) && imm > 255) {
						int r;
						for (r = 0; r != 32; r += 2) {
							if (!(imm & ~0xff)) {
								ao->o |= (r << 15) | (imm << 24) | 2;
								break;
							}
							imm = (imm << 2) | (imm >> 30);
						}
					} else {
						ao->o |= (imm << 24) | 2;
					}
				} else {
					ao->o |= reg << 24;
				}
				if (ao->a[3]) {
					ao->o |= getshift(ao->a[3]);
				}
				break;
			case TYPE_SWP:
				{
				int a1 = getreg (ao->a[1]);
				if (a1) {
					ao->o = 0xe1;
					ao->o |= (getreg (ao->a[0]) << 4) << 16;
					ao->o |= (0x90 + a1) << 24;
					if (ao->a[2]) {
						ao->o |= (getreg (ao->a[2] + 1)) << 8;
					} else {
						return 0;
					}
				}
				if (0xff == ((ao->o >> 16) & 0xff)) {
					return 0;
				}
				}
				break;
			case TYPE_MOV:
				if (!strcmpnull (ao->op, "movs")) {
					ao->o = 0xb0e1;
				}
				ao->o |= getreg (ao->a[0]) << 20;
				ret = getreg (ao->a[1]);
				if (ret != -1) {
					ao->o |= ret << 24;
				} else {
					int immed = getimmed8 (ao->a[1]);
					if (err) {
						return 0;
					}
					ao->o |= 0xa003 | (immed & 0xff) << 24 | (immed >> 8) << 16;
				}
				break;
			case TYPE_MOVW:
				reg = getreg (ao->a[0]);
				if (reg == -1) {
					return 0;
				}
				ao->o |= getreg (ao->a[0]) << 20;
				ret = getnum (ao->a[1]);

				ao->o |= 0x3 | ret << 24;
				ao->o |= (ret & 0xf000) >> 4;
				ao->o |= (ret & 0xf00) << 8;
				break;
			case TYPE_MOVT:
				ao->o |= getreg (ao->a[0]) << 20;
				ret = getnum (ao->a[1]);

				ao->o |= 0x4003 | ret << 24;
				ao->o |= (ret & 0xf000) >> 4;
				ao->o |= (ret & 0xf00) << 8;
				break;
			case TYPE_MUL:
				if (!strcmpnull (ao->op, "mul")) {
					ret = getreg (ao->a[0]);
					a = getreg (ao->a[1]);
					b = getreg (ao->a[2]);
					if (b == -1) {
						b = a;
						a = ret;
					}
					if (ret == -1 || a == -1) {
						return 0;
					}
					ao->o |= ret << 8;
					ao->o |= a << 24;
					ao->o |= b << 16;
				} else {
					low = getreg (ao->a[0]);
					high = getreg (ao->a[1]);
					a = getreg (ao->a[2]);
					b = getreg (ao->a[3]);
					if (low == -1 || high == -1 || a == -1 || b == -1) {
						return 0;
					}
					if (!strcmpnull (ao->op, "smlal")) {
						ao->o |= low << 20;
						ao->o |= high << 8;
						ao->o |= a << 24;
						ao->o |= b << 16;
					} else if (!strncmp (ao->op, "smla", 4)) {
						if (low > 14 || high > 14 || a > 14) {
							return 0;
						}
						ao->o |= low << 8;
						ao->o |= high << 24;
						ao->o |= a << 16;
						ao->o |= b << 20;
						break;
					} else {
						ao->o |= low << 20;
						ao->o |= high << 8;
						ao->o |= a << 24;
						ao->o |= b << 16;
					}
				}
				break;
			case TYPE_TST:
				a = getreg (ao->a[0]);
				b = getreg (ao->a[1]);
				if (b == -1) {
					int y, z;
					b = getnum (ao->a[1]);
					if (b >= 0 && b <= 0xff) {
						ao->o = 0x50e3;
						// TODO: if (b>255) -> automatic multiplier
						ao->o |= (a << 8);
						ao->o |= ((b & 0xff) << 24);
					} else
					if (findyz (b, &y, &z)) {
						ao->o = 0x50e3;
						ao->o |= (y << 24);
						ao->o |= (z << 16);
					} else {
						eprintf ("Parameter %d out0x3000a0e1 of range (0-255)\n", (int)b);
						return 0;
					}
				} else {
					ao->o |= (a << 8);
					ao->o |= (b << 24);
					if (ao->a[2]) {
						ao->o |= getshift (ao->a[2]);
					}
				}
				if (ao->a[2]) {
					int n = getnum (ao->a[2]);
					if (n & 1) {
						eprintf ("Invalid multiplier\n");
						return 0;
					}
					ao->o |= (n >> 1) << 16;
				}
				break;
			case TYPE_SHFT:
				reg = getreg (ao->a[2]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 16;

				reg = getreg (ao->a[0]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 20;

				reg = getreg (ao->a[1]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 24;
				break;
			case TYPE_REV:
				reg = getreg (ao->a[0]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 20;

				reg = getreg (ao->a[1]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 24;

				break;
			case TYPE_ENDIAN:
				if (!strcmp (ao->a[0], "le")) {
					ao->o |= 0;
				} else if (!strcmp (ao->a[0], "be")) {
					ao->o |= 0x20000;
				} else {
					return 0;
				}
				break;
			case TYPE_COPROC:
				//printf ("%s %s %s %s %s\n", ao->a[0], ao->a[1], ao->a[2], ao->a[3], ao->a[4] );
				if (ao->a[0]) {
					coproc = getnum (ao->a[0] + 1);
					if (coproc == -1 || coproc > 9) {
						return 0;
					}
					ao->o |= coproc << 16;
				}

				opc = getnum (ao->a[1]);
				if (opc == -1 || opc > 7) {
					return 0;
				}
				ao->o |= opc << 13;

				reg = getreg (ao->a[2]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 20;

				// coproc register 1
				const char *a3 = ao->a[3];
				if (a3) {
					coproc = getnum (a3 + 1);
					if (coproc == -1 || coproc > 15) {
						return 0;
					}
					ao->o |= coproc << 8;
				}

				const char *a4 = ao->a[4];
				if (a4) {
					coproc = getnum (ao->a[4] + 1);
					if (coproc == -1 || coproc > 15) {
						return 0;
					}
					ao->o |= coproc << 24;
				}

				coproc = getnum (ao->a[5]);
				if (coproc > -1) {
					if (coproc > 7) {
						return 0;
					}
					// optional opcode
					ao->o |= coproc << 29;
				}

				break;
			case TYPE_CLZ:
				ao->o |= 1 << 28;

				reg = getreg (ao->a[0]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 20;

				reg = getreg (ao->a[1]);
				if (reg == -1 || reg > 14) {
					return 0;
				}
				ao->o |= reg << 24;

				break;
			case TYPE_NEG:
				if (!ao->a[0] || !ao->a[1]) {
					return 0;
				}
				ao->a[2] = "0";
				int len = strlen (ao->a[1]) + 1;
				memmove (ao->a[0] + 1, ao->a[0], ao->a[1] - ao->a[0] + len);
				ao->a[0]++;
				ao->a[1]++;
				strncpy (ao->op, "rsbs", 5);
				arm_assemble (ao, off, str); // rsbs reg0, reg1, #0
				break;
			}
			}
			return 1;
		}
	}
	return 0;
}

typedef int (*AssembleFunction)(ArmOpcode *, ut64, const char *);
static AssembleFunction assemble[2] = { &arm_assemble, &thumb_assemble };

ut32 armass_assemble(const char *str, ut64 off, int thumb) {
	int i, j;
	char buf[128];
	ArmOpcode aop = {.off = off};
	for (i = j = 0; i < sizeof (buf) - 1 && str[j]; i++, j++) {
		if (str[j] == '#') {
			i--; continue;
		}
		buf[i] = tolower ((const ut8)str[j]);
	}
	buf[i] = 0;
	arm_opcode_parse (&aop, buf);
	aop.off = off;
	if (thumb < 0 || thumb > 1) {
		return -1;
	}
	if (assemble[thumb] (&aop, off, buf) <= 0) {
		//eprintf ("armass: Unknown opcode (%s)\n", buf);
		return -1;
	}
	return aop.o;
}

#ifdef MAIN
void thisplay(const char *str) {
	char cmd[32];
	int op = armass_assemble (str, 0x1000, 1);
	printf ("[%04x] %s\n", op, str);
	snprintf (cmd, sizeof(cmd), "rasm2 -d -b 16 -a arm %04x", op);
	system (cmd);
}

void display(const char *str) {
	char cmd[32];
	int op = armass_assemble (str, 0x1000, 0);
	printf ("[%08x] %s\n", op, str);
	snprintf (cmd, sizeof(cmd), "rasm2 -d -a arm %08x", op);
	system (cmd);
}

int main() {
	thisplay ("ldmia r1!, {r3, r4, r5}");
	thisplay ("stmia r1!, {r3, r4, r5}");
	thisplay ("bkpt 12");
return 0;
	thisplay("sub r1, r2, 0");
	thisplay("sub r1, r2, 4");
	thisplay("sub r1, r2, 5");
	thisplay("sub r1, r2, 7");
	thisplay("sub r3, 44");
return 0;
#if 0
	thisplay("mov r0, 11");
	thisplay("mov r0, r2");
	thisplay("mov r1, r4");
	thisplay("cmp r1, r2");
	thisplay("cmp r3, 44");
	thisplay("nop");
	thisplay("svc 15");
	thisplay("add r1, r2");
	thisplay("add r3, 44");
	thisplay("sub r1, r2, 3");
	thisplay("sub r3, 44");
	thisplay("tst r3,r4");
	thisplay("bx r3");
	thisplay("b 33");
	thisplay("b 0");
	thisplay("bne 44");
	thisplay("and r2,r3");
#endif
	// INVALID thisplay("ldr r1, [pc, r2]");
	// INVALID thisplay("ldr r1, [sp, r2]");
#if 0
	thisplay("ldr r1, [pc, 12]");
	thisplay("ldr r1, [sp, 24]");
	thisplay("ldr r1, [r2, r3]");
#endif
	// INVALID thisplay("str r1, [pc, 22]");
	// INVALID thisplay("str r1, [pc, r2]");
	// INVALID thisplay("str r1, [sp, r2]");
#if 0
   0:   8991            ldrh    r1, [r2, #12]
   2:   7b11            ldrb    r1, [r2, #12]
   4:   8191            strh    r1, [r2, #12]
   6:   7311            strb    r1, [r2, #12]
#endif
	thisplay("ldrh r1, [r2, 8]"); // aligned to 4
	thisplay("ldrh r1, [r3, 8]"); // aligned to 4
	thisplay("ldrh r1, [r4, 16]"); // aligned to 4
	thisplay("ldrh r1, [r2, 32]"); // aligned to 4
	thisplay("ldrb r1, [r2, 20]"); // aligned to 4
	thisplay("strh r1, [r2, 20]"); // aligned to 4
	thisplay("strb r1, [r2, 20]"); // aligned to 4
	thisplay("str r1, [sp, 20]"); // aligned to 4
	thisplay("str r1, [r2, 12]"); // OK
	thisplay("str r1, [r2, r3]");
return 0;
#if 0
	display("mov r0, 33");
	display("mov r1, 33");
	display("movne r0, 33");
	display("tst r0, r1, lsl #2");
	display("svc 0x80");
	display("sub r3, r1, r2");
	display("add r0, r1, r2");
	display("mov fp, 0");
	display("pop {pc}");
	display("pop {r3}");
	display("bx r1");
	display("bx r3");
	display("bx pc");
	display("blx fp");
	display("pop {pc}");
	display("add lr, pc, lr");
	display("adds r3, #8");
	display("adds r3, r2, #8");
	display("subs r2, #1");
	display("cmp r0, r4");
	display("cmp r7, pc");
	display("cmp r1, r3");
	display("mov pc, 44");
	display("mov pc, r3");
	display("push {pc}");
	display("pop {pc}");
	display("nop");
	display("ldr r1, [r2, 33]");
	display("ldr r1, [r2, r3]");
	display("ldr r3, [r4, r6]");
	display("str r1, [pc, 33]");
	display("str r1, [pc], 2");
	display("str r1, [pc, 3]");
	display("str r1, [pc, r4]");
	display("bx r3");
	display("bcc 33");
	display("blx r3");
	display("bne 0x1200");
	display("str r0, [r1]");
	display("push {fp,lr}");
	display("pop {fp,lr}");
	display("pop {pc}");
#endif

   //10ab4:       00047e30        andeq   r7, r4, r0, lsr lr
   //10ab8:       00036e70        andeq   r6, r3, r0, ror lr

	display("andeq r7, r4, r0, lsr lr");
	display("andeq r6, r3, r0, ror lr");
//  c4:   e8bd80f0        pop     {r4, r5, r6, r7, pc}
	display("pop {r4,r5,r6,r7,pc}");


#if 0
	display("blx r1");
	display("blx 0x8048");
#endif

#if 0
	display("b 0x123");
	display("bl 0x123");
	display("blt 0x123"); // XXX: not supported
#endif
	return 0;
}
#endif
