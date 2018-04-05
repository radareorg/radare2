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
};

static int strcmpnull(const char *a, const char *b) {
	if (!a || !b)
		return -1;
	return strcmp (a, b);
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

	{ NULL }
};

static const ut32 M_BIT = 0x01;
static const ut32 S_BIT = 0x02;
static const ut32 C_BITS = 0x3c;
static const ut32 DOTN_BIT = 0x40;
static const ut32 DOTW_BIT = 0x80;
static const ut32 L_BIT = 0x100;
static const ut32 X_BIT = 0x200;
static const ut32 TWO_BIT = 0x400;
static const ut32 IE_BIT = 0x800;
static const ut32 ID_BIT = 0x1000;
static const ut32 DBEA_BIT = 0x2000;
static const ut32 IAFD_BIT = 0x4000;
static const ut32 T_BIT = 0x8000;
static const ut32 BYTE_BIT = 0x10000;
static const ut32 HALFWORD_BIT = 0x20000;
static const ut32 DOUBLEWORD_BIT = 0x40000;
static const ut32 W_BIT = 0x80000;

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
	ut8 i;
	r_str_case (input, false);
	
	for (i = 0; i < strlen(input); i++) {
		switch (input[i]) {
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

static ut32 opmask(char *input, char *opcode) {
	ut32 res = 0;
	ut32 i;
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	r_str_case (input, false);
	if (strlen (opcode) > strlen (input)) {
		return 0;
	}
	if (r_str_startswith (input, opcode)) {
		input += strlen (opcode);
		res |= M_BIT;

		if (*input == 's') {
			res |= S_BIT;
			input++;
		}
		if (r_str_startswith (input, "db") || r_str_startswith (input, "ea")) {
			res |= DBEA_BIT;
			input += 2;
		}
		if (r_str_startswith (input, "ia") || r_str_startswith (input, "fd")) {
			res |= IAFD_BIT;
			input += 2;
		}
		if (*input == 'b') {
			res |= BYTE_BIT;
			input++;
		} else
	        if (*input == 'h') {
			res |= HALFWORD_BIT;
			input++;
		} else
		if (*input == 'd') {
			res |= DOUBLEWORD_BIT;
			input++;
		}
		if (*input == 't') {
			res |= T_BIT;
			input++;
		}
		if (*input == 'w') {
			res |= W_BIT;
			input++;
		}
		if (*input == 's') {
			res |= S_BIT;
			input++;
		}
		if (*input == '2') {
			res |= TWO_BIT;
			input++;
		}
		for (i = 0; conds[i]; i++) {
			if (r_str_startswith (input, conds[i])) {
				res |= i << 2;
				input += strlen (conds[i]);
				break;
			}
		}
		if (!conds[i]) {
			// default is nv (no value)
			res |= 15 << 2;
		}
		if (*input == 'l') {
			res |= L_BIT;
			input++;
		}
		if (*input == 'x') {
			res |= X_BIT;
			input++;
		}
		for (i = 0; conds[i]; i++) {
			if (r_str_startswith (input, conds[i])) {
				res &= i << 2; // NB: cond should be 1f here, otherwise the op is undefined
				input+= strlen (conds[i]);
				break;
			}
		}
		if (r_str_startswith (input, "id")) {
			res |= ID_BIT;
			input += 2;
		}
		if (r_str_startswith (input, "ie")) {
			res |= IE_BIT;
			input += 2;
		}
		if (r_str_startswith (input, ".n")) {
			res |= 1 << 6;
			input += 2;
		}
		if (r_str_startswith (input, ".w")) {
			res |= 1 << 7;
			input += 2;
		}
		if (*input == 0) {
			return res;
		}
	}
	return 0;
}

static ut32 itmask(char *input, char *opcode) {
	ut32 res = 0;
	ut32 i;
	r_str_case (input, false);
	if (strlen (opcode) > strlen (input)) {
		return 0;
	}
	if (r_str_startswith (input, opcode)) {
		input += strlen (opcode);
		res |= 1; // matched
		if (strlen(input) > 3) {
			return 0;
		}
		res |= (strlen (input) & 0x3) << 4;
		for (i = 0; i < strlen(input); i++, input++ ) {
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
	val = strtol (str, &endptr, 0);
	if (str != endptr && *endptr == '\0') {
		return val;
	}
	err = true;
	return 0;
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
	} else 	if ( ((num & 0xff00ff00) == 0) && ((num & 0x00ff0000) == ((num & 0x000000ff) << 16)) ) {
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
		if (*s == '[' || *s == ']')
			memmove (s, s+1, strlen (s+1)+1);
		if (*s == '}')
			*s = 0;
		s++;
	}
	while (p && *p == ' ') p++;
	return p;
}

#if 0
static int getshift_unused (const char *s) {
	int i;
	const char *shifts[] = { "lsl", "lsr", "asr", "ror", NULL };
	for (i=0; shifts[i]; i++)
		if (!strcmpnull (s, shifts[i]))
			return i * 0x20;
	return 0;
}
#endif

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
	int i, j;
	int start, end;
	char *temp2 = malloc (strlen (input));
	char *temp = malloc (strlen (input));
	char *otemp = temp;
	while (*input != '\0') {
		for (; *input == ' '; input++);
		for (i = 0; input[i] != ',' && input[i] != '\0'; i++);
		strncpy (temp, input, i);
		temp[i] = 0;

		input += i;
		if (*input != '\0') {
			input++;
		}

		for (i = 0; temp[i] != '-' && temp[i] != '\0'; i++);
		if (i == strlen (temp)) {
			tempres = getreg (temp);
			if (tempres == -1 || tempres > 15) {
				return -1;
			}
			res |= 1 << tempres;
		} else {
			strncpy (temp2, temp, i);
			temp2[i] = 0;
			temp += i + 1;
			start = getreg (temp2);
			if (start == -1 || start > 15) {
				return -1;
			}
			end = getreg (temp);
			if (end == -1 || end > 15) {
				return -1;
			}

			for (j = start; j <= end; j++ ) {
				res |= 1 << j;
			}
		}
	}

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
	if ((strlen (input) < 2) || (*input != '[') || (input[strlen (input) - 1] != ']')) {
		return -1;
	}
	input++;
	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0;
	res = getreg (temp);
	free (temp);
	return res;
}
	
static st32 getregmemend(const char *input) {
	st32 res;
	if ((strlen (input) < 1) || (input[strlen (input) - 1] != ']')) {
		return -1;
	}

	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0;
	res = getreg (temp);
	free (temp);
	return res;
}
	
static st32 getreglist(const char *input) {
	st32 res;
	
	if ((strlen (input) < 2) || (*input != '{') || (input[strlen (input) - 1] != '}')) {
		return -1;
	}
	input++;
	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0;
	res = getlistmask (temp);
	free (temp);
	return res;
}

static st32 getnummemend (const char *input) {
	st32 res;
	err = false;
	if ((strlen(input) < 1) || (input[strlen(input) - 1] != ']')) {
		err = true;
		return 0;
	}
	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0;
	res = getnum (temp);
	free (temp);
	return res;
}

static st32 getnummemendbang (const char *input) {
	st32 res;
	err = false;
	if ((strlen (input) < 2) || (input[strlen(input) - 2] != ']' && input[strlen(input) - 1] != '!')) {
		err = true;
		return 0;
	}
	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 2);
	temp[strlen (input) - 2] = 0; 
	res = getnum (temp);
	free (temp);
	return res;
}

static st32 getregmembang(const char *input) {
	st32 res;
	if ((strlen (input) < 1) || (!(input[strlen (input) - 1] == '!'))) {
		return -1;
	}
	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0; 
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
	const char *fields[] = {"c", "x", "s", "f", 0};
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
		for (i = 0; str+5+i; i++) {
			for (j = 0; fields[j]; j++) {
				if (!(strcmp(str+5+i, fields[j]))) {
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
		
static int thumb_getreg(const char *str) {
	if (!str)
		return -1;
	if (*str == 'r')
		return atoi (str+1);
	//FIXME Note that pc is only allowed in pop; lr in push in Thumb1 mode.
	if (!strcmpnull (str, "pc") || !strcmpnull (str,"lr"))
		return 8;
	return -1;
}

static int getlist(char *op) {
	int reg, list = 0;
	char *ptr = strchr (op, '{');
	if (ptr) {
		do {
			ptr++;
			while (*ptr && *ptr == ' ') ptr++;
			reg = getreg (ptr);
			if (reg == -1)
				break;
			list |= (1 << reg);
			while (*ptr && *ptr!=',') ptr++;
		} while (*ptr && *ptr == ',');
	}
	return list;
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
	if ((strlen (input) < 1) || (input[strlen (input) - 1] != ']')) {
		return -1;
	}

	char *temp = (char*) malloc (strlen (input));
	strncpy (temp, input, strlen (input) - 1);
	temp[strlen (input) - 1] = 0;
	res = thumb_getshift (temp);
	free (temp);
	return res;
}
	
void collect_list(char *input[]) {
	if (input[0] == NULL) {
		return;
	}
	char *temp  = malloc (500);
	temp[0] = 0;
	int i;
	int conc = 0;
	int start, end = 0;
	int arrsz;
	for (arrsz = 1; input[arrsz] != NULL; arrsz++);

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
	if (!strcasecmp (type, shifts[5])) {
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
			if (!strcasecmp (type, shifts[i])) {
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
			if (shift == 6) i |= (1 << 20);
		} else {
			char *bracket = strchr (arg, ']');
			if (bracket) {
				*bracket = '\0';
			}
			// ensure only the bottom 5 bits are used
			i &= 0x1f;
			if (!i) i = 32;
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
	if (strlen (str)+1>=sizeof (ao->op))
		return;
	strncpy (ao->op, str, sizeof (ao->op)-1);
	strcpy (ao->opstr, ao->op);
	ao->a[0] = strchr (ao->op, ' ');
	for (i=0; i<15; i++) {
		if (ao->a[i]) {
			*ao->a[i] = 0;
			ao->a[i+1] = strchr (++ao->a[i], ',');
		} else break;
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

static void thumb_swap (ut32 *a) {
	ut32 a2 = *a;
	ut8 *b = (ut8 *)a;
	ut8 *b2 = (ut8 *) & a2;
	b[0] = b2[1];
	b[1] = b2[0];
	b[2] = b2[3];
	b[3] = b2[2];
}

static ut64 thumb_getoffset(char *label, ut64 cur) {
	ut64 res = r_num_math (NULL, label);
	res -= 4;
	res -= cur; // possible integer underflow
	//printf("thumb_getoffset: %s, %lld, %lld\n", label, res, cur);
	return res;
}

// TODO: group similar instructions like for non-thumb
static int thumb_assemble(ArmOpcode *ao, ut64 off, const char *str) {
	int reg, j;
	ut32 m;
	ao->o = UT32_MAX;
	if (!strcmpnull (ao->op, "pop") && ao->a[0]) {
		ao->o = 0xbc;
		if (*ao->a[0] ++== '{') {
			// XXX: inverse order?
			for (j=0; j<16; j++) {
				if (ao->a[j] && *ao->a[j]) {
					int sr, er;
					char *ers;
					getrange (ao->a[j]); // XXX filter regname string
					sr = er = thumb_getreg (ao->a[j]);
					if ((ers = strchr (ao->a[j], '-'))) { // register sequence
						er = thumb_getreg (ers+1);
					}
					for (reg = sr; reg <= er; reg++) {
						if (reg != -1) {
							if (reg < 8)
								ao->o |= 1 << (8 + reg);
							if (reg == 8) {
								ao->o |= 1;
							}
							//	else ignore...
						}
					}
				}
			}
		} else ao->o |= getnum (ao->a[0]) << 24; // ???
		return 2;
	} else
	if (!strcmpnull (ao->op, "push") && ao->a[0]) {
		ao->o = 0xb4;
		if (*ao->a[0] ++== '{') {
			for (j = 0; j < 16; j++) {
				if (ao->a[j] && *ao->a[j]) {
					getrange (ao->a[j]); // XXX filter regname string
					reg = thumb_getreg (ao->a[j]);
					if (reg != -1) {
						if (reg < 8)
							ao->o |= 1 << (8 + reg);
						if (reg == 8)
							ao->o |= 1;
					//	else ignore...
					}
				}
			}
		} else ao->o |= getnum (ao->a[0]) << 24; // ???
		return 2;
	} else
	if (!strcmpnull (ao->op, "stmia")) {
		ao->o = 0xc0 + getreg (ao->a[0]);
		ao->o |= getlist(ao->opstr) << 8;
		return 2;
	} else
#if 0
	if (!strcmpnull (ao->op, "nop")) {
		ao->o = 0xbf;
		return 2;
	} else
#endif
	if (!strcmpnull (ao->op, "yield")) {
		ao->o = 0x10bf;
		return 2;
	} else
	if (!strcmpnull (ao->op, "udf")) {
		ao->o = 0xde;
		ao->o |= getnum (ao->a[0]) << 8;
		return 2;
	} else
	if (!strcmpnull (ao->op, "wfe")) {
		ao->o = 0x20bf;
		return 2;
	} else
	if (!strcmpnull (ao->op, "wfi")) {
		ao->o = 0x30bf;
		return 2;
	} else
	if (!strcmpnull (ao->op, "sev")) {
		ao->o = 0x40bf;
		return 2;
	} else
	if (!strcmpnull (ao->op, "svc")) {
		ao->o = 0xdf;
		ao->o |= (0xff & getnum (ao->a[0])) << 8;
		return 2;
	} else
#if 0
	if (!strcmpnull (ao->op, "mov")) {
		int reg = getreg (ao->a[1]);
		if (reg != -1) {
			ao->o = 0x46;
			ao->o |= (getreg (ao->a[0]) & 0x8) << 12;
			ao->o |= (getreg (ao->a[0]) & 0x7) << 8;
			ao->o |= reg << 11;
		} else {
			ao->o = 0x20;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1]) & 0xff) << 8;
		}
		return 2;
	} else
	if (!strcmpnull (ao->op, "mov.w")) {
		ao->o = 0x4ff00000;
		int reg = getreg (ao->a[0]);
		int num = getnum (ao->a[1]);
		int top_bits = num & 0xf00;
		if (reg != -1) {
			ao->o |= reg;
			if (num < 256) {
				ao->o |= num << 8;
			} else if (num < 512) {
				if (num & 1) {
					return 0;
				}
				num = (num ^ top_bits) >> 1;
				ao->o |= 0x00048070 | num << 8;
			} else if (num < 1024) {
				if (num & 3) {
					return 0;
				}
				num = (num ^ top_bits) >> 2;
				ao->o |= 0x00040070 | num << 8;
			} else if (num < 2048) {
				if (num & 7) {
					return 0;
				}
				num = (num ^ top_bits) >> 3;
				ao->o |= 0x00048060 | num << 8;
			} else if (num == 2048) {
				ao->o = 0x4ff40060 | reg;
			} else {
				return 0;
			}
		} else {
			return 0;
		}
		return 8;
	} else
#endif
	if (!strncmp (ao->op, "str", 3)) {
		getrange (ao->a[1]);
		getrange (ao->a[2]);
		if (ao->op[3] == 'h') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 == -1) {
				a2 = getnum (ao->a[2]);
				ao->o = 0x80; // | (8+(0xf & a0));
				ao->o |= (7 & a0) << 8;
				ao->o |= (7 & a1) << 11;
				ao->o |= (7 & (a2 >> 1));
				return 2;
			}
		} else
		if (ao->op[3] == 'b') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 == -1) {
				a2 = getnum (ao->a[2]);
				ao->o = 0x70; // | (8+(0xf & a0));
				ao->o |= (7 & a0) << 8;
				ao->o |= (7 & a1) << 11;
				ao->o |= (7 & a2);
				return 2;
			}
		} else {
			if (!strcmpnull (ao->a[1], "sp")) {
				// ldr r0, [sp, n] = a[r0-7][nn]
				if (getreg (ao->a[2]) == -1) {
					int ret = getnum (ao->a[2]);
					if (ret%4) {
						eprintf ("ldr index must be aligned to 4");
						return 0;
					}
					ao->o = 0x90 + (0xf & getreg (ao->a[0]));
					ao->o |= (0xff & getnum (ao->a[2]) / 4) << 8;
					return 2;
				}
			} else
			if (!strcmpnull (ao->a[1], "pc")) {
				return 0;
			} else {
				int a0 = getreg (ao->a[0]);
				int a1 = getreg (ao->a[1]);
				int a2 = getreg (ao->a[2]);
				if (a2 == -1) {
					a2 = getnum (ao->a[2]);
					ao->o = 0x60;
					ao->o |= (7 & a0) << 8;
					ao->o |= (7 & a1) << 11;
					ao->o |= (3 & (a2 / 4)) << 14;
					ao->o |= ((28 & (a2 / 4)) / 4);
				} else {
					ao->o = 0x50;
					ao->o |= (7 & a0) << 8;
					ao->o |= (7 & a1) << 11;
					ao->o |= (3 & a2) << 14;
				}
				return 2;
			}
		}
	} else
	if (!strcmpnull (ao->op, "tst")) {
		ao->o = 0x42;
		ao->o |= (getreg (ao->a[0])) << 8;
		ao->o |= getreg (ao->a[1]) << 11;
		return 2;
	} else
#if 0
	if (!strcmpnull (ao->op, "mul") || !strcmpnull (ao->op, "mul.w")) {
		int reg0 = getreg (ao->a[0]);
		int reg1 = getreg (ao->a[1]);
		int reg2 = getreg (ao->a[2]);
		if (reg0!=-1 && reg1 != -1) {
			if (reg2 == -1) {
				reg0 = getreg (ao->a[0]);
				reg1 = getreg (ao->a[0]);
				reg2 = getreg (ao->a[1]);
			}
			ao->o = 0;
			ao->o |= 0x00 | reg1;
			ao->o <<= 8;
			ao->o |= 0xfb;
			ao->o <<= 8;
			ao->o |= 0x00 | reg2;
			ao->o <<= 8;
			ao->o |= 0xf0 | reg0;
			return 4;
		}
	} else
#endif
	if (!strcmpnull (ao->op, "add")) {
		// XXX: signed unsigned ??
		// add r, r = 44[7bits,7bits]
		// adds r, n = 3[r0-7][nn]
		int reg3 = getreg (ao->a[2]);
		if (reg3 != -1) {
			return -1;
		}
		int reg = getreg (ao->a[1]);
		if (reg != -1) {
			ao->o = 0x44;
			ao->o |= (getreg (ao->a[0])) << 8;
			ao->o |= reg << 11;
		} else {
			if (reg < 10) {
				int num = getnum (ao->a[1]);
				if (err) {
					return 0;
				}
				if (getreg (ao->a[0]) == 13 &&
				    (!(num & 0xb) || !(num & 0x7))) {
					ao->o = 0x04b0;
					ao->o |= num << 6;
					return 2;
				}
				if (num > 0xff) {
					if (num % 2) {
						return 0;
					}
					ao->o = 0x00f58070;
					ao->o |= (num >> 8) << 16;
					ao->o |= (num & 0xff) << 7;
				} else {
					ao->o = 0x00f10000;
					ao->o |= num << 8;
				}
				ao->o |= getreg (ao->a[0]) << 24;
				ao->o |= getreg (ao->a[0]);
			}
			/*ao->o = 0x30;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1]) & 0xff) << 8;*/
		}
		return 2;
	} else
	if ((m = opmask (ao->op, "adc"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
			// a bit naughty, perhaps?
		case THUMB_REG_REG_CONST: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ao->o = 0x40f10000;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= getreg (ao->a[1]) << 24;
			ao->o |= getthimmed12(ao->a[2]);
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ( (reg1 < 8) && (reg2 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x4041;
				ao->o |= (reg1 << 8);
				ao->o |= (reg2 << 11);
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
			// a bit naughty, perhaps?
		case THUMB_REG_REG_REG: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ao->o = 0x40eb0000;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getreg (ao->a[1])) << 24;
			ao->o |= (getreg (ao->a[2])) << 8;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			ao->a[3] = ao->a[2];
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
			// a bit naughty, perhaps?
		case THUMB_REG_REG_REG_SHIFT: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ao->o = 0x40eb0000;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getreg (ao->a[1])) << 24;
			ao->o |= (getreg (ao->a[2])) << 8;
			ao->o |= thumb_getshift (ao->a[3]);
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
	if ((m = opmask (ao->op, "adr"))) {
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
	if ((m = opmask (ao->op, "and"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if (( !(m & DOTW_BIT)) && (reg1 < 8) && (reg2 < 8)) {
				ao->o = 0x0040;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ao->o = 0x00ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_CONST: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 imm = getthimmed12(ao->a[2]);
			ao->o = 0x00f00000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= imm;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			ao->a[3] = ao->a[2];
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);
			ao->o = 0x00ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "asr"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 imm = getnum (ao->a[2]);
			if (((int)imm < 1) && ((int)imm > 32)) {
				return -1;
			}
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x0010;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				ao->o |= (imm & 0x3) << 14;
				ao->o |= (imm & 0x1c) >> 2;
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
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x0041;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ao->o = 0x40fa00f0;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if (( m = opmask (ao->op, "b") )) {
		ut64 argt = thumb_selector (ao->a);
		switch ( ((L_BIT | X_BIT) & m)) {
		case THUMB_LXSUFFIX: {
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
		        }
			break;
		case THUMB_XSUFFIX: {
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
		        }
			break;
		case THUMB_LSUFFIX: {
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
		        }
		case THUMB_NOSUFFIX: {
			if (!(argt == 0x2)) {
				return -1;
			}
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
			// should never get here
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bfc") )) {
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
	if (( m = opmask (ao->op, "bfi") )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST_CONST: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 lsb = getnum (ao->a[2]);
			ut32 width = getnum (ao->a[3]);
			ut32 msb = lsb + width - 1;
			if ((lsb > 31) || (msb > 31)) {
				return -1;
			}
			ao->o = 0x60f30000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
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
	if (( m = opmask (ao->op, "bic") )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x8043;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2]=ao->a[1];
			ao->a[1]=ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ao->o = 0x20ea0000;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			return 4;
		        }
			break;
		case THUMB_REG_CONST: {
			ao->a[2]=ao->a[1];
			ao->a[1]=ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ao->o = 0x20f00000;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= getthimmed12 (ao->a[2]);
			return 4;
		        }
			break;
		case THUMB_REG_REG_SHIFT: {
			ao->a[3]=ao->a[2];
			ao->a[2]=ao->a[1];
			ao->a[1]=ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ao->o = 0x20ea0000;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= thumb_getshift (ao->a[3]);
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "bkpt") )) {
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
	if (( m = opmask (ao->op, "cbnz") )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 offset = thumb_getoffset (ao->a[1], off);
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
	if (( m = opmask (ao->op, "cbz") )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut32 offset = thumb_getoffset (ao->a[1], off);
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
	if (( m = opmask (ao->op, "cdp") )) {
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
	if (( m = opmask (ao->op, "clrex") )) {
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
	if (( m = opmask (ao->op, "clz") )) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ao->o = 0xb0fa80f0;
			ao->o |= reg1;
			ao->o |= reg2 << 8;
			ao->o |= reg2 << 24;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (( m = opmask (ao->op, "cmn") )) {
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
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0xc042;
				ao->o |= reg1 << 8;
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
			ao->o = 0x10eb000f;
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
	if (( m = opmask (ao->op, "cmp") )) {
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
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x8042;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
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
	if (( m = opmask (ao->op, "cps") )) {
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
	if ((m = opmask (ao->op, "dbg"))) {
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
	if ((m = opmask (ao->op, "dmb"))) {
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
	if ((m = opmask (ao->op, "dsb"))) {
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
	if ((m = opmask (ao->op, "eor"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST:
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			st8 reg1 = getreg (ao->a[0]);
			st8 reg2 = getreg (ao->a[1]);
			ut32 imm = getthimmed12 (ao->a[2]);
			if (err || (reg1 == -1) || (reg2 == -1)) {
				return -1;
			}
			ao->o = 0x80f00000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= imm;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			st8 reg1 = getreg (ao->a[0]);
			st8 reg2 = getreg (ao->a[1]);
			if ((reg1 == -1) || (reg2 == -1)) {
				return -1;
			}
			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x4040;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG:
			ao->a[3] = "lsl 0";
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			st8 reg1 = getreg (ao->a[0]);
			st8 reg2 = getreg (ao->a[1]);
			st8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);
			if ((reg1 == -1) || (reg2 == -1) || (reg3 == -1) || err) {
				return -1;
			}
			ao->o = 0x80ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "isb"))) {
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
	if ((m = itmask (ao->op, "it"))) {
		// NB: This doesn't actually do anything: We still can't properly interpret the following instructions
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_OTHER: {
			ut16 cond;
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
			
			for (i = 0; i < ((m & 0x30) >> 4); i++) {
				ao->o |= ((cond & 0x1) ^ ((m & (0x1 << (3 - i))) >> (3 -i))) << (11 - i);
			}
			ao->o |= 1 << (11 - i);
			return 2;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "ldc"))) {
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
	if ((m = opmask (ao->op, "ldm"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REGBANG_LIST: {
			ut8 reg1 = getregmembang (ao->a[0]);
			ut32 list = getreglist (ao->a[1]);
			if (!(m & DBEA_BIT) && !(list & 0xff00) && (reg1 < 8) && !(m & DOTW_BIT)) {
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
			if (m & DBEA_BIT) {
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
			if (!(m & DBEA_BIT) && !(list & 0xff00) && (reg1 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x00c8;
				ao->o |= reg1;
				ao->o |= 1 << (reg1 + 8);
				ao->o |= (list & 0xff) << 8;
				return 2;
			}
			if (list & 0x2000) {
				return -1;
			}
			
			if (m & DBEA_BIT) {
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
	if ((m = opmask (ao->op, "ldr"))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 ldrsel = m & (BYTE_BIT | HALFWORD_BIT | DOUBLEWORD_BIT);
		if ((m & S_BIT) && !(m & (BYTE_BIT | HALFWORD_BIT))) {
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
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= num << 8;
					return 4;
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
				if ((reg1 < 8) && (reg2 < 8) && (num >= 0) && (num < 128) && (num % 4 == 0) && (!(m & DOTW_BIT))) {
					ao->o = 0x0068;
					ao->o |= (num >> 4);
					ao->o |= reg1 << 8;
					ao->o |= reg2 << 11;
					ao->o |= ((num >> 2) & 0x3) << 14;
					return 2;
				}
				if ((num > 4095) || (num < -1023)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0xd0f80000;
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return 4;
				}
				ao->o = 0x50f8000c;
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				ao->o |= (-num & 0xff) << 8;
				return 4;
			} else
			if (ldrsel == BYTE_BIT) {
				if (m & T_BIT) {
					if ((num < 0) || (num > 255)) {
						return -1;
					}
					ao->o = 0x10f8000e;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= num << 8;
					return 4;
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
				if ((reg1 < 8) && (reg2 < 8) && (num >= 0) && (num < 32) && (!(m & DOTW_BIT)) && (!(m & S_BIT))) {
					ao->o = 0x0078;
					ao->o |= (num >> 2);
					ao->o |= reg1 << 8;
					ao->o |= reg2 << 11;
					ao->o |= (num & 0x3) << 14;
					return 2;
				}
				if ((num > 4095) || (num < -255)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0x90f80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return 4;
				}
				ao->o = 0x10f8000c;
				if (m & S_BIT) {
					ao->o |= 1 << 16;
				}
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				ao->o |= -num << 8;
				return 4;
			} else
			if (ldrsel == HALFWORD_BIT) {
				if (m & T_BIT) {
					if ((num < 0) || (num > 255)) {
						return -1;
					}
					ao->o = 0x30f8000e;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= num << 8;
					return 4;
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
				if ((reg1 < 8) && (reg2 < 8) && (num >= 0) && (num < 64) && (num % 2 == 0) && (!(m & DOTW_BIT)) && (!(m & S_BIT))) {
					ao->o = 0x0088;
					ao->o |= (num >> 3);
					ao->o |= reg1 << 8;
					ao->o |= reg2 << 11;
					ao->o |= ((num >> 1) & 0x3) << 14;
					return 2;
				}
				if ((num > 4095) || (num < -255)) {
					return -1;
				}
				if (num >= 0) {
					ao->o = 0xb0f80000;
					if (m & S_BIT) {
						ao->o |= 1 << 16;
					}
					ao->o |= reg1 << 4;
					ao->o |= reg2 << 24;
					ao->o |= (num & 0xff) << 8;
					ao->o |= (num & 0xf00) >> 8;
					return 4;
				}
				ao->o = 0x30f8000c;
				if (m & S_BIT) {
					ao->o |= 1 << 16;
				}
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				ao->o |= -num << 8;
				return 4;
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
			if (ldrsel == BYTE_BIT) {
				ao->o = 0x10f80009;
			} else 
			if (ldrsel == HALFWORD_BIT) {
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
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= num << 8;
			return 4;
		        }
			break;
		case THUMB_REG_BRACKREG_CONSTBRACKBANG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			st32 num = getnummemendbang (ao->a[2]);
			if ((num < -255) || (num > 255)) {
				return -1;
			}
			if (ldrsel == 0) {
				ao->o = 0x50f8000d;
			} else 
			if (ldrsel == BYTE_BIT) {
				ao->o = 0x10f8000d;
			} else 
			if (ldrsel == HALFWORD_BIT) {
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
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= num << 8;
			return 4;
		        }
			break;
		case THUMB_REG_BRACKREG_REGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			ut8 reg3 = getregmemend (ao->a[2]);
			if ((reg1 < 8) && (reg2 < 8) && (reg3 < 8) & (!(m & DOTW_BIT))) {
				if (ldrsel == 0) {
					ao->o = 0x0058;
				} else
				if (ldrsel == BYTE_BIT) {
					if (m & S_BIT) {
						ao->o = 0x0056;
					} else {
						ao->o = 0x005c;
					}
				} else
				if (ldrsel == HALFWORD_BIT) {
					if (m & S_BIT) {
						ao->o = 0x005e;
					} else {
						ao->o = 0x005a;
					}
				} else
				{
					return -1;
				}
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				ao->o |= (reg3 & 0x3) << 14;
				ao->o |= (reg3 & 0x4) >> 2;
				return 2;
			}
			ao->a[2][strlen (ao->a[2]) -1] = '\0';
			ao->a[3] = "lsl 0]";
		        }
			// intentional fallthrough
		case THUMB_REG_BRACKREG_REG_SHIFTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = getshiftmemend (ao->a[3]);

			shift >>= 2;
			if (shift & 0xffffcfff) {
				return -1;
			}

			if (ldrsel == 0) {
				ao->o = 0x50f80000;
			} else
			if (ldrsel == BYTE_BIT) {
				ao->o = 0x10f80000;
			} else
			if (ldrsel == HALFWORD_BIT) {
				ao->o = 0x30f80000;
			} else
			{
				return -1;
			}
			if (m & S_BIT) {
				ao->o |= 1 << 16;
			}
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= shift;
			return 4;
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

			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != DOUBLEWORD_BIT)) {
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
			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != DOUBLEWORD_BIT)) {
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
			if ((num > 1020) || (num < -1020) || (num % 4 != 0) || (ldrsel != DOUBLEWORD_BIT)) {
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
	if ((m = opmask (ao->op, "ldrex"))) {
		ut64 argt = thumb_selector (ao->a);
		ut32 ldrsel = m & (BYTE_BIT | HALFWORD_BIT | DOUBLEWORD_BIT);
		switch (argt) {
		case THUMB_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstartend (ao->a[1]);
			if (ldrsel == BYTE_BIT) {
				ao->o = 0xd0e84f0f;
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				return 4;
			} else
			if (ldrsel == HALFWORD_BIT) {
				ao->o = 0xd0e85f0f;
				ao->o |= reg1 << 4;
				ao->o |= reg2 << 24;
				return 4;
			} else
			if (ldrsel == 0) {
				ao->a[1][strlen (ao->a[1]) - 1] = '\0';
				ao->a[2] = "0]";
			} else 
				return -1;
		        }
			// intentional fallthrough
		case THUMB_REG_BRACKREG_CONSTBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getregmemstart (ao->a[1]);
			st32 num = getnummemend (ao->a[2]);
			if ((ldrsel != 0) || (num < 0) || (num > 1020) || (num % 4 != 0)) {
				return -1;
			}
			ao->o = 0x50e8000f;
			ao->o |= reg1 << 4;
			ao->o |= reg2 << 24;
			ao->o |= (num >> 2) << 8;
			return 4;
		        }
			break;
		case THUMB_REG_REG_BRACKREGBRACK: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getregmemstartend (ao->a[2]);
			if (!(ldrsel && DOUBLEWORD_BIT)) {
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
	if ((m = opmask (ao->op, "lsl"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);
			if (num > 32) {
				return -1;
			}
			if ( (reg1 < 8) && (reg2 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x0000;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
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
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ( (reg1 < 8) && (reg2 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x8040;
				ao->o |= (reg1 << 8);
				ao->o |= (reg2 << 11);
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ao->o = 0x00fa00f0;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "lsr"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut32 num = getnum (ao->a[2]);
			if (num > 32) {
				return -1;
			}
			if ( (reg1 < 8) && (reg2 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0x0008;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
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
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			if ( (reg1 < 8) && (reg2 < 8) && !(m & DOTW_BIT)) {
				ao->o = 0xc040;
				ao->o |= (reg1 << 8);
				ao->o |= (reg2 << 11);
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			if (m & DOTN_BIT) {
				// this is explicitly an error
				return -1;
			}
			ao->o = 0x20fa00f0;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "mcr"))) {
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

			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}

			if ((coproc > 15) || (opc1 > 7) || (reg1 > 15) || (coreg1 > 15) || (coreg2 > 15) || (opc2 > 7)) {
				return -1;
			}

			ao->o = 0x00ee1000;
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
	if ((m = opmask (ao->op, "mcrr"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_REG_REG_COREG: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 reg2 = getreg (ao->a[3]);
			ut32 coreg = getcoprocreg (ao->a[4]);

			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}

			if ((coproc > 15) || (opc > 15) || (reg1 > 15) || (reg2 > 15) || (coreg > 15)) {
				return -1;
			}

			ao->o = 0x40ec0000;
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
	if ((m = opmask (ao->op, "mla"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut32 reg1 = getreg (ao->a[0]);
			ut32 reg2 = getreg (ao->a[1]);
			ut32 reg3 = getreg (ao->a[2]);
			ut32 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}

			ao->o = 0x00fb0000;

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
	if ((m = opmask (ao->op, "mls"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG_REG: {
			ut32 reg1 = getreg (ao->a[0]);
			ut32 reg2 = getreg (ao->a[1]);
			ut32 reg3 = getreg (ao->a[2]);
			ut32 reg4 = getreg (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || (reg4 > 15)) {
				return -1;
			}

			ao->o = 0x00fb1000;

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
	if ((m = opmask (ao->op, "mov"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ut32 reg1 = getreg (ao->a[0]);
			err = false;
			ut32 num = getthimmed12 (ao->a[1]);

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
			
			if ((num < 256) && (reg1 < 8)) {
				ao->o = 0x0020;
				ao->o |= reg1;
				ao->o |= num;
				return 2;
			}
				
			ao->o = 0x4ff00000;
			ao->o |= reg1;
			ao->o |= num;
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
			
			if ((reg1 < 8) && (reg2 < 8)) {
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
	if ((m = opmask (ao->op, "mrc"))) {
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

			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}

			if ((coproc > 15) || (opc1 > 7) || (reg1 > 15) || (coreg1 > 15) || (coreg2 > 15) || (opc2 > 7)) {
				return -1;
			}

			ao->o = 0x10ee1000;
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
	if ((m = opmask (ao->op, "mrrc"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_COPROC_CONST_REG_REG_COREG: {
			ut32 coproc = getcoproc (ao->a[0]);
			ut32 opc = getnum (ao->a[1]);
			ut32 reg1 = getreg (ao->a[2]);
			ut32 reg2 = getreg (ao->a[3]);
			ut32 coreg = getcoprocreg (ao->a[4]);

			if (m & TWO_BIT) {
				ao->o |= 1 << 20;
			}

			if ((coproc > 15) || (opc > 15) || (reg1 > 15) || (reg2 > 15) || (coreg > 15)) {
				return -1;
			}

			ao->o = 0x50ec0000;
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
	if ((m = opmask (ao->op, "mrs"))) {
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
	if ((m = opmask (ao->op, "msr"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_OTHER: {
			ut32 reg1 = getreg (ao->a[0]);
			r_str_case (ao->a[1], false);
			ut8 spsr = 0;
			ut8 bank = interpret_msrbank (ao->a[1], &spsr);

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
	if ((m = opmask (ao->op, "mul"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15)) {
				return -1;
			}
			
			if (!(m & DOTW_BIT) && (reg1 < 8) && (reg2 < 8) && (reg1 == reg3)) {
				ao->o = 0x4043;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}

			if (m & S_BIT) {
				// mul oddly does not support this
				return -1;
			}

			ao->o = 0x00fb00f0;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "mvn"))) {
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
			
			if ((reg1 < 8) && (reg2 < 8) && (shift == 0)) {
				ao->o = 0xc043;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}

			ao->o = 0x6fea0000;
			ao->o |= reg1;
			ao->o |= reg2;
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
	if ((m = opmask (ao->op, "nop"))) {
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
	if ((m = opmask (ao->op, "orn"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15) || err) {
				return -1;
			}

			ao->o = 0x60f00000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= num;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				ao->a[3] = ao->a[2];
				ao->a[2] = ao->a[1];
				ao->a[1] = ao->a[0];
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

			ao->o = 0x60ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "orr"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_CONST: {
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_CONST: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			err = false;
			ut32 num = getthimmed12 (ao->a[2]);

			if ((reg1 > 15) || (reg2 > 15) || err) {
				return -1;
			}

			ao->o = 0x40f00000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= num;
			if (m & S_BIT) {
				ao->o |= 1 << 28;
			}
			return 4;
		        }
			break;
		case THUMB_REG_REG: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);

			if ((reg1 < 8) && (reg2 < 8) && (!(m & DOTW_BIT))) {
				ao->o = 0x0043;
				ao->o |= reg1 << 8;
				ao->o |= reg2 << 11;
				return 2;
			}
			ao->a[2] = ao->a[1];
			ao->a[1] = ao->a[0];
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG: {
			ao->a[3] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_SHIFT: {
			if (ao->a[3] == NULL) { // double fallthrough
				ao->a[3] = ao->a[2];
				ao->a[2] = ao->a[1];
				ao->a[1] = ao->a[0];
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

			ao->o = 0x40ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
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
	if ((m = opmask (ao->op, "pkhtb"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG: {
			ao->a[4] = "asr 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || ((shift & 0x00003000) != 0x00002000)) {
				return -1;
			}

			ao->o = 0xc0ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if ((m = opmask (ao->op, "pkhbt"))) {
		ut64 argt = thumb_selector (ao->a);
		switch (argt) {
		case THUMB_REG_REG_REG: {
			ao->a[4] = "lsl 0";
		        }
			// intentional fallthrough
		case THUMB_REG_REG_REG_SHIFT: {
			ut8 reg1 = getreg (ao->a[0]);
			ut8 reg2 = getreg (ao->a[1]);
			ut8 reg3 = getreg (ao->a[2]);
			ut32 shift = thumb_getshift (ao->a[3]);

			if ((reg1 > 15) || (reg2 > 15) || (reg3 > 15) || ((shift & 0x00003000) != 0)) {
				return -1;
			}

			ao->o = 0xc0ea0000;
			ao->o |= reg1;
			ao->o |= reg2 << 24;
			ao->o |= reg3 << 8;
			ao->o |= shift;
			return 4;
		        }
			break;
		default:
			return -1;
		}
	} else
	if (!strcmpnull (ao->op, "sub")) {
		int reg = getreg (ao->a[1]);
		if (reg != -1) {
			int n = getnum (ao->a[2]); // TODO: add limit
			ao->o = 0x1e;
			ao->o |= (getreg (ao->a[0])) << 8;
			ao->o |= reg << 11;
			ao->o |= n / 4 | ((n % 4) << 14);
		} else {
			if (reg < 10) {
				int num = getnum (ao->a[1]);
				if (err) {
					return 0;
				}
				if (getreg (ao->a[0]) == 13 &&
				    (!(num & 0xb) || !(num & 0x7))) {
					ao->o = 0x80b0;
					ao->o |= num << 6;
					return 2;
				}
				if (num > 0xff) {
					if (num % 2) {
						return 0;
					}
					ao->o = 0xa0f58070;
					ao->o |= (num >> 8) << 16;
					ao->o |= (num & 0xff) << 7;
				} else {
					ao->o = 0xa0f10000;
					ao->o |= num << 8;
				}
				ao->o |= getreg (ao->a[0]) << 24;
				ao->o |= getreg (ao->a[0]);
			}
			/*ao->o = 0x30;
			ao->o |= 8 + (getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1]) & 0xff) << 8;*/
		}
		return 2;
	}
	return 0;
}

static int findyz(int x, int *y, int *z) {
	int i, j;
	for (i = 0;i < 0xff; i++) {
		for (j = 0;j < 0xf;j++) {
			int v = i << j;
			if (v > x) continue;
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
			if (ao->a[0] || ops[i].type == TYPE_BKP)
			switch (ops[i].type) {
			case TYPE_MEM:
				if (!strncmp (ops[i].name, "strex", 5)) {
					rex = 1;
				}
				getrange (ao->a[0]);
				getrange (ao->a[1]);
				getrange (ao->a[2]);
				if (ao->a[0] && ao->a[1]) {
					char rn[8];
					strncpy (rn, ao->a[1], 7);
					int r0 = getreg (ao->a[0]);
					int r1 = getreg (ao->a[1]);
					if ( (r0 < 0 || r0 > 15) || (r1 > 15 || r1 < 0) ) {
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
						ao->o |=  r1 << 8;
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
						ao->o |=  r1 << 24;
					} else {
						ao->o |=  r1 << 8; // delta
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
						ao->o |= (strstr (str,"],")) ? 6 : 7;
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
				if (*ao->a[0] ++== '{') {
					for (j = 0; j < 16; j++) {
						if (ao->a[j] && *ao->a[j]) {
							getrange (ao->a[j]); // XXX filter regname string
							reg = getreg (ao->a[j]);
							if (reg != -1) {
								if (reg < 8)
									ao->o |= 1 << (24 + reg);
								else
									ao->o |= 1 << (8 + reg);
							}
						}
					}
				} else ao->o |= getnum (ao->a[0]) << 24; // ???
				break;
			case TYPE_BRA:
				if ((ret = getreg (ao->a[0])) == -1) {
					// TODO: control if branch out of range
					ret = (getnum (ao->a[0]) - (int)ao->off - 8) / 4;
					if (ret >= 0x00800000 || ret < (int)0xff800000) {
						eprintf("Branch into out of range\n");
						return 0;
					}
					ao->o |= ((ret >> 16) & 0xff) << 8;
					ao->o |= ((ret >> 8) & 0xff) << 16;
					ao->o |= ((ret) & 0xff) << 24;
				} else {
					eprintf("This branch does not accept reg as arg\n");
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
					ao->o |= ((dst) & 0xff) << 24;
					return 4;
				} else ao->o |= (getreg (ao->a[0]) << 24);
				break;
			case TYPE_HLT:
				{
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
				ao->o |= (reg != -1)? reg << 24 : 2 | getnum (ao->a[2]) << 24;
				if (ao->a[3]) {
					ao->o |= getshift (ao->a[3]);
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
				if (0xff == ((ao->o >> 16) & 0xff))
					return 0;
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
					if (ao->a[2])
						ao->o |= getshift (ao->a[2]);
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
	for (i = j = 0; i < sizeof (buf) - 1 && str[i]; i++, j++) {
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
	if (!assemble[thumb] (&aop, off, buf)) {
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
