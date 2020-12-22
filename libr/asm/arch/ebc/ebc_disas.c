/* radare - LGPL - 2013-2015 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include "ebc_disas.h"
#include <r_types.h>

#define CHK_SNPRINTF(dst, sz, fmt, ...) do { \
		int len_chk_snprintf_ = snprintf (dst, sz, fmt, __VA_ARGS__); \
		if (len_chk_snprintf_ >= sz) { \
			return -1; \
		}\
	} while (0)

static const char *instr_names[] = {
	"break",
	"jmp",
	"jmp8",
	"call",
	"ret",
	"cmp",
	"cmp",
	"cmp",
	"cmp",
	"cmp",
	"not",
	"neg",
	"add",
	"sub",
	"mul",
	"mulu",
	"div",
	"divu",
	"mod",
	"modu",
	"and",
	"or",
	"xor",
	"shl",
	"shr",
	"ashr",
	"extndb",
	"extndw",
	"extndd",
	"movbw",
	"movww",
	"movdw",
	"movqw",
	"movbd",
	"movwd",
	"movdd",
	"movqd",
	"movsnw",
	"movsnd",
	"",
	"movqq",
	"loadsp",
	"storesp",
	"push",
	"pop",
	"cmpi",
	"cmpi",
	"cmpi",
	"cmpi",
	"cmpi",
	"movnw",
	"movnd",
	"",
	"pushn",
	"popn",
	"movi",
	"movin",
	"movrel"
};

/* Dedicated registers names */
static const char *dedic_regs[] = {
	"FLAGS",
	"IP",
	"DR_RESERVED1",
	"DR_RESERVED2",
	"DR_RESERVED3",
	"DR_RESERVED4",
	"DR_RESERVED5",
	"DR_RESERVED6"
};

typedef int (*decode)(const ut8 *, ebc_command_t *cmd);

typedef struct ebc_index {
	enum { EBC_INDEX16, EBC_INDEX32, EBC_INDEX64 } type;
	enum { EBC_INDEX_PLUS = 0, EBC_INDEX_MINUS } sign;
	ut8 a_width;
	ut32 c;
	ut32 n;
} ebc_index_t;

static int decode_index16(const ut8 *data, ebc_index_t *index) {
	ut16 tmp = *(ut16*)data;
	index->type = EBC_INDEX16;
	index->sign = tmp & 0x8000 ? EBC_INDEX_PLUS : EBC_INDEX_MINUS;
	index->a_width = ((tmp >> 12) & EBC_N_BIT_MASK(2)) * 2;
	index->n = tmp & EBC_N_BIT_MASK(index->a_width);
	index->c = (tmp >> index->a_width) & EBC_N_BIT_MASK(12 - index->a_width);
	return 0;
}

static int decode_index32(const ut8 *data, ebc_index_t *index) {
	ut32 tmp = *(ut32*)data;
	index->type = EBC_INDEX32;
	index->sign = tmp & EBC_NTH_BIT(31) ? EBC_INDEX_PLUS : EBC_INDEX_MINUS;
	index->a_width = ((tmp >> 28) & EBC_N_BIT_MASK(2)) * 4;
	index->n = tmp & EBC_N_BIT_MASK(index->a_width);
	index->c = (tmp >> index->a_width) & EBC_N_BIT_MASK(28 - index->a_width);
	return 0;
}

static int decode_index64(const ut8 *data, ebc_index_t *index) {
	ut64 tmp = *(ut64*)data;
	index->type = EBC_INDEX64;
	index->sign = tmp & EBC_NTH_BIT(63) ? EBC_INDEX_PLUS : EBC_INDEX_MINUS;
	index->a_width = ((tmp >> 60) & EBC_N_BIT_MASK(2)) * 8;
	index->n = tmp & EBC_N_BIT_MASK(index->a_width);
	index->c = (tmp >> index->a_width) & EBC_N_BIT_MASK(60- index->a_width);
	return 0;
}

static int decode_break(const ut8 *bytes, ebc_command_t *cmd) {
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s", instr_names[EBC_BREAK]);
	snprintf(cmd->operands, EBC_OPERANDS_MAXLEN, "%d", bytes[1]);
	return 2;
}

// TODO: what is the difference between relative and absolute jump in disas?
static int decode_jmp(const ut8 *bytes, ebc_command_t *cmd) {
	int ret;
	int bits = 32;
	char op1[32] = {0};
	int32_t immed32;
	ebc_index_t idx32;
	char sign;
	unsigned long immed;

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%d%s", instr_names[EBC_JMP], bits,
			TEST_BIT(bytes[1], 7) ? TEST_BIT(bytes[1], 6) ? "cs" : "cc" : "");

	if (TEST_BIT(bytes[0], 6)){
		immed = *(ut64*)(bytes + 2);
		bits = 64;
		ret = 10;
		snprintf(cmd->operands, EBC_OPERANDS_MAXLEN, "0x%lx", immed);
	} else {
		if ((bytes[1] & 0x7) != 0) {
			{
				snprintf (op1, sizeof (op1), "%sr%u ",
					TEST_BIT (bytes[1], 3) ? "@" : "", bytes[1] & 0x7);
			}
		}
		if (TEST_BIT (bytes[0], 7)) {
			if (TEST_BIT (bytes[1], 3)) {
				decode_index32 (bytes + 2, &idx32);
				sign = idx32.sign ? '+' : '-';

				CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
					"%s(%c%u, %c%u)",
					op1, sign, idx32.n, sign, idx32.c);
			} else {
				immed32 = *(int32_t *)(bytes + 2);
				CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
					"%s0x%x", op1, immed32);
			}
			ret = 6;
		} else {
			snprintf (cmd->operands, EBC_OPERANDS_MAXLEN, "%s", op1);
			ret = 2;
		}
	}

	return ret;
}

static int decode_jmp8(const ut8 *bytes, ebc_command_t *cmd) {
	char suff[3] = {0};
	if (TEST_BIT (bytes[0], 7)) {
		const char *str = (TEST_BIT(bytes[0], 6))? "cs": "cc";
		snprintf (suff, 3, "%s", str);
	}
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK], suff);
	snprintf(cmd->operands, EBC_OPERANDS_MAXLEN, "0x%x", bytes[1]);
	return 2;
}

static int decode_call(const ut8 *bytes, ebc_command_t *cmd) {
	int ret;
	short bits = 32;
	ut8 op1 = bytes[1] & 0x7;
	ut32 i1;
	unsigned long i2;
	ebc_index_t idx32;
	char sign;

	if (!TEST_BIT (bytes[0], 6)) {
		//CALL32
		bits = 32;
		ret = 2;
		if (TEST_BIT (bytes[1], 3)) {
			//operand 1 indirect
			if (TEST_BIT (bytes[0], 7)) {
				// immediate data is present
				decode_index32 (bytes + 2, &idx32);
				sign = idx32.sign ? '+' : '-';

				CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
					"@r%d(%c%u, %c%u)",
					op1, sign, idx32.n, sign, idx32.c);
				ret = 6;
			} else {
				snprintf (cmd->operands, EBC_OPERANDS_MAXLEN,
					"@r%d", op1);
			}
		} else {
			//operand 1 direct
			if (TEST_BIT (bytes[0], 7)) {
				// immediate data present
				i1 = *(ut32 *)(bytes + 2);
				CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
					"r%d(0x%x)", op1, i1);
				ret = 6;
			} else {
				// no immediate data present
				CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
					"r%d", op1);
			}
		}
	} else {
		bits = 64;
		ret = 10;
		i2 = *(ut64 *)&bytes[2];
		CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "0x%lx", i2);
	}
	CHK_SNPRINTF (cmd->instr, EBC_INSTR_MAXLEN, "%s%d%s%s",
		instr_names[EBC_CALL], bits,
		TEST_BIT (bytes[1], 5) ? "ex" : "",
		TEST_BIT (bytes[1], 4) ? "" : "a");
	return ret;
}

static int decode_ret(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s", instr_names[EBC_RET]);
	cmd->operands[0] = '\0';
	return ret;
}

static int decode_cmp(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	int op1, op2;
	char sign;
	ut16 immed;
	ebc_index_t idx;

	op1 = bytes[1] & 0x07;
	op2 = (bytes[1] >> 4) & 0x07;

	if (TEST_BIT (bytes[0], 7)) {
		ret += 2;
		if (TEST_BIT (bytes[1], 7)) {
			decode_index16 (bytes + 2, &idx);
			sign = idx.sign ? '+' : '-';
			CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
				"r%d, @r%d (%c%d, %c%d)",
				op1, op2, sign, idx.n, sign, idx.c);
		} else {
			immed = *(ut16 *)&bytes[2];
			CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
				"r%d, r%d %d", op1, op2, immed);
		}
	} else {
		CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN,
			"r%d, r%d", op1, op2);
	}

	return ret;
}

static int decode_cmpeq(const ut8 *bytes, ebc_command_t *cmd) {
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%deq",
			instr_names[EBC_CMPLTE], bits);
	return decode_cmp(bytes, cmd);
}

static int decode_cmplte(const ut8 *bytes, ebc_command_t *cmd) {
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%dlte",
			instr_names[EBC_CMPLTE], bits);
	return decode_cmp(bytes, cmd);
}

static int decode_cmpgte(const ut8 *bytes, ebc_command_t *cmd) {
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%dgte",
			instr_names[EBC_CMPGTE], bits);
	return decode_cmp(bytes, cmd);
}

static int decode_cmpulte(const ut8 *bytes, ebc_command_t *cmd) {
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%dulte",
			instr_names[EBC_CMPULTE], bits);
	return decode_cmp(bytes, cmd);
}

static int decode_cmpugte(const ut8 *bytes, ebc_command_t *cmd) {
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%dugte",
			instr_names[EBC_CMPUGTE], bits);
	return decode_cmp(bytes, cmd);
}

static int decode_not(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	unsigned op1, op2;
	char index[32] = {0};
	ut16 immed;

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%u", instr_names[EBC_NOT],
			bits);

	op1 = bytes[1] & 0x07;
	op2 = (bytes[1] >> 4) & 0x07;

	if (TEST_BIT(bytes[0], 7)) {
		//immediate/index present
		ret = 4;
		if (TEST_BIT(bytes[1], 7)) {
			ebc_index_t idx;
			decode_index16(bytes + 2, &idx);
			snprintf(index, 32, " (%c%d, %c%d)",
					idx.sign ? '+' : '-', idx.n,
					idx.sign ? '+' : '-', idx.c);
		} else {
			immed = *(ut16*)&bytes[2];
			snprintf(index, 32, "(%u)", immed);
		}
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%sr%d, %sr%d%s",
		TEST_BIT (bytes[1], 3) ? "@" : "", op1,
		TEST_BIT (bytes[1], 7) ? "@" : "", op2, index);
	return ret;
}

static int decode_neg(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_not(bytes, cmd);
	cmd->instr[1] = 'e';
	cmd->instr[2] = 'g';
	return ret;
}

static int decode_add(const ut8 *bytes, ebc_command_t *cmd) {
	char sign;
	int ret = 2;
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	unsigned op1, op2;
	char index[32] = {0};
	ut16 immed;

	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u", instr_names[EBC_ADD],
			bits);

	op1 = bytes[1] & 0x07;
	op2 = (bytes[1] >> 4) & 0x07;

	if (TEST_BIT (bytes[0], 7)) {
		ret = 4;
		if (TEST_BIT (bytes[1], 7)) {
			ebc_index_t idx;
			decode_index16(bytes + 2, &idx);
			sign = idx.sign ? '+' : '-';
			snprintf(index, sizeof (index),
				" (%c%d, %c%d)", sign, idx.n, sign, idx.c);
		} else {
			immed = *(ut16*)&bytes[2];
			snprintf (index, sizeof (index), "(%u)", immed);
		}
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%sr%d, %sr%d%s",
		TEST_BIT (bytes[1], 3) ? "@" : "", op1,
		TEST_BIT (bytes[1], 7) ? "@" : "", op2, index);
	return ret;
}

static int decode_sub(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[EBC_SUB], bits);
	return ret;
}

static int decode_mul(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[EBC_MUL], bits);
	return ret;
}

static int decode_mulu(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;

	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[EBC_MULU], bits);
	return ret;
}

static int decode_div(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[EBC_DIV], bits);
	return ret;
}

static int decode_divu(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[EBC_DIVU], bits);
	return ret;
}

static int decode_arith(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = decode_add(bytes, cmd);
	unsigned bits = TEST_BIT (bytes[0], 6)? 64: 32;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[bytes[0] & EBC_OPCODE_MASK], bits);
	return ret;
}

static int decode_mov_args(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op1, op2;
	char op1c[32], op2c[32];
	char ind1[32] = {0}, ind2[32] = {0};
	ebc_index_t idx;
	char sign;

	op1 = bytes[1] & 0x07;
	op2 = (bytes[1] >> 4) & 0x07;

	snprintf(op1c, 32, "%sr%u", TEST_BIT(bytes[1], 3) ? "@" : "", op1);
	snprintf(op2c, 32, "%sr%u", TEST_BIT(bytes[1], 7) ? "@" : "", op2);

	switch (bytes[0] & EBC_OPCODE_MASK) {
	case EBC_MOVBW:
	case EBC_MOVWW:
	case EBC_MOVDW:
	case EBC_MOVQW:
		if (TEST_BIT(bytes[0], 7)) {
			decode_index16(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind1, 32,"(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 2;
		}
		if (TEST_BIT(bytes[0], 6)) {
			decode_index16(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind2, 32, "(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 2;
		}
		break;
	case EBC_MOVBD:
	case EBC_MOVWD:
	case EBC_MOVDD:
	case EBC_MOVQD:
		if (TEST_BIT(bytes[0], 7)) {
			decode_index32(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind1, 32, "(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 4;
		}
		if (TEST_BIT(bytes[0], 6)) {
			decode_index32(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind2, 32, "(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 4;
		}
		break;
	case EBC_MOVQQ:
		if (TEST_BIT(bytes[0], 7)) {
			decode_index64(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind1, 32, "(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 8;
		}
		if (TEST_BIT(bytes[0], 6)) {
			decode_index64(bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf(ind1, 32, "(%c%u, %c%u)", sign,
					idx.n, sign, idx.c);
			ret += 8;
		}
		break;
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %s%s",
		op1c, ind1, op2c, ind2);

	return ret;
}

static int decode_mov(const ut8 *bytes, ebc_command_t *cmd) {
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK]);
	return decode_mov_args(bytes, cmd);
}

static int decode_movsn_args(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op1, op2;
	char op1c[32], op2c[32], sign;
	char ind1[32] = {0}, ind2[32] = {0};

	op1 = bytes[1] & 0x07;
	op2 = (bytes[1] >> 4) & 0x07;

	snprintf(op1c, 32, "%sr%u", TEST_BIT(bytes[1], 3) ? "@" : "", op1);
	snprintf(op2c, 32, "%sr%u", TEST_BIT(bytes[1], 7) ? "@" : "", op2);

	switch (bytes[0] & EBC_OPCODE_MASK) {
	case EBC_MOVSNW:
		if (TEST_BIT(bytes[0], 7)) {
			ebc_index_t idx;
			ret += 2;
			decode_index16(bytes + 2, &idx);
			sign = idx.sign? '+': '-';
			snprintf (ind1, 32, "(%c%u, %c%u)",
				sign, idx.n, sign, idx.c);
		}
		if (TEST_BIT(bytes[0], 6)) {
			ebc_index_t idx;
			decode_index16 (bytes + ret, &idx);
			sign = idx.sign? '+': '-';
			snprintf (ind2, 32, "(%c%u, %c%u)",
				sign, idx.n, sign, idx.c);
			ret += 2;
		}
		break;
	case EBC_MOVSND:
		break;
	}
	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %s%s",
		op1c, ind1, op2c, ind2);
	return ret;
}

static int decode_movsn(const ut8 *bytes, ebc_command_t *cmd) {
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK]);
	return decode_movsn_args(bytes, cmd);
}

static int decode_loadsp(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK]);
	snprintf(cmd->operands, EBC_OPERANDS_MAXLEN, "%s, r%u",
			dedic_regs[bytes[1] & 0x7],
			(bytes[1] >> 4) & 0x7);
	return ret;
}

static int decode_storesp(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op2 = (bytes[1] >> 4) & 0x07;
	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s",
		instr_names[bytes[0] & EBC_OPCODE_MASK]);
	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "r%u, %s",
		bytes[1] & 0x7,
		op2 < 2 ? dedic_regs[op2] : "RESERVED_DEDICATED_REG");
	return ret;
}

static int decode_push_pop(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op1 = bytes[1] & 0x07;
	char op1c[32];

	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u",
			instr_names[bytes[0] & EBC_OPCODE_MASK],
			TEST_BIT(bytes[0], 6) ? 64 : 32);

	snprintf (op1c, sizeof (op1c), "%sr%d",
		TEST_BIT(bytes[1], 3) ? "@" : "", op1);

	if (TEST_BIT (bytes[0], 7)) {
		ret += 2;
		if (TEST_BIT (bytes[1], 3)) {
			ebc_index_t idx;
			char sign;
			decode_index16(bytes + 2, &idx);

			sign = idx.sign ? '+' : '-';

			CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s (%c%d, %c%d)",
				op1c, sign, idx.n, sign, idx.c);
		} else {
			ut16 immed = *(ut16 *)(bytes + 2);

			CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s %u",
				op1c, immed);
		}
    } else {
        CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s",	op1c);
    }

	return ret;
}

static int decode_cmpi(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op1 = bytes[1] & 0x07;
	char op1c[32];
	char indx[32] = {0};
	char immed[32] = {0};
	char *suff[] = {"eq", "lte", "gte", "ulte", "ugte"};

	snprintf (op1c, sizeof (op1c)-1, "%sr%u",
		TEST_BIT(bytes[1], 3) ? "@" : "", op1);

	snprintf (cmd->instr, EBC_INSTR_MAXLEN, "%s%u%c%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK],
			TEST_BIT(bytes[0], 6) ? 64 : 32,
			TEST_BIT(bytes[0], 7) ? 'd' : 'w',
			suff[(bytes[0] & EBC_OPCODE_MASK) - EBC_CMPIEQ]
			);

	if (TEST_BIT (bytes[1], 4)) {
		char sign;
		ebc_index_t idx;

		decode_index16(bytes + 2, &idx);

		sign = idx.sign ? '+' : '-';

		snprintf(indx, sizeof (indx), " (%c%u, %c%u)", sign, idx.n, sign, idx.c);

		ret += 2;
	}

	if (TEST_BIT(bytes[0], 7)) {
		ut32 im = *(ut32*)(bytes + ret);
		snprintf (immed, sizeof (immed), "%u", im);
		ret += 4;
	} else {
		ut16 im = *(ut16*)(bytes + ret);
		snprintf (immed, sizeof (immed), "%u", im);
		ret += 2;
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %s", op1c, indx, immed);
	return ret;
}

static int decode_movn(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	unsigned op1 = bytes[1] & 0x07;
	unsigned op2 = (bytes[1] >> 4) & 0x07;
	char op1c[32], op2c[32];
	char indx1[32] = {0};
	char indx2[32] = {0};
	char sign;
	ebc_index_t idx;

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s",
			instr_names[bytes[0] & EBC_OPCODE_MASK]);

	snprintf(op1c, 32, "%sr%u", TEST_BIT(bytes[1], 3) ? "@" : "", op1);
	snprintf(op2c, 32, "%sr%u", TEST_BIT(bytes[1], 7) ? "@" : "", op2);

	if ((bytes[0] & EBC_OPCODE_MASK) == EBC_MOVNW) {
		if (TEST_BIT(bytes[0], 7)) {
			decode_index16(bytes + ret, &idx);
			sign = idx.sign ? '+' : '-';
			snprintf(indx1, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);
			ret += 2;
		}
		if (TEST_BIT(bytes[0], 6)) {
			decode_index16(bytes + ret, &idx);
			sign = idx.sign ? '+' : '-';
			snprintf(indx2, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);
			ret += 2;
		}
	} else {
		if (TEST_BIT(bytes[0], 7)) {
			decode_index32(bytes + ret, &idx);
			sign = idx.sign ? '+' : '-';
			snprintf(indx1, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);
			ret += 4;
		}
		if (TEST_BIT(bytes[0], 6)) {
			decode_index32(bytes + ret, &idx);
			sign = idx.sign ? '+' : '-';
			snprintf(indx2, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);
			ret += 4;
		}
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %s%s", op1c, indx1, op2c, indx2);
	return ret;
}

static int decode_movi(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	char p1 = 0, p2 = 0;
	char indx[32] = {0};
	char op1[32];
	unsigned long immed = 0;

	switch (bytes[0] >> 6) {
	case 0: ret = -1; break;
	case 1: p2 = 'w'; break;
	case 2: p2 = 'd'; break;
	case 3: p2 = 'q'; break;
	}

	if (ret < 0) {
		return ret;
	}

	switch ((bytes[1] >> 4) & 0x3) {
	case 0: p1 = 'b'; break;
	case 1: p1 = 'w'; break;
	case 2: p1 = 'd'; break;
	case 3: p1 = 'q'; break;
	}

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%c%c",
			instr_names[bytes[0] & EBC_OPCODE_MASK], p1, p2);

	if (TEST_BIT(bytes[1], 6)) {
		char sign;
		ebc_index_t idx;

		decode_index16(bytes + 2, &idx);
		sign = idx.sign ? '+' : '-';

		snprintf(indx, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);

		ret += 2;
	}

	switch (p2) {
	ut16 i1;
	ut32 i2;
	ut64 i3;
	case 'w':
		i1 = *(ut16*)(bytes + ret);
		immed = (unsigned long)i1;
		ret += 2;
		break;
	case 'd':
		i2 = *(ut32*)(bytes + ret);
		immed = (unsigned long)i2;
		ret += 4;
		break;
	case 'q':
		i3 = *(ut64*)(bytes + ret);
		immed = i3;
		ret += 8;
		break;
	}

	snprintf (op1, 32, "%sr%u", TEST_BIT (bytes[1], 3) ? "@" : "", bytes[1] & 0x7);
	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %lu", op1, indx, immed);
	return ret;
}

static int decode_movin(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	char p1 = 0;
	char indx1[32] = {0};
	char indx2[32] = {0};
	char op1[32];
	char sign;
	ebc_index_t idx = {0};

	switch (bytes[0] >> 6) {
	case 0: ret = -1; break;
	case 1: p1 = 'w'; break;
	case 2: p1 = 'd'; break;
	case 3: p1 = 'q'; break;
	}

	if (ret < 0) {
		return ret;
	}

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%c",
			instr_names[bytes[0] & EBC_OPCODE_MASK], p1);

	if (TEST_BIT(bytes[1], 6)) {
		decode_index16(bytes + 2, &idx);

		sign = idx.sign ? '+' : '-';

		snprintf(indx1, 32, "(%c%u, %c%u)", sign,
				idx.n, sign, idx.c);

		ret += 2;
	}

	switch (p1) {
	case 'w':
		decode_index16(bytes + ret, &idx);
		ret += 2;
		break;
	case 'd':
		decode_index32(bytes + ret, &idx);
		ret += 4;
		break;
	case 'q':
		decode_index64(bytes + ret, &idx);
		ret += 8;
		break;
	}

	sign = idx.sign ? '+' : '-';

	snprintf (indx2, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);

	snprintf (op1, 32, "%sr%u", TEST_BIT (bytes[1], 3) ? "@" : "", bytes[1] & 0x7);
	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, %s", op1, indx1, indx2);
	return ret;
}

static int decode_movrel(const ut8 *bytes, ebc_command_t *cmd) {
	int ret = 2;
	char p1 = 0;
	char op1[32];
	char indx[32] = {0};
	unsigned long immed = 0;
	unsigned formathex = 0;

	switch (bytes[0] >> 6) {
	case 0:
		ret = -1;
		break;
	case 1:
		p1 = 'w';
		formathex = 4;
		break;
	case 2:
		p1 = 'd';
		formathex = 8;
		break;
	case 3:
		p1 = 'q';
		formathex = 16;
		break;
	}

	if (ret < 0) {
		return ret;
	}

	snprintf(cmd->instr, EBC_INSTR_MAXLEN, "%s%c",
			instr_names[bytes[0] & EBC_OPCODE_MASK], p1);
	snprintf(op1, 32, "%sr%u", TEST_BIT(bytes[1], 3) ? "@" : "", bytes[1] & 0x7);

	if (TEST_BIT(bytes[1], 6)) {
		ebc_index_t idx;
		char sign;

		decode_index16(bytes + 2, &idx);
		sign = idx.sign ? '+' : '-';

		snprintf(indx, 32, "(%c%u, %c%u)", sign, idx.n, sign, idx.c);

		ret += 2;
	}

	ut16 v16;
	ut32 v32;
	ut64 v64;
	switch (p1) {
	case 'w':
		v16 = *(ut16 *)(bytes + 2);
		immed = v16;
		ret += 2;
		break;
	case 'd':
		v32 = *(ut32 *)(bytes + 2);
		immed = v32;
		ret += 4;
		break;
	case 'q':
		v64 = *(ut64 *)(bytes + 2);
		immed = v64;
		ret += 8;
		break;
	}

	CHK_SNPRINTF (cmd->operands, EBC_OPERANDS_MAXLEN, "%s%s, 0x%0*lx",
		op1, indx, formathex, immed);
	return ret;
}

static int decode_invalid(const ut8 *bytes, ebc_command_t *cmd) {
	return -1;
}

static decode decodes[EBC_COMMAND_NUM] = {
	decode_break,
	decode_jmp,
	decode_jmp8,
	decode_call,
	decode_ret,
	decode_cmpeq,
	decode_cmplte,
	decode_cmpgte,
	decode_cmpulte,
	decode_cmpugte,
	decode_not,
	decode_neg,
	decode_add,
	decode_sub,
	decode_mul,
	decode_mulu,
	decode_div,
	decode_divu,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_arith,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_mov,
	decode_movsn,
	decode_movsn,
	decode_invalid,
	decode_mov,
	decode_loadsp,
	decode_storesp,
	decode_push_pop,
	decode_push_pop,
	decode_cmpi,
	decode_cmpi,
	decode_cmpi,
	decode_cmpi,
	decode_cmpi,
	decode_movn,
	decode_movn,
	decode_invalid,
	decode_push_pop,
	decode_push_pop,
	decode_movi,
	decode_movin,
	decode_movrel
};

int ebc_decode_command(const ut8 *instr, ebc_command_t *cmd) {
	if ((instr[0] & EBC_OPCODE_MASK) > 0x39) {
		{
			return -1;
		}
	}
	return decodes[instr[0] & EBC_OPCODE_MASK](instr, cmd);
}
