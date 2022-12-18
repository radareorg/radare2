/* radare - LGPL - Copyright 2014-2022 - Fedor Sakharov */

#include <r_util.h>
#include "v850e0.h"

static const char * const instrs[] = {
	[V850_MOV]	= "mov",
	[V850_NOT]	= "not",
	[V850_DIVH]	= "divh",
	[V850_JMP]	= "jmp",
	[V850_SATSUBR]	= "satsubr",
	[V850_SATSUB]	= "stasub",
	[V850_SATADD]	= "satadd",
	[V850_MULH]	= "mulh",
	[V850_OR]	= "or",
	[V850_XOR]	= "xor",
	[V850_AND]	= "and",
	[V850_TST]	= "tst",
	[V850_SUBR]	= "subr",
	[V850_SUB]	= "sub",
	[V850_ADD]	= "add",
	[V850_CMP]	= "cmp",
	[V850_MOV_IMM5]	= "mov",
	[V850_SATADD_IMM5] = "satadd",
	[V850_ADD_IMM5]	= "add",
	[V850_CMP_IMM5] = "cmp",
	[V850_SHR_IMM5] = "shr",
	[V850_SAR_IMM5] = "sar",
	[V850_SHL_IMM5]	= "shl",
	[V850_MULH_IMM5]	= "mulh",
	[V850_SLDB]	= "sldb",
	[V850_SSTB]	= "sstb",
	[V850_SLDH]	= "sldh",
	[V850_SSTH]	= "ssth",
	[V850_SLDW]	= "sldw",
	[V850_SSTW]	= "sstw",
	[V850_BCOND]	= "bcond",
	[V850_ADDI]	= "addi",
	[V850_MOVEA]	= "movea",
	[V850_MOVHI]	= "movhi",
	[V850_SATSUBI]	= "satsubi",
	[V850_ORI]	= "ori",
	[V850_XORI]	= "xori",
	[V850_ANDI]	= "andi",
	[V850_MULHI]	= "mulhi",
	[V850_LDB]	= "ld",
	[V850_LDHW]	= "ld",
	[V850_STB]	= "st",
	[V850_STHW]	= "st",
	[V850_JARL1]	= "jarl",
	[V850_JARL2]	= "jarl",
	[V850_BIT_MANIP] = "",
	[V850_EXT1]	= "",
};

static const char * const bit_instrs[] = {
	[V850_BIT_SET1]	= "set1",
	[V850_BIT_NOT1]	= "not1",
	[V850_BIT_CLR1]	= "clr1",
	[V850_BIT_TST1]	= "tst1",
};

static const char * const ext_instrs1[] = {
	[V850_EXT_SETF]	= "setf",
	[V850_EXT_LDSR]	= "ldsr",
	[V850_EXT_STSR]	= "stsr",
	[V850_EXT_SHR]	= "shr",
	[V850_EXT_SAR]	= "sar",
	[V850_EXT_SHL]	= "shl",
	[V850_EXT_TRAP]	= "trap",
	[V850_EXT_HALT]	= "halt",
	[V850_EXT_RETI]	= "reti",
	[V850_EXT_EXT2]	= "ext2",
};

static const char * const ext_instrs2[] = {
	[V850_EXT_DI]	= "di",
	[V850_EXT_EI]	= "ei",
};

static const char * const conds[] = {
	[V850_COND_V]	= "v",
	[V850_COND_CL]	= "cl",
	[V850_COND_ZE]	= "z",
	[V850_COND_NH]	= "nh",
	[V850_COND_N]	= "n",
	[V850_COND_AL]	= "",
	[V850_COND_LT]	= "lt",
	[V850_COND_LE]	= "le",
	[V850_COND_NV]	= "nv",
	[V850_COND_NC]	= "nc",
	[V850_COND_NZ]	= "nz",
	[V850_COND_H]	= "h",
	[V850_COND_NS]	= "ns",
	[V850_COND_SA]	= "sa",
	[V850_COND_GE]	= "ge",
	[V850_COND_GT]	= "gt",
};

static int decode_reg_reg(const ut16 instr, struct v850_cmd *cmd) {
	ut8 opcode = get_opcode (instr);

	if (opcode >= sizeof (instrs)/sizeof (char *)) {
		return -1;
	}

	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", instrs[opcode]);

	if (opcode == V850_JMP) {
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "[r%u]",
				get_reg1 (instr));
	} else {
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%u, r%u",
			get_reg1 (instr), get_reg2 (instr));
	}

	return 2;
}

static int decode_imm_reg(const ut16 instr, struct v850_cmd *cmd) {
	ut8 opcode = get_opcode (instr);
	if (opcode >= sizeof (instrs) / sizeof (char *)) {
		return -1;
	}

	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", instrs[opcode]);

	st8 immed = get_reg1 (instr);

	if (immed & 0x10) {
		immed |= 0xE0;
	}

	if (immed >= -9 && immed <= 9) {
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "%d, r%u",
				immed, get_reg2 (instr));
	} else {
		if (immed >= 0) {
			snprintf (cmd->operands, V850_INSTR_MAXLEN - 1,
					"0x%x, r%u", immed, get_reg2 (instr));
		} else {
			snprintf (cmd->operands, V850_INSTR_MAXLEN - 1,
					"-0x%x, r%u", immed * -1, get_reg2 (instr));
		}
	}

	return 2;
}

static int decode_bcond(const ut16 instr, int len, struct v850_cmd *cmd) {
#if 0
	ut16 disp = ((instr >> 4) & 0x7) | (instr >> 11);
	disp <<= 1;
	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "b%s", conds[instr & 0xF]);
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x", disp);
#else
	ut64 delta = ((((instr >> 4) & 0x7) | ((instr >> 11) << 3)) << 1);
	if (delta & 0x100) {
		delta |= 0xFE00;
	}
	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "b%s", conds[instr & 0xF]);
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%08"PFMT64x, cmd->addr + delta);
#endif
	return 2;
}

static int decode_jarl(const ut8 *instr, int len, struct v850_cmd *cmd) {
	if (len < 4) {
		return -1;
	}

	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

	ut8 reg = get_reg2 (word1);
	ut32 disp = (word2 << 6) | get_reg1 (word1);

	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", instrs[get_opcode (word1)]);
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%08x, r%d",
			disp << 1, reg);

	return 4;
}

static int decode_3operands(const ut8 *instr, int len, struct v850_cmd *cmd) {
	if (len < 4) {
		return -1;
	}
	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);
	snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", instrs[get_opcode (word1)]);
	snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x, r%d, r%d",
			word2, get_reg1 (word1), get_reg2 (word1));
	return 4;
}

static int decode_load_store(const ut8 *instr, int len, struct v850_cmd *cmd) {
	if (len < 4) {
		return -1;
	}

	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

	switch (get_opcode (word1)) {
	case V850_STB:
		snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s.b", instrs[get_opcode (word1)]);
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%d, 0x%x[r%d]",
			       get_reg2 (word1), word2, get_reg1 (word1));
		break;
	case V850_LDB:
		snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s.b", instrs[get_opcode (word1)]);
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x[r%d], r%d",
			       get_reg1 (word1), word2, get_reg2 (word1));
		break;
	case V850_LDHW:
		snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s.%c",
				instrs[get_opcode (word1)], word2 & 1 ? 'w' : 'h');
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x[r%d], r%d",
				word2 & 0xFFFE, get_reg1 (word1), get_reg2 (word1));
		break;
	case V850_STHW:
		snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s.%c",
				instrs[get_opcode (word1)], word2 & 1 ? 'w' : 'h');
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%d, 0x%x[r%d]",
			       get_reg2 (word1), word2 & 0xFFFE, get_reg1 (word1));
		break;
	}

	return 4;
}

static int decode_bit_op(const ut8 *instr, int len, struct v850_cmd *cmd) {
	if (len < 4) {
		return -1;
	}

	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);
	snprintf (cmd->instr, sizeof (cmd->instr) - 1, "%s", bit_instrs[word1 >> 14]);
	ut8 reg1 = get_reg1 (word1);
	snprintf (cmd->operands, sizeof (cmd->instr) - 1, "%u, 0x%x[r%d]",
			(word1 >> 11) & 0x7, word2, reg1);
	return 4;
}

static int decode_extended(const ut8 *instr, int len, struct v850_cmd *cmd) {
	if (len < 4) {
		return -1;
	}

	ut16 word1 = r_read_le16 (instr);
	ut16 word2 = r_read_at_le16 (instr, 2);

	int index = get_subopcode (word1);
	if (index < 0 || index >= R_ARRAY_SIZE (ext_instrs1)) {
		return -1;
	}
	snprintf (cmd->instr, sizeof (cmd->instr) - 1, "%s", ext_instrs1[index]);

	switch (get_subopcode (word1)) {
	case V850_EXT_SETF:
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "%s, r%d",
				conds[word1 & 0xF], get_reg2 (word1));
		break;
	case V850_EXT_LDSR:
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%d, r%d",
				get_reg2 (word1), get_reg1(word1));
		break;
	case V850_EXT_STSR:
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%d, r%d",
				get_reg1 (word1), get_reg2 (word1));
		break;
	case V850_EXT_SHR:
	case V850_EXT_SAR:
	case V850_EXT_SHL:
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "r%d, r%d",
				get_reg1 (word1), get_reg2 (word2));
		break;
	case V850_EXT_TRAP:
		snprintf (cmd->operands, V850_INSTR_MAXLEN - 1, "0x%x", get_reg1 (word1));
		break;
	case V850_EXT_HALT:
	case V850_EXT_RETI:
		cmd->operands[0] = '\0';
		break;
	case V850_EXT_EXT2:
		// can be only 0 or 1
		snprintf (cmd->instr, V850_INSTR_MAXLEN - 1, "%s", ext_instrs2[(word2 >> 13) & 1]);
		break;
	default:
		return -1;
	}

	return 4;
}

int v850_decode_command (const ut8 *instr, int len, struct v850_cmd *cmd) {
	int ret;

	if (len < 2) {
		return -1;
	}
	ut16 in = r_read_le16 (instr);

	switch (get_opcode (in)) {
	case V850_MOV:
	case V850_NOT:
	case V850_DIVH:
	case V850_JMP:
	case V850_SATSUBR:
	case V850_SATSUB:
	case V850_SATADD:
	case V850_MULH:
	case V850_OR:
	case V850_XOR:
	case V850_AND:
	case V850_TST:
	case V850_SUBR:
	case V850_SUB:
	case V850_ADD:
	case V850_CMP:
		ret = decode_reg_reg (in, cmd);
		break;
	case V850_MOV_IMM5:
	case V850_SATADD_IMM5:
	case V850_ADD_IMM5:
	case V850_CMP_IMM5:
	case V850_SHR_IMM5:
	case V850_SAR_IMM5:
	case V850_SHL_IMM5:
	case V850_MULH_IMM5:
		ret = decode_imm_reg (in, cmd);
		break;
	case V850_ADDI:
	case V850_MOVEA:
	case V850_MOVHI:
	case V850_SATSUBI:
	case V850_ORI:
	case V850_XORI:
	case V850_ANDI:
	case V850_MULHI:
		ret = decode_3operands (instr, len, cmd);
		break;
	case V850_JARL1:
	case V850_JARL2:
		ret = decode_jarl (instr, len, cmd);
		break;
	case V850_STB:
	case V850_LDB:
	case V850_LDHW:
	case V850_STHW:
		ret = decode_load_store (instr, len, cmd);
		break;
	case V850_BIT_MANIP:
		ret = decode_bit_op (instr, len, cmd);
		break;
	case V850_EXT1:
		ret = decode_extended (instr, len, cmd);
		break;
	default:
		if ((get_opcode (in) >> 2) == 0xB) {
			ret = decode_bcond (in, len, cmd);
		} else {
			ret = -1;
		}
	}

	return ret;
}
