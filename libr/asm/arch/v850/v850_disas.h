#ifndef R2_V850_DISASM_H
#define R2_V850_DISASM_H

#define V850_INSTR_MAXLEN	24

#define SEXT5(imm) (((imm) & 0x10) ? (imm) | 0xE0 : (imm))
#define SEXT9(imm) (((imm) & 0x100) ? (imm) | 0xFFFFFE00 : (imm))
#define SEXT26(imm) (((imm) & 0x2000000) ? (imm) | 0xFC000000 : (imm))

enum v850_cmd_opcodes {
	V850_MOV	= 0x0,
	V850_NOT	= 0x1,
	V850_DIVH	= 0x2,
	V850_JMP	= 0x3,
	V850_SATSUBR	= 0x4,
	V850_SATSUB	= 0x5,
	V850_SATADD	= 0x6,
	V850_MULH	= 0x7,
	V850_OR		= 0x8,
	V850_XOR	= 0x9,
	V850_AND	= 0xA,
	V850_TST	= 0xB,
	V850_SUBR	= 0xC,
	V850_SUB	= 0xD,
	V850_ADD	= 0xE,
	V850_CMP	= 0xF,
	V850_MOV_IMM5	= 0x10,
	V850_SATADD_IMM5 = 0x11,
	V850_ADD_IMM5	= 0x12,
	V850_CMP_IMM5	= 0x13,
	V850_SHR_IMM5	= 0x14,
	V850_SAR_IMM5	= 0x15,
	V850_SHL_IMM5	= 0x16,
	V850_MULH_IMM5	= 0x17,
	V850_SLDB	= 0x18,
	V850_SSTB	= 0x1C,
	V850_SLDH	= 0x20,
	V850_SSTH	= 0x24,
	V850_SLDW	= 0x28,
	V850_SSTW	= 0x29,
	V850_BCOND	= 0x2C,
	V850_BCOND2	= 0x2D,
	V850_BCOND3	= 0x2E,
	V850_BCOND4	= 0x2F,
	V850_ADDI	= 0x30,
	V850_MOVEA	= 0x31,
	V850_MOVHI	= 0x32,
	V850_SATSUBI	= 0x33,
	V850_ORI	= 0x34,
	V850_XORI	= 0x35,
	V850_ANDI	= 0x36,
	V850_MULHI	= 0x37,
	V850_LDB	= 0x38,
	V850_LDHW	= 0x39,
	V850_STB	= 0x3A,
	V850_STHW	= 0x3B,
	V850_JARL1	= 0x3C,
	V850_JARL2	= 0x3D,
	V850_BIT_MANIP	= 0x3E,
	V850_EXT1	= 0x3F,
};

enum v850_conds {
	V850_COND_V		= 0x0, // Overflow
	V850_COND_CL	= 0x1, // Carry/Lower
	V850_COND_ZE	= 0x2, // Zero/equal
	V850_COND_NH	= 0x3, // Not higher
	V850_COND_N		= 0x4, // Negative
	V850_COND_AL	= 0x5, // Always
	V850_COND_LT	= 0x6, // Less than signed
	V850_COND_LE	= 0x7, // Less than or equal signed
	V850_COND_NV	= 0x8, // No overflow
	V850_COND_NL	= 0x9, // No carry / not lower
	V850_COND_NC	= 0x9, // No carry / not lower
	V850_COND_NE	= 0xA, // Not zero / not equal
	V850_COND_NZ	= 0xA, // Not zero / not equal
	V850_COND_H		= 0xB, // Higher/Greater than
	V850_COND_P		= 0xC, // Positive / not sign
	V850_COND_NS	= 0xC, // Positive / not sign
	V850_COND_SA	= 0xD, // Saturated
	V850_COND_GE	= 0xE, // Greater than or equal signed
	V850_COND_GT	= 0xF, // Greater than signed
};

enum v850_bit_ops {
	V850_BIT_SET1	= 0x0,
	V850_BIT_NOT1	= 0x1,
	V850_BIT_CLR1	= 0x2,
	V850_BIT_TST1	= 0x3,
};

enum v850_extension1 {
	V850_EXT_SETF	= 0x0,
	V850_EXT_LDSR	= 0x1,
	V850_EXT_STSR	= 0x2,
	V850_EXT_UNDEF1	= 0x3,
	V850_EXT_SHR	= 0x4,
	V850_EXT_SAR	= 0x5,
	V850_EXT_SHL	= 0x6,
	V850_EXT_UNDEF2	= 0x7,
	V850_EXT_TRAP	= 0x8,
	V850_EXT_HALT	= 0x9,
	V850_EXT_RETI	= 0xa,
	V850_EXT_EXT2	= 0xb,
};

enum v850_extension2 {
	V850_EXT_DI	= 0x0,
	V850_EXT_EI	= 0x4,
};

enum v850_regs {
	V850_ZERO = 0x0,
	V850_R1 = 0x1,
	V850_R2 = 0x2,
	V850_SP = 0x3,
	V850_GP = 0x4,
	V850_TP = 0x5,
	V850_R6 = 0x6,
	V850_R7 = 0x7,
	V850_R8 = 0x8,
	V850_R9 = 0x9,
	V850_R10 = 0xA,
	V850_R11 = 0xB,
	V850_R12 = 0xC,
	V850_R13 = 0xD,
	V850_R14 = 0xE,
	V850_R15 = 0xF,
	V850_R16 = 0x10,
	V850_R17 = 0x11,
	V850_R18 = 0x12,
	V850_R19 = 0x13,
	V850_R20 = 0x14,
	V850_R21 = 0x15,
	V850_R22 = 0x16,
	V850_R23 = 0x17,
	V850_R24 = 0x18,
	V850_R25 = 0x19,
	V850_R26 = 0x1A,
	V850_R27 = 0x1B,
	V850_R28 = 0x1C,
	V850_R29 = 0x1D,
	V850_EP = 0x1E,
	V850_LP = 0x1F,
};

enum v850_sysregs {
	V850_SREG_EIPC = 0x0,
	V850_SREG_EIPCW = 0x1,
	V850_SREG_FEPC = 0x2,
	V850_SREG_FEPSW = 0x3,
	V850_SREG_ECR = 0x4,
	V850_SREG_PSW = 0x5,
	V850_SREG_CTPC = 0x10,
	V850_SREG_CTPSW = 0x11,
	V850_SREG_DBPC = 0x12,
	V850_SREG_DBPSW = 0x13,
	V850_SREG_CTBP = 0x14,
	V850_SREG_DIR = 0x15,
};

enum v850_flags {
	V850_FLAG_CY = 1,
	V850_FLAG_OV,
	V850_FLAG_S,
	V850_FLAG_Z,
};

struct v850_cmd {
	ut64 addr;
	unsigned type;
	char	instr[V850_INSTR_MAXLEN];
	char	operands[V850_INSTR_MAXLEN];
};

static inline ut8 get_opcode(const ut16 instr) {
	return (instr >> 5) & 0x3F;
}

// FIXME: XXX: Invalid for extended instruction format 4 (Format XII)!
static inline ut8 get_subopcode(const ut16  instr) {
	return (instr & 0x7e00000) >> 21;
}

static inline ut8 get_reg1(const ut16 instr) {
	return instr & 0x1F;
}

static inline ut8 get_reg2(const ut16 instr) {
	return instr >> 11;
}

int v850_decode_command (const ut8 *instr, int len, struct v850_cmd *cmd);
#endif /* R2_V850_DISASM_H */
