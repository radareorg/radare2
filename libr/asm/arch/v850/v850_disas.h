#ifndef R2_V850_DISASM_H
#define R2_V850_DISASM_H

#define V850_INSTR_MAXLEN	24

#define SEXT5(imm) (((imm) & 0x10) ? (imm) | 0xE0 : (imm))
#define SEXT9(imm) (((imm) & 0x100) ? (imm) | 0xFFFFFE00 : (imm))
#define SEXT26(imm) (((imm) & 0x2000000) ? (imm) | 0xFC000000 : (imm))

// Format I
#define F1_REG1(instr) ((instr) & 0x1F)
#define F1_REG2(instr) (((instr) & 0xF800) >> 11)

#define F1_RN1(instr) (V850_REG_NAMES[F1_REG1(instr)])
#define F1_RN2(instr) (V850_REG_NAMES[F1_REG2(instr)])

// Format II
#define F2_IMM(instr) F1_REG1(instr)
#define F2_REG2(instr) F1_REG2(instr)

#define F2_RN2(instr) (V850_REG_NAMES[F2_REG2(instr)])

// Format III
#define F3_COND(instr) ((instr) & 0xF)
#define F3_DISP(instr) (((instr) & 0x70) >> 4) | (((instr) & 0xF800) >> 7)

// Format IV
#define F4_DISP(instr) ((instr) & 0x3F)
#define F4_REG2(instr) F1_REG2(instr)

#define F4_RN2(instr) (V850_REG_NAMES[F4_REG2(instr)])

// Format V
#define F5_REG2(instr) F1_REG2(instr)
#define F5_DISP(instr) ((((ut32)(instr) & 0xffff) << 31) | (((ut32)(instr) & 0xffff0000) << 1))
#define F5_RN2(instr) (V850_REG_NAMES[F5_REG2(instr)])

// Format VI
#define F6_REG1(instr) F1_REG1(instr)
#define F6_REG2(instr) F1_REG2(instr)
#define F6_IMM(instr) (((instr) & 0xFFFF0000) >> 16)

#define F6_RN1(instr) (V850_REG_NAMES[F6_REG1(instr)])
#define F6_RN2(instr) (V850_REG_NAMES[F6_REG2(instr)])

// Format VII
#define F7_REG1(instr) F1_REG1(instr)
#define F7_REG2(instr) F1_REG2(instr)
#define F7_DISP(instr) F6_IMM(instr)

#define F7_RN1(instr) (V850_REG_NAMES[F7_REG1(instr)])
#define F7_RN2(instr) (V850_REG_NAMES[F7_REG2(instr)])

// Format VIII
#define F8_REG1(instr) F1_REG1(instr)
#define F8_DISP(instr) F6_IMM(instr)
#define F8_BIT(instr) (((instr) & 0x3800) >> 11)
#define F8_SUB(instr) (((instr) & 0xC000) >> 14)

#define F8_RN1(instr) (V850_REG_NAMES[F8_REG1(instr)])
#define F8_RN2(instr) (V850_REG_NAMES[F8_REG2(instr)])

// Format IX
// Also regID/cond
#define F9_REG1(instr) F1_REG1(instr)
#define F9_REG2(instr) F1_REG2(instr)
#define F9_SUB(instr) (((instr) & 0x7E00000) >> 21)

#define F9_RN1(instr) (V850_REG_NAMES[F9_REG1(instr)])
#define F9_RN2(instr) (V850_REG_NAMES[F9_REG2(instr)])
// TODO: Format X

// Format XI
#define F11_REG1(instr) F1_REG1(instr)
#define F11_REG2(instr) F1_REG2(instr)
#define F11_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F11_SUB(instr) ((((instr) & 0x7E00000) >> 20) | (((instr) & 2) >> 1))

#define F11_RN1(instr) (V850_REG_NAMES[F11_REG1(instr)])
#define F11_RN2(instr) (V850_REG_NAMES[F11_REG2(instr)])
// Format XII
#define F12_IMM(instr) (F1_REG1(instr) | (((instr) & 0x7C0000) >> 13))
#define F12_REG2(instr) F1_REG2(instr)
#define F12_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F12_SUB(instr) ((((instr) & 0x7800001) >> 22) | (((instr) & 2) >> 1))

#define F12_RN2(instr) (V850_REG_NAMES[F12_REG2(instr)])
#define F12_RN3(instr) (V850_REG_NAMES[F12_REG3(instr)])

// Format XIII
#define F13_IMM(instr) (((instr) & 0x3E) >> 1)
// Also a subopcode
#define F13_REG2(instr) (((instr) & 0x1F0000) >> 16)
#define F13_LIST(instr) (((instr) && 0xFFE00000) >> 21)

#define F13_RN2(instr) (V850_REG_NAMES[F13_REG2(instr)])

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
	V850_R1	= 0x1,
	V850_R2	= 0x2,
	V850_SP	= 0x3,
	V850_GP	= 0x4,
	V850_TP	= 0x5,
	V850_R6	= 0x6,
	V850_R7	= 0x7,
	V850_R8	= 0x8,
	V850_R9	= 0x9,
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

static const char* V850_REG_NAMES[] = {
	"zero",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"ep",
	"lp",
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

R_API int v850_decode_command (const ut8 *instr, struct v850_cmd *cmd);
#endif /* R2_V850_DISASM_H */
