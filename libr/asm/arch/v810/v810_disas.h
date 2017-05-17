#ifndef R2_V810_DISASM_H
#define R2_V810_DISASM_H

#define V810_INSTR_MAXLEN     24

#define OPCODE(instr) (((instr) >> 10) & 0x3F)
#define REG1(instr) ((instr) & 0x1F)
#define REG2(instr) (((instr) >> 5) & 0x1F)
#define IMM5(instr) REG1((instr))
#define COND(instr) (((instr) >> 9) & 0xF)

#define SEXT5(imm) (((imm) & 0x10) ? (imm) | 0xE0 : (imm))
#define SEXT9(imm) (((imm) & 0x100) ? (imm) | 0xFFFFFE00 : (imm))
#define SEXT26(imm) (((imm) & 0x2000000) ? (imm) | 0xFC000000 : (imm))

#define DISP9(word1) SEXT9((word1) & 0x1FE)
#define DISP26(word1, word2) SEXT26((((word1) & 0x3FF) << 16) | (word2))

enum v810_cmd_opcodes {
	V810_MOV		= 0x0,
	V810_ADD		= 0x1,
	V810_SUB		= 0x2,
	V810_CMP		= 0x3,
	V810_SHL		= 0x4,
	V810_SHR		= 0x5,
	V810_JMP		= 0x6,
	V810_SAR		= 0x7,
	V810_MUL		= 0x8,
	V810_DIV		= 0x9,
	V810_MULU		= 0xA,
	V810_DIVU		= 0xB,
	V810_OR			= 0xC,
	V810_AND		= 0xD,
	V810_XOR		= 0xE,
	V810_NOT		= 0xF,
	V810_MOV_IMM5	= 0x10,
	V810_ADD_IMM5	= 0x11,
	V810_SETF		= 0x12,
	V810_CMP_IMM5	= 0x13,
	V810_SHL_IMM5	= 0x14,
	V810_SHR_IMM5	= 0x15,
	V810_CLI		= 0x16,
	V810_SAR_IMM5	= 0x17,
	V810_TRAP		= 0x18,
	V810_RETI		= 0x19,
	V810_HALT		= 0x1A,
	V810_LDSR		= 0x1C,
	V810_STSR		= 0x1D,
	V810_SEI		= 0x1E,
	V810_BSTR		= 0x1F,
	V810_BCOND		= 0x20,
	V810_MOVEA		= 0x28,
	V810_ADDI		= 0x29,
	V810_JR			= 0x2A,
	V810_JAL		= 0x2B,
	V810_ORI		= 0x2C,
	V810_ANDI		= 0x2D,
	V810_XORI		= 0x2E,
	V810_MOVHI		= 0x2F,
	V810_LDB		= 0x30,
	V810_LDH		= 0x31,
	V810_LDW		= 0x33,
	V810_STB		= 0x34,
	V810_STH		= 0x35,
	V810_STW		= 0x37,
	V810_INB		= 0x38,
	V810_INH		= 0x39,
	V810_CAXI		= 0x3A,
	V810_INW		= 0x3B,
	V810_OUTB		= 0x3C,
	V810_OUTH		= 0x3D,
	V810_EXT		= 0x3E,
	V810_OUTW		= 0x3F,
};

enum v810_bit_ops {
	V810_BIT_SCH0U	= 0x0,
	V810_BIT_SCH0D	= 0x1,
	V810_BIT_SCH1U	= 0x2,
	V810_BIT_SCH1D	= 0x3,
	V810_BIT_ORU	= 0x8,
	V810_BIT_ANDU	= 0x9,
	V810_BIT_XORU	= 0xA,
	V810_BIT_MOVU	= 0xB,
	V810_BIT_ORNU	= 0xC,
	V810_BIT_ANDNU	= 0xD,
	V810_BIT_XORNU	= 0xE,
	V810_BIT_NOTU	= 0xF,
};

enum v810_ext_ops {
	V810_EXT_CMPF_S		= 0x0,
	V810_EXT_CVT_WS		= 0x2,
	V810_EXT_CVT_SW		= 0x3,
	V810_EXT_ADDF_S		= 0x4,
	V810_EXT_SUBF_S		= 0x5,
	V810_EXT_MULF_S		= 0x6,
	V810_EXT_DIVF_S		= 0x7,
	V810_EXT_XB			= 0x8,
	V810_EXT_XH			= 0x9,
	V810_EXT_REV		= 0xA,
	V810_EXT_TRNC_SW	= 0xB,
	V810_EXT_MPYHW		= 0xC,
};

enum v810_conds {
	V810_COND_V		= 0x0,
	V810_COND_L		= 0x1,
	V810_COND_E		= 0x2,
	V810_COND_NH	= 0x3,
	V810_COND_N		= 0x4,
	V810_COND_NONE	= 0x5,
	V810_COND_LT	= 0x6,
	V810_COND_LE	= 0x7,
	V810_COND_NV	= 0x8,
	V810_COND_NL	= 0x9,
	V810_COND_NE	= 0xA,
	V810_COND_H		= 0xB,
	V810_COND_P		= 0xC,
	V810_COND_NOP	= 0xD,
	V810_COND_GE	= 0xE,
	V810_COND_GT	= 0xF,
};

enum v810_sysregs {
	V810_SREG_EIPC	= 0x0,
	V810_SREG_EIPSW	= 0x1,
	V810_SREG_FEPC	= 0x2,
	V810_SREG_FEPSW	= 0x3,
	V810_SREG_ECR	= 0x4,
	V810_SREG_PSW	= 0x5,
	V810_SREG_PIR	= 0x6,
	V810_SREG_TKCW	= 0x7,
	V810_SREG_CHCW	= 0x18,
	V810_SREG_ADTRE	= 0x19,
};

struct v810_cmd {
	unsigned type;
	char instr[V810_INSTR_MAXLEN];
	char operands[V810_INSTR_MAXLEN];
};

R_API int v810_decode_command(const ut8 *instr, int len, struct v810_cmd *cmd);

#endif /* R2_V810_DISASM_H */
