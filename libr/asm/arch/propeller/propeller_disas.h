#ifndef PROPELLER_DISAS_H
#define PROPELLER_DISAS_H

#define PROP_INSTR_MAXLEN	32

enum propeller_opcodes {
	PROP_ABS		= 0x2A,
	PROP_ABSNEG		= 0x2B,
	PROP_ADD		= 0x20,
	PROP_ADDABS		= 0x22,
	PROP_ADDS		= 0x34,
	PROP_ADDSX		= 0x36,
	PROP_ADDX		= 0x32,
	PROP_AND		= 0x18,
	PROP_ANDN		= 0x19,
	PROP_CALL		= 0x17,
	PROP_CMP		= 0x21,
	PROP_CMPS		= 0x30,
	PROP_CMPSUB		= 0x38,
	PROP_CMPSX		= 0x31,
	PROP_CMPX		= 0x33,
	PROP_DJNZ		= 0x39,
	PROP_HUBOP		= 0x03,
	PROP_JMP		= 0x17,
	PROP_JMPRET		= 0x17,
	PROP_MAX		= 0x13,
	PROP_MAXS		= 0x11,
	PROP_MIN		= 0x12,
	PROP_MINS		= 0x10,
	PROP_MOV		= 0x28,
	PROP_MOVD		= 0x15,
	PROP_MOVI		= 0x16,
	PROP_MOVS		= 0x14,
	PROP_MUXC		= 0x1c,
	PROP_MUXNC		= 0x1d,
	PROP_MUXNZ		= 0x1f,
	PROP_MUXZ		= 0x1e,
	PROP_NEG		= 0x29,
	PROP_NEGC		= 0x2c,
	PROP_NEGNC		= 0x2d,
	PROP_NEGNZ		= 0x2f,
	PROP_NEGZ		= 0x2e,
	PROP_NOP		= 0x00,
	PROP_OR			= 0x1a,
	PROP_RCL		= 0x0d,
	PROP_RCR		= 0x0c,
	PROP_RDBYTE		= 0x00,
	PROP_RDLONG		= 0x02,
	PROP_RDWORD		= 0x01,
	PROP_RET		= 0x17,
	PROP_REV		= 0x0f,
	PROP_ROL		= 0x09,
	PROP_ROR		= 0x08,
	PROP_SAR		= 0x0e,
	PROP_SHL		= 0x0b,
	PROP_SHR		= 0x0a,
	PROP_SUB		= 0x21,
	PROP_SUBABS		= 0x23,
	PROP_SUBS		= 0x35,
	PROP_SUBSX		= 0x37,
	PROP_SUBX		= 0x33,
	PROP_SUMC		= 0x24,
	PROP_SUMNC		= 0x25,
	PROP_SUMNZ		= 0x27,
	PROP_SUMZ		= 0x26,
	PROP_TEST		= 0x18,
	PROP_TESTN		= 0x19,
	PROP_TJNZ		= 0x3a,
	PROP_TJZ		= 0x3b,
	PROP_WAITCNT	= 0x3e,
	PROP_WAITPEQ	= 0x3c,
	PROP_WAITPNE	= 0x3d,
	PROP_WAITVID	= 0x3f,
	PROP_WRBYTE		= 0x00,
	PROP_WRLONG		= 0x02,
	PROP_WRWORD		= 0x01,
	PROP_XOR		= 0x1b,
};

enum propeller_ext_opcodes {
	PROP_CLKSET		= 0x18,
	PROP_COGID		= 0x19,
	PROP_COGINIT	= 0x1a,
	PROP_COGSTOP	= 0x1b,
	PROP_LOCKCLR	= 0x1f,
	PROP_LOCKNEW	= 0x1c,
	PROP_LOCKRET	= 0x1d,
	PROP_LOCKSET	= 0x1e,
};

enum propeller_conditions {
	PROP_IF_ALWAYS		= 0xf,
	PROP_IF_NEVER		= 0x0,
	PROP_IF_E			= 0xa,
	PROP_IF_NE			= 0x5,
	PROP_IF_A			= 0x1,
	PROP_IF_B			= 0xc,
	PROP_IF_AE			= 0x3,
	PROP_IF_BE			= 0xe,
	PROP_IF_C_EQ_Z		= 0x9,
	PROP_IF_C_NE_Z		= 0x6,
	PROP_IF_C_AND_Z		= 0x8,
	PROP_IF_C_AND_NZ	= 0x4,
	PROP_IF_NC_AND_Z	= 0x2,
	PROP_IF_NZ_OR_NC	= 0x7,
	PROP_IF_NZ_OR_C		= 0xd,
	PROP_IF_Z_OR_NC		= 0xb,
};

struct propeller_cmd {
	unsigned type;
	ut16	src;
	ut16	dst;
	ut16	opcode;
	ut8		immed;
	char	prefix[16];
	char	instr[PROP_INSTR_MAXLEN];
	char	operands[PROP_INSTR_MAXLEN];
};

int propeller_decode_command (const ut8* instr, struct propeller_cmd *cmd);
#endif /* PROPELLER_DISAS_H */
