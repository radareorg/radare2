#ifndef R2_EBC_DISAS_H
#define R2_EBC_DISAS_H

#include <stdint.h>

#define EBC_OPCODE_MASK		0x3F
#define EBC_MODIFIER_MASK	0xC0
#define EBC_OPERAND1_MASK       0x07
#define EBC_OPERAND2_MASK       (0x07 << 4)
#define EBC_OPERAND1_DIRECT     0x08
#define EBC_OPERAND2_DIRECT     0xA0
#define EBC_OPERAND1_INDX	0x01
#define EBC_OPERAND2_INDX	0x02

#define EBC_GET_OPCODE(byte)	(byte & EBC_OPCODE_MASK)

#define EBC_INSTR_MAXLEN	32
#define EBC_OPERANDS_MAXLEN	32

#define EBC_NTH_BIT(n)		(1ULL << n)
#define EBC_N_BIT_MASK(n)	(~(~0U << (n)))
#define EBC_GET_BIT(v,n)	((v >> n) & 1)

#define TEST_BIT(x,n)		(x & (1 << n))

enum ebc_opcodes {
	EBC_BREAK	= 0x00,
	EBC_JMP		= 0x01,
	EBC_JMP8	= 0x02,
	EBC_CALL	= 0x03,
	EBC_RET		= 0x04,
	EBC_CMPEQ	= 0x05,
	EBC_CMPLTE	= 0x06,
	EBC_CMPGTE	= 0x07,
	EBC_CMPULTE	= 0x08,
	EBC_CMPUGTE	= 0x09,
	EBC_NOT		= 0x0A,
	EBC_NEG		= 0x0B,
	EBC_ADD		= 0x0C,
	EBC_SUB		= 0x0D,
	EBC_MUL		= 0x0E,
	EBC_MULU	= 0x0F,
	EBC_DIV		= 0x10,
	EBC_DIVU	= 0x11,
	EBC_MOD		= 0x12,
	EBC_MODU	= 0x13,
	EBC_AND		= 0x14,
	EBC_OR		= 0x15,
	EBC_XOR		= 0x16,
	EBC_SHL		= 0x17,
	EBC_SHR		= 0x18,
	EBC_ASHR	= 0x19,
	EBC_EXTNDB	= 0x1A,
	EBC_EXTNDW	= 0x1B,
	EBC_EXTNDD	= 0x1C,
	EBC_MOVBW 	= 0x1D,
	EBC_MOVWW 	= 0x1E,
	EBC_MOVDW 	= 0x1F,
	EBC_MOVQW 	= 0x20,
	EBC_MOVBD 	= 0x21,
	EBC_MOVWD 	= 0x22,
	EBC_MOVDD 	= 0x23,
	EBC_MOVQD 	= 0x24,
	EBC_MOVSNW	= 0x25,
	EBC_MOVSND	= 0x26,
	EBC_UNDEFINED	= 0x27,
	EBC_MOVQQ 	= 0x28,
	EBC_LOADSP	= 0x29,
	EBC_STORESP	= 0x2A,
	EBC_PUSH	= 0x2B,
	EBC_POP		= 0x2C,
	EBC_CMPIEQ	= 0x2D,
	EBC_CMPILTE	= 0x2E,
	EBC_CMPIGTE	= 0x2F,
	EBC_CMPIULTE	= 0x30,
	EBC_CMPIUGTE	= 0x31,
	EBC_MOVNW 	= 0x32,
	EBC_MOVND 	= 0x33,
	EBC_UNDEFINED2	= 0x34,
	EBC_PUSHN	= 0x35,
	EBC_POPN	= 0x36,
	EBC_MOVI	= 0x37,
	EBC_MOVIN	= 0x38,
	EBC_MOVREL	= 0x39,
	EBC_COMMAND_NUM
};


typedef struct ebc_command {
	char instr[EBC_INSTR_MAXLEN];
	char operands[EBC_OPERANDS_MAXLEN];
} ebc_command_t;

int ebc_decode_command(const uint8_t *instr, ebc_command_t *cmd);

#endif /* EBC_DISAS_H */
