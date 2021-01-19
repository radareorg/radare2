#ifndef AVR_DISASSEMBLER_INSTRUCTIONSET_H
#define AVR_DISASSEMBLER_INSTRUCTIONSET_H

#include <stdint.h>

/* Total number of assembly instructions, Maximum number of operands */
#define AVR_TOTAL_INSTRUCTIONS	145
#define AVR_MAX_NUM_OPERANDS	2

/* Enumeration for all types of AVR Operands */
enum AVR_Operand_Types {
	OPERAND_NONE, OPERAND_REGISTER_GHOST,
	OPERAND_REGISTER, OPERAND_REGISTER_STARTR16,
	OPERAND_REGISTER_EVEN_PAIR, OPERAND_REGISTER_EVEN_PAIR_STARTR24,
	OPERAND_BRANCH_ADDRESS, OPERAND_RELATIVE_ADDRESS, OPERAND_LONG_ABSOLUTE_ADDRESS,
	OPERAND_IO_REGISTER, OPERAND_DATA, OPERAND_DES_ROUND, OPERAND_COMPLEMENTED_DATA, OPERAND_BIT, OPERAND_WORD_DATA,
	OPERAND_X, OPERAND_XP, OPERAND_MX,
	OPERAND_Y, OPERAND_YP, OPERAND_MY, OPERAND_YPQ,
	OPERAND_Z, OPERAND_ZP, OPERAND_MZ, OPERAND_ZPQ,
};

/* Structure for each instruction in the instruction set */
struct _instructionInfo {
	char mnemonic[7];
	/* Bitwise AND mask for just the instruction bits */
	uint16_t opcodeMask;
	int numOperands;
	/* Bitwise AND mask for each operand in the opcode */
	uint16_t operandMasks[AVR_MAX_NUM_OPERANDS];
	int operandTypes[AVR_MAX_NUM_OPERANDS];
};
typedef struct _instructionInfo instructionInfo;

#endif /* AVR_DISASSEMBLER_INSTRUCTIONSET_H */