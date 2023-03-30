#ifndef MSP430_DISAS_H
#define MSP430_DISAS_H

enum msp430_oneop_opcodes {
	MSP430_RRC,
	MSP430_SWPB,
	MSP430_RRA,
	MSP430_SXT,
	MSP430_PUSH,
	MSP430_CALL,
	MSP430_RETI,
	MSP430_UNUSED,
};

enum msp430_jumps {
	MSP430_JNE,
	MSP430_JEQ,
	MSP430_JNC,
	MSP430_JC,
	MSP430_JN,
	MSP430_JGE,
	MSP430_JL,
	MSP430_JMP,
};

enum msp430_twoop_opcodes {
	MSP430_JMP_OPC	= 0x1,
	MSP430_MOV	= 0x4,
	MSP430_ADD,
	MSP430_ADDC,
	MSP430_SUBC,
	MSP430_SUB,
	MSP430_CMP,
	MSP430_DADD,
	MSP430_BIT,
	MSP430_BIC,
	MSP430_BIS,
	MSP430_XOR,
	MSP430_AND,
};

enum msp430_addr_modes {
	MSP430_DIRECT,
	MSP430_INDEXED,
	MSP430_INDIRECT,
	MSP430_INDIRECT_INC,
};

enum msp430_cmd_type {
	MSP430_ONEOP,
	MSP430_TWOOP,
	MSP430_JUMP,
	MSP430_INV,
};

enum msp430_registers {
	MSP430_PC,
	MSP430_SP,
	MSP430_SR,
	MSP430_R3,
	MSP430_R4,
	MSP430_R5,
	MSP430_R6,
	MSP430_R7,
	MSP430_R8,
	MSP430_R9,
	MSP430_R10,
	MSP430_R11,
	MSP430_R12,
	MSP430_R13,
	MSP430_R14,
	MSP430_R15,
};

struct msp430_cmd {
	ut8 type;
	ut8	opcode;
	st16	jmp_addr;
	ut16	call_addr;
	ut8	jmp_cond;

	// Null-delimited string representation of an assembly operation mnemonic.
	// Length of array: 'i', 'n', 'v', 'a', 'l', 'i', 'd', '\0'
	// (This is longer than any real assembly mnemonic.)
	char	instr[7 + 1];

	// Null-delimited string representation of assembly operands.
	// Length of array: 2 * ('0', 'x', 4-digit hexadecimal numeral, '(', 'r', 2-digit
	// decimal numeral, ')'), ',', ' ', '\0'
	char	operands[2 * (2 + 4 + 2 + 3) + 2 + 1];
};

int msp430_decode_command(const ut8 *instr, int len, struct msp430_cmd *cmd);
#endif /* MSP430_DISAS_H */
