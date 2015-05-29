/* SHARP LH 5801 disassembler -- instruction decoder,
 * Copyright (C) 2014 Jonathan Neuschäfer,
 * Released under the terms and conditions of the GNU LGPL.
 */

/*
 * This disassembler is based on the "SHARP PC-1500/A Systemhandbuch"
 * (system manual) as published by Günter Holtkötter GmbH.
 */

#include <stdint.h>
#include <stdlib.h>
typedef uint8_t ut8;

/* Instruction classes. That's for example "add with carry". */
enum lh5801_insn_class {
	LH5801_INSNC_ADC,
	LH5801_INSNC_ADI,
	LH5801_INSNC_DCA,
	LH5801_INSNC_ADR,
	LH5801_INSNC_SBC,
	LH5801_INSNC_SBI,
	LH5801_INSNC_DCS,
	LH5801_INSNC_AND,
	LH5801_INSNC_ANI,
	LH5801_INSNC_ORA,
	LH5801_INSNC_ORI,
	LH5801_INSNC_EOR,
	LH5801_INSNC_EAI,
	LH5801_INSNC_INC,
	LH5801_INSNC_DEC,
	LH5801_INSNC_CPA,
	LH5801_INSNC_CPI,
	LH5801_INSNC_BIT,
	LH5801_INSNC_BII,
	LH5801_INSNC_LDA,
	LH5801_INSNC_LDE,
	LH5801_INSNC_LIN,
	LH5801_INSNC_LDI,
	LH5801_INSNC_LDX,
	LH5801_INSNC_STA,
	LH5801_INSNC_SDE,
	LH5801_INSNC_SIN,
	LH5801_INSNC_STX,
	LH5801_INSNC_PSH,
	LH5801_INSNC_POP,
	LH5801_INSNC_ATT,
	LH5801_INSNC_TTA,
	LH5801_INSNC_TIN,
	LH5801_INSNC_CIN,
	LH5801_INSNC_ROL,
	LH5801_INSNC_ROR,
	LH5801_INSNC_SHL,
	LH5801_INSNC_SHR,
	LH5801_INSNC_DRL,
	LH5801_INSNC_DRR,
	LH5801_INSNC_AEX,
	LH5801_INSNC_SEC,
	LH5801_INSNC_REC,
	LH5801_INSNC_CDV,
	LH5801_INSNC_ATP,
	LH5801_INSNC_SPU,
	LH5801_INSNC_RPU,
	LH5801_INSNC_SPV,
	LH5801_INSNC_RPV,
	LH5801_INSNC_SDP,
	LH5801_INSNC_RDP,
	LH5801_INSNC_ITA,
	LH5801_INSNC_SIE,
	LH5801_INSNC_RIE,
	LH5801_INSNC_AM0,
	LH5801_INSNC_AM1,
	LH5801_INSNC_NOP,
	LH5801_INSNC_HLT,
	LH5801_INSNC_OFF,
	LH5801_INSNC_JMP,
	LH5801_INSNC_BCH,
	LH5801_INSNC_BCC,
	LH5801_INSNC_LOP,
	LH5801_INSNC_SJP,
	LH5801_INSNC_VEJ,
	LH5801_INSNC_VMJ,
	LH5801_INSNC_VCC,
	LH5801_INSNC_RTN,
	LH5801_INSNC_RTI,

	LH5801_INSNC_NUMBER
};

/* Instruction description. */
struct lh5801_insn_class_desc {
	char mnem[4];		/* Assembler mnemonic */
	const char *desc;	/* Textual description (for ?d) */

	/* TODO: r2 insn type? */
};

const struct lh5801_insn_class_desc
	lh5801_insn_class_descs[LH5801_INSNC_NUMBER];

/* A decoded instruction */
struct lh5801_insn {
	ut8 iclass;	/* an index into lh5801_insn_class_descs */
	ut8 type;	/* an index into lh5801_insn_descs */
	ut8 fd;
	ut8 opcode;
	ut8 imm[3];
};

int lh5801_decode(struct lh5801_insn *, const uint8_t *, int);
void lh5801_print_insn(char *out, int size, const struct lh5801_insn *);
