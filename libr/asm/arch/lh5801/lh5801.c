/* SHARP LH 5801 disassembler -- instruction decoder,
 * Copyright (C) 2014 jn,
 * Released under the terms and conditions of the GNU LGPL.
 */

/*
 * This disassembler is based on the "SHARP PC-1500/A Systemhandbuch"
 * (system manual) as published by Günter Holtkötter GmbH.
 *
 * An english version is available at
 * http://www.pc1500.com/technical_reference_manual.html.
 */

#include "lh5801.h"
#include <stdio.h>
#include <string.h>
#include <r_types.h>

#define ARRAY_LENGTH(a) (sizeof(a)/sizeof((a)[0]))

const struct lh5801_insn_class_desc
		lh5801_insn_class_descs[LH5801_INSNC_NUMBER] = {
	[LH5801_INSNC_ADC] = { "adc", "add with carry" },
	[LH5801_INSNC_ADI] = { "adi", "add immediate" },
	[LH5801_INSNC_DCA] = { "dca", "decimal add" },
	[LH5801_INSNC_ADR] = { "adr", "add Rreg" },
	[LH5801_INSNC_SBC] = { "sbc", "subtract with carry" },
	[LH5801_INSNC_SBI] = { "sbi", "subtract immediate" },
	[LH5801_INSNC_DCS] = { "dcs", "decimal subtract" },
	[LH5801_INSNC_AND] = { "and", "and accumulator" },
	[LH5801_INSNC_ANI] = { "ani", "and immediate" },
	[LH5801_INSNC_ORA] = { "ora", "or accumulator" },
	[LH5801_INSNC_ORI] = { "ori", "or immediate" },
	[LH5801_INSNC_EOR] = { "eor", "exclusive or" },
	[LH5801_INSNC_EAI] = { "eai", "exclusive or accumulator, immediate" },
	[LH5801_INSNC_INC] = { "inc", "increment" },
	[LH5801_INSNC_DEC] = { "dec", "decrement" },
	[LH5801_INSNC_CPA] = { "cpa", "compare accumulator" },
	[LH5801_INSNC_CPI] = { "cpi", "compare immediate" },
	[LH5801_INSNC_BIT] = { "bit", "bit test" },
	[LH5801_INSNC_BII] = { "bii", "bit test immediate" },
	[LH5801_INSNC_LDA] = { "lda", "load accumulator" },
	[LH5801_INSNC_LDE] = { "lde", "load and decrement" },
	[LH5801_INSNC_LIN] = { "lin", "load and increment" },
	[LH5801_INSNC_LDI] = { "ldi", "load immediate" },
	[LH5801_INSNC_LDX] = { "ldx", "load Xreg" },
	[LH5801_INSNC_STA] = { "sta", "store accumulator" },
	[LH5801_INSNC_SDE] = { "sde", "store and decrement" },
	[LH5801_INSNC_SIN] = { "sin", "store and increment" },
	[LH5801_INSNC_STX] = { "stx", "store Xreg" },
	[LH5801_INSNC_PSH] = { "psh", "push" },
	[LH5801_INSNC_POP] = { "pop", "pop" },
	[LH5801_INSNC_ATT] = { "att", "accumulator to t (status register)" },
	[LH5801_INSNC_TTA] = { "tta", "t (status register) to accumulator" },
	[LH5801_INSNC_TIN] = { "tin", "transfer and increment" },
	[LH5801_INSNC_CIN] = { "cin", "compare and increment" },
	[LH5801_INSNC_ROL] = { "rol", "rotate left" },
	[LH5801_INSNC_ROR] = { "ror", "rotate right" },
	[LH5801_INSNC_SHL] = { "shl", "shift left" },
	[LH5801_INSNC_SHR] = { "shr", "shift right" },
	[LH5801_INSNC_DRL] = { "drl", "digit rotate left" },
	[LH5801_INSNC_DRR] = { "drr", "digit rotate right" },
	[LH5801_INSNC_AEX] = { "aex", "exchange accumulator" },
	[LH5801_INSNC_SEC] = { "sec", "set carry flag" },
	[LH5801_INSNC_REC] = { "rec", "reset carry flag" },
	[LH5801_INSNC_CDV] = { "cdv", "clear divider" },
	[LH5801_INSNC_ATP] = { "atp", "accumulator to port" },
	[LH5801_INSNC_SPU] = { "spu", "set PU" },
	[LH5801_INSNC_RPU] = { "rpu", "reset PU" },
	[LH5801_INSNC_SPV] = { "spv", "set PV" },
	[LH5801_INSNC_RPV] = { "rpv", "reset PV" },
	[LH5801_INSNC_SDP] = { "sdp", "set display" },
	[LH5801_INSNC_RDP] = { "rdp", "reset display" },
	[LH5801_INSNC_ITA] = { "ita", "IN to accumulator" },
	[LH5801_INSNC_SIE] = { "sie", "set interrupt enable" },
	[LH5801_INSNC_RIE] = { "rie", "reset interrupt enable" },
	[LH5801_INSNC_AM0] = { "am0", "accumulator to tm and 0" },
	[LH5801_INSNC_AM1] = { "am1", "accumulator to tm and 1" },
	[LH5801_INSNC_NOP] = { "nop", "no operation" },
	[LH5801_INSNC_HLT] = { "hlt", "halt" },
	[LH5801_INSNC_OFF] = { "off", "\"off\", reset BF" },
	[LH5801_INSNC_JMP] = { "jmp", "jump" },
	[LH5801_INSNC_BCH] = { "bch", "unconditional branch" },
	[LH5801_INSNC_BCC] = { "bcc", "conditional branch" },
	[LH5801_INSNC_LOP] = { "lop", "loop" },
	[LH5801_INSNC_SJP] = { "sjp", "subroutine jump (aka. call)" },
	[LH5801_INSNC_VEJ] = { "vej", "vector subroutine jump, short format" },
	[LH5801_INSNC_VMJ] = { "vmj", "vector subroutine jump, long format" },
	[LH5801_INSNC_VCC] = { "vcc", "conditional vector subroutine jump" },
	[LH5801_INSNC_RTN] = { "rtn", "return from subroutine" },
	[LH5801_INSNC_RTI] = { "rti", "return from interrupt" }
};

/* These flags describe an instruction variant's properties with regard to
 * encoding and printing */
enum lh5801_insn_format {
	/* An instruction can contain up to three immediate data bytes. */
	LH5801_IFMT_IMM0 = 0,
	LH5801_IFMT_IMM1,
	LH5801_IFMT_IMM2,
	LH5801_IFMT_IMM3,
	LH5801_IFMT_IMM_MASK = 3,

	/* Instructions may either require an 0xFD prefix, require its absence,
	 * or behave differently if it is found. */
	LH5801_IFMT_FD_NO   = 0,
	LH5801_IFMT_FD_YES  = 1 << 2,
	LH5801_IFMT_FD_MOD  = 2 << 2,		/* FD_MEM */
	LH5801_IFMT_FD_MASK = 3 << 2,		/* ^- also take care of (ij) */

	/* Some instructions encode access registers */
	LH5801_IFMT_RREG = 1 << 4, /* X,Y or U, encoded by two bits */
	LH5801_IFMT_AREG = 2 << 4, /* accumulator */
	LH5801_IFMT_SREG = 3 << 4, /* stack pointer */
	LH5801_IFMT_PREG = 4 << 4, /* program counter */
	LH5801_IFMT_REG_MASK = 7 << 4,

	/* Branch and vector jump instructions may have a three-bit condition
	 * code. */
	LH5801_IFMT_COND = 1 << 7,

	/* Branch instructions may point forward or backward. */
	LH5801_IFMT_BCH = 1 << 8,

	/* The short vector jump instruction (VEJ) */
	LH5801_IFMT_VEJ = 1 << 9,

	/* Register access modes: full, low/high half, or memory pointed to */
	LH5801_IFMT_RFULL = 0,
	LH5801_IFMT_RLOW  = 1 << 10,
	LH5801_IFMT_RHIGH = 2 << 10,
	LH5801_IFMT_RMEM  = 3 << 10,		/* <-- kill this, see above */
	LH5801_IFMT_RMODE_MASK = 3 << 10,
};

#define LH5801_IFMT_IMMS(f)  ((f)&LH5801_IFMT_IMM_MASK)
#define LH5801_IFMT_RMODE(f) ((f)&LH5801_IFMT_RMODE_MASK)

static bool lh5801_ifmt_fd_matches(enum lh5801_insn_format fmt, int fd) {
	switch (fmt & LH5801_IFMT_FD_MASK) {
	case LH5801_IFMT_FD_NO: 	return !fd;
	case LH5801_IFMT_FD_YES:	return fd;
	case LH5801_IFMT_FD_MOD:	return true;
	default:			return false;
	}
}

/* Instruction (variant) description. */
struct lh5801_insn_desc {
	ut8 iclass;	/* enum lh5801_insn_class */

	/* The common bits in this format */
	ut8 opcode;

	ut16 format;	/* enum lh5801_insn_format */
};

const struct lh5801_insn_desc lh5801_insn_descs[] = {
	{ /* adc rl*/
		.iclass = LH5801_INSNC_ADC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x02,
	},
	{ /* adc rh*/
		.iclass = LH5801_INSNC_ADC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH,
		.opcode = 0x82,
	},
	{ /* adc (r) */
		.iclass = LH5801_INSNC_ADC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x03,
	},
	{ /* adc (0000h) */
		.iclass = LH5801_INSNC_ADC,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xa3,
	},
	{ /* adi a, 00h */
		.iclass = LH5801_INSNC_ADI,
		.format = LH5801_IFMT_IMM1|LH5801_IFMT_AREG,
		.opcode = 0xb3
	},
	{ /* adi (r), 00h */
		.iclass = LH5801_INSNC_ADI,
		.format = LH5801_IFMT_IMM1|LH5801_IFMT_RREG|LH5801_IFMT_FD_MOD|LH5801_IFMT_RMEM,
		.opcode = 0x4f,
	},
	{ /* adi (0000h), 00h */
		.iclass = LH5801_INSNC_ADI,
		.format = LH5801_IFMT_IMM3|LH5801_IFMT_FD_MOD,
		.opcode = 0xef
	},
	{ /* dca (r) */
		.iclass = LH5801_INSNC_DCA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x8c,
	},
	{ /* adr r */
		.iclass = LH5801_INSNC_ADR,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_FD_YES,
		.opcode = 0xca,
	},
	{ /* sbc rl */
		.iclass = LH5801_INSNC_SBC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x00
	},
	{ /* sbc rh */
		.iclass = LH5801_INSNC_SBC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH,
		.opcode = 0x80
	},
	{ /* sbc (r) */
		.iclass = LH5801_INSNC_SBC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x01
	},
	{ /* sbc (0000h) */
		.iclass = LH5801_INSNC_SBC,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xa1
	},
	{ /* sbi a, 00h */
		.iclass = LH5801_INSNC_SBI,
		.format = LH5801_IFMT_AREG|LH5801_IFMT_IMM1,
		.opcode = 0xb1
	},
	{ /* dcs (r) */
		.iclass = LH5801_INSNC_DCS,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x0c
	},
	{ /* and (r) */
		.iclass = LH5801_INSNC_AND,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x09
	},
	{ /* and (0000h) */
		.iclass = LH5801_INSNC_AND,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xa9
	},
	{ /* ani a, 00h */
		.iclass = LH5801_INSNC_ANI,
		.format = LH5801_IFMT_IMM1|LH5801_IFMT_AREG,
		.opcode = 0xb9
	},
	{ /* ani (r), 00h */
		.iclass = LH5801_INSNC_ANI,
		.format = LH5801_IFMT_IMM1|LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x49
	},
	{ /* ani (0000h), 00h */
		.iclass = LH5801_INSNC_ANI,
		.format = LH5801_IFMT_IMM3|LH5801_IFMT_FD_MOD,
		.opcode = 0xe9
	},
	{ /* ora (r) */
		.iclass = LH5801_INSNC_ORA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x0b
	},
	{ /* ora (0000h) */
		.iclass = LH5801_INSNC_ORA,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xab
	},
	{ /* ori a, 00h */
		.iclass = LH5801_INSNC_ORI,
		.format = LH5801_IFMT_AREG|LH5801_IFMT_IMM1,
		.opcode = 0xbb
	},
	{ /* ori (r), 00h */
		.iclass = LH5801_INSNC_ORI,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_IMM1|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x4b
	},
	{ /* ori (0000h), 00h */
		.iclass = LH5801_INSNC_ORI,
		.format = LH5801_IFMT_IMM3|LH5801_IFMT_FD_MOD,
		.opcode = 0xeb
	},
	{ /* eor (r) */
		.iclass = LH5801_INSNC_EOR,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x0d
	},
	{ /* eor (0000h) */
		.iclass = LH5801_INSNC_EOR,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xad
	},
	{ /* eai 00h */
		.iclass = LH5801_INSNC_EAI,
		.format = LH5801_IFMT_IMM1,
		.opcode = 0xbd
	},
	{ /* inc a */
		.iclass = LH5801_INSNC_INC,
		.format = LH5801_IFMT_AREG,
		.opcode = 0xdd,
	},
	{ /* inc rl */
		.iclass = LH5801_INSNC_INC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x40,
	},
	{ /* inc rh */
		.iclass = LH5801_INSNC_INC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH|LH5801_IFMT_FD_YES,
		.opcode = 0x40,
	},
	{ /* inc r */
		.iclass = LH5801_INSNC_INC,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x44
	},
	{ /* dec a */
		.iclass = LH5801_INSNC_DEC,
		.format = LH5801_IFMT_AREG,
		.opcode = 0xdf,
	},
	{ /* dec rl */
		.iclass = LH5801_INSNC_DEC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x42,
	},
	{ /* dec rh */
		.iclass = LH5801_INSNC_DEC,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH|LH5801_IFMT_FD_YES,
		.opcode = 0x42,
	},
	{ /* dec r */
		.iclass = LH5801_INSNC_DEC,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x46
	},
	{ /* cpa rl */
		.iclass = LH5801_INSNC_CPA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x06
	},
	{ /* cpa rh */
		.iclass = LH5801_INSNC_CPA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH,
		.opcode = 0x86
	},
	{ /* cpa (r) */
		.iclass = LH5801_INSNC_CPA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x07
	},
	{ /* cpa (0000h) */
		.iclass = LH5801_INSNC_CPA,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xa7
	},
	{ /* cpi rl,00h */
		.iclass = LH5801_INSNC_CPI,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW|LH5801_IFMT_IMM1,
		.opcode = 0x4e
	},
	{ /* cpi rh,00h */
		.iclass = LH5801_INSNC_CPI,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH|LH5801_IFMT_IMM1,
		.opcode = 0x4c
	},
	{ /* cpi a,00h */
		.iclass = LH5801_INSNC_CPI,
		.format = LH5801_IFMT_AREG|LH5801_IFMT_IMM1,
		.opcode = 0xb7
	},
	{ /* bit (r) */
		.iclass = LH5801_INSNC_BIT,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x0f
	},
	{ /* bit (0000h) */
		.iclass = LH5801_INSNC_BIT,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xaf
	},
	{ /* bii a, 00h */
		.iclass = LH5801_INSNC_BII,
		.format = LH5801_IFMT_AREG|LH5801_IFMT_IMM1,
		.opcode = 0xbf
	},
	{ /* bii (r), 00h */
		.iclass = LH5801_INSNC_BII,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_IMM1|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x4d
	},
	{ /* bii (0000h), 00h */
		.iclass = LH5801_INSNC_BII,
		.format = LH5801_IFMT_IMM3|LH5801_IFMT_FD_MOD,
		.opcode = 0xed
	},
	{ /* lda rl */
		.iclass = LH5801_INSNC_LDA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x04,
	},
	{ /* lda rh */
		.iclass = LH5801_INSNC_LDA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH,
		.opcode = 0x84,
	},
	{ /* lda (r) */
		.iclass = LH5801_INSNC_LDA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x05,
	},
	{ /* lda (0000h) */
		.iclass = LH5801_INSNC_LDA,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xa5,
	},
	{ /* lde r */
		.iclass = LH5801_INSNC_LDE,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x47,
	},
	{ /* lin r */
		.iclass = LH5801_INSNC_LIN,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x45,
	},
	{ /* ldi rl, 00h */
		.iclass = LH5801_INSNC_LDI,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW|LH5801_IFMT_IMM1,
		.opcode = 0x4a,
	},
	{ /* ldi rh, 00h */
		.iclass = LH5801_INSNC_LDI,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH|LH5801_IFMT_IMM1,
		.opcode = 0x48,
	},
	{ /* ldi a, 00h */
		.iclass = LH5801_INSNC_LDI,
		.format = LH5801_IFMT_AREG|LH5801_IFMT_IMM1,
		.opcode = 0xb5
	},
	{ /* ldi s, 0000h */
		.iclass = LH5801_INSNC_LDI,
		.format = LH5801_IFMT_SREG|LH5801_IFMT_IMM2,
		.opcode = 0xaa
	},
	{ /* ldx r */
		.iclass = LH5801_INSNC_LDX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_RREG,
		.opcode = 0x08,
	},
	{ /* ldx s */
		.iclass = LH5801_INSNC_LDX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_SREG,
		.opcode = 0x48,
	},
	{ /* ldx p */
		.iclass = LH5801_INSNC_LDX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_PREG,
		.opcode = 0x58
	},
	{ /* sta rl */
		.iclass = LH5801_INSNC_STA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RLOW,
		.opcode = 0x0a
	},
	{ /* sta rh */
		.iclass = LH5801_INSNC_STA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RHIGH,
		.opcode = 0x08
	},
	{ /* sta (r) */
		.iclass = LH5801_INSNC_STA,
		.format = LH5801_IFMT_RREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0x0e
	},
	{ /* sta (0000h) */
		.iclass = LH5801_INSNC_STA,
		.format = LH5801_IFMT_IMM2|LH5801_IFMT_FD_MOD,
		.opcode = 0xae
	},
	{ /* sde r */
		.iclass = LH5801_INSNC_SDE,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x43
	},
	{ /* sin r */
		.iclass = LH5801_INSNC_SIN,
		.format = LH5801_IFMT_RREG,
		.opcode = 0x41
	},
	{ /* stx r */
		.iclass = LH5801_INSNC_STX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_RREG,
		.opcode = 0x4a
	},
	{ /* stx s */
		.iclass = LH5801_INSNC_STX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_SREG,
		.opcode = 0x4e
	},
	{ /* stx p */
		.iclass = LH5801_INSNC_STX,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_PREG,
		.opcode = 0x5e
	},
	{ /* psh a */
		.iclass = LH5801_INSNC_PSH,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_AREG,
		.opcode = 0xc8
	},
	{ /* psh r */
		.iclass = LH5801_INSNC_PSH,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_RREG,
		.opcode = 0x88
	},
	{ /* pop a */
		.iclass = LH5801_INSNC_POP,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_AREG,
		.opcode = 0x8a
	},
	{ /* pop r */
		.iclass = LH5801_INSNC_POP,
		.format = LH5801_IFMT_FD_YES|LH5801_IFMT_RREG,
		.opcode = 0x0a
	},
	{ /* att */
		.iclass = LH5801_INSNC_ATT,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xec
	},
	{ /* tta */
		.iclass = LH5801_INSNC_TTA,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xaa
	},
	{ /* tin */
		.iclass = LH5801_INSNC_TIN,
		.format = 0,
		.opcode = 0xf5
	},
	{ /* cin */
		.iclass = LH5801_INSNC_CIN,
		.format = 0,
		.opcode = 0xf7
	},
	{ /* rol */
		/* FIXME:
		 * In the technical reference manual rol is encoded as 0xd8
		 * (vej d8h) in one table and 0xdd (inc a) in another. The
		 * actual encoding of rol should be used instead.
		 */
		.iclass = LH5801_INSNC_ROL,
		.format = 0,
		.opcode = 0xdd
	},
	{ /* ror */
		.iclass = LH5801_INSNC_ROR,
		.format = 0,
		.opcode = 0xd1
	},
	{ /* shl */
		.iclass = LH5801_INSNC_SHL,
		.format = 0,
		.opcode = 0xd9
	},
	{ /* shr */
		.iclass = LH5801_INSNC_SHR,
		.format = 0,
		.opcode = 0xd5
	},
	{ /* drl (x) */
		.iclass = LH5801_INSNC_DRL,
		.format = 0, //LH5801_IFMT_XREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0xd7
	},
	{ /* drr (x) */
		.iclass = LH5801_INSNC_DRR,
		.format = 0, //LH5801_IFMT_XREG|LH5801_IFMT_RMEM|LH5801_IFMT_FD_MOD,
		.opcode = 0xd3
	},
	{ /* aex */
		.iclass = LH5801_INSNC_AEX,
		.format = 0,
		.opcode = 0xf1
	},
	{ /* am0 */
		.iclass = LH5801_INSNC_AM0,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xce
	},
	{ /* am1 */
		.iclass = LH5801_INSNC_AM1,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xde
	},
	{ /* cdv */
		.iclass = LH5801_INSNC_CDV,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0x8e
	},
	{ /* atp */
		.iclass = LH5801_INSNC_ATP,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xcc
	},
	{ /* sdp */
		.iclass = LH5801_INSNC_SDP,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xc1
	},
	{ /* rdp */
		.iclass = LH5801_INSNC_RDP,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xc0
	},
	{ /* spu */
		.iclass = LH5801_INSNC_SPU,
		.format = 0,
		.opcode = 0xe1
	},
	{ /* rpu */
		.iclass = LH5801_INSNC_RPU,
		.format = 0,
		.opcode = 0xe3
	},
	{ /* spv */
		.iclass = LH5801_INSNC_SPV,
		.format = 0,
		.opcode = 0xa8
	},
	{ /* rpv */
		.iclass = LH5801_INSNC_RPV,
		.format = 0,
		.opcode = 0xb8
	},
	{ /* ita */
		.iclass = LH5801_INSNC_ITA,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xba
	},
	{ /* rie */
		.iclass = LH5801_INSNC_RIE,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xbe
	},
	{ /* sie */
		.iclass = LH5801_INSNC_SIE,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0x81
	},
	{ /* hlt */
		.iclass = LH5801_INSNC_HLT,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0xb1
	},
	{ /* off */
		.iclass = LH5801_INSNC_OFF,
		.format = LH5801_IFMT_FD_YES,
		.opcode = 0x4c
	},
	{ /* nop */
		.iclass = LH5801_INSNC_NOP,
		.format = 0,
		.opcode = 0x38
	},
	{ /* sec */
		.iclass = LH5801_INSNC_SEC,
		.format = 0,
		.opcode = 0xfb
	},
	{ /* rec */
		.iclass = LH5801_INSNC_REC,
		.format = 0,
		.opcode = 0xf9
	},
	{ /* jmp 0000h */
		.iclass = LH5801_INSNC_JMP,
		.format = LH5801_IFMT_IMM2,
		.opcode = 0xba
	},
	{ /* bch ±00h */
		.iclass = LH5801_INSNC_BCH,
		.format = LH5801_IFMT_BCH|LH5801_IFMT_IMM1,
		.opcode = 0x8e
	},
	{ /* bcc ±00h */
		.iclass = LH5801_INSNC_BCC,
		.format = LH5801_IFMT_BCH|LH5801_IFMT_COND|LH5801_IFMT_IMM1,
		.opcode = 0x81
	},
	{ /* lop 02h */
		.iclass = LH5801_INSNC_LOP,
		.format = LH5801_IFMT_IMM1,
		.opcode = 0x88
	},
	{ /* sjp 0000h */
		.iclass = LH5801_INSNC_SJP,
		.format = LH5801_IFMT_IMM2,
		.opcode = 0xbe,
	},
	{ /* vej c0h */
		.iclass = LH5801_INSNC_VEJ,
		.format = LH5801_IFMT_VEJ,
		.opcode = 0xc0
	},
	{ /* vcc 00h */
		.iclass = LH5801_INSNC_VCC,
		.format = LH5801_IFMT_IMM1|LH5801_IFMT_COND,
		.opcode = 0xc1
	},
	{ /* vmj 00h */
		/* FIXME:
		 * This instruction is documented in the technical reference
		 * manual, but when decoded in the same way as bcc, it looks
		 * like vvr (vector jump if overflow is reset).
		 * It should be tested what the hardware does on vmj with the
		 * overflow bit set.
		 */
		.iclass = LH5801_INSNC_VMJ,
		.format = LH5801_IFMT_IMM1,
		.opcode = 0xcd
	},
	{ /* rtn */
		.iclass = LH5801_INSNC_RTN,
		.format = 0,
		.opcode = 0x9a
	},
	{ /* rti */
		.iclass = LH5801_INSNC_RTI,
		.format = 0,
		.opcode = 0x8a
	}
};


/* Decodes one instruction.
 * returns -1 on invalid instructions, the length on valid instructions,
 * and 0 when decoding wasn't possible due to a too small length */
int lh5801_decode(struct lh5801_insn *insn, const ut8 *buf, int len) {
	int fd = (buf[0] == 0xfd);
	int type = -1;
	unsigned i;
	struct lh5801_insn_desc desc;

	if (fd) {
		buf++;
		len--;
	}

	if (len == 0)
		return 0;

	/* Find the correct opcode */
	for (i = 0; i < ARRAY_LENGTH(lh5801_insn_descs); i++) {
		ut8 byte = *buf;
		unsigned fmt;
		unsigned ifmt_reg;

		desc = lh5801_insn_descs[i];
		fmt = desc.format;
		ifmt_reg = fmt & LH5801_IFMT_REG_MASK;

		if(!lh5801_ifmt_fd_matches(fmt, fd))
			continue;

		/* Ignore instructions referencing the register number 3. */
		if (ifmt_reg == LH5801_IFMT_RREG && (byte >> 4) % 4 == 3)
			continue;

		/* Reduce the opcode byte to the relevant bits */
		if (ifmt_reg == LH5801_IFMT_RREG)
			byte &= 0xcf;	/* xxRRxxxx */
		if (fmt & LH5801_IFMT_COND)
			byte &= 0xf1;	/* xxxxCCCx */
		if (fmt & LH5801_IFMT_BCH)
			byte &= 0xef;	/* xxxSxxxx */

		if (byte == desc.opcode) {
			type = i;
			break;
		}

		/* The short vector subroutine jump instructions require
		 * special treatment. */
		if (fmt & LH5801_IFMT_VEJ) {
			if (!(byte & 1) && byte >= 0xc0 && byte <= 0xf6) {
				type = i;
				break;
			}
		}
	}
	if (type == -1)
		return -1;

	/* fill the insn structure. */
	insn->iclass = desc.iclass;
	insn->type = type;
	insn->fd = fd;
	insn->opcode = buf[0];
	switch (LH5801_IFMT_IMMS(desc.format)) {
	case 3: insn->imm[2] = buf[3];
	case 2: insn->imm[1] = buf[2];
	case 1: insn->imm[0] = buf[1];
	}

	/* return the instruction length */
	return fd + 1 + LH5801_IFMT_IMMS(desc.format);
}

/* Print the accessed register. Buf must point to a buffer of at least eight
 * bytes. Only the return value should be used. */
static char *print_reg(char *buf, const struct lh5801_insn *insn) {
	const struct lh5801_insn_desc desc = lh5801_insn_descs[insn->type];
	unsigned regnr = (insn->opcode >> 4) & 3;
	const char names[] = "xyu";
	char *saved_buf = buf;

	/* Handle A, S, and P, before handling R */
	switch(desc.format & LH5801_IFMT_REG_MASK) {
		case LH5801_IFMT_AREG: return "a";
		case LH5801_IFMT_SREG: return "s";
		case LH5801_IFMT_PREG: return "p";
	}

	if (regnr == 3)
		return "invalid";
	else switch (LH5801_IFMT_RMODE(desc.format)) {
	case LH5801_IFMT_RFULL:
		buf[0] = names[regnr];
		buf[1] = '\0';
		break;
	case LH5801_IFMT_RLOW:
	case LH5801_IFMT_RHIGH:
		buf[0] = names[regnr];
		buf[1] = (desc.format & LH5801_IFMT_RLOW)? 'l':'h';
		buf[2] = '\0';
		break;
	case LH5801_IFMT_RMEM:
		if (desc.format & LH5801_IFMT_FD_MOD) {
			if (insn->fd)
				*(buf++) = '#';
			buf[0] = '(';
			buf[1] = names[regnr];
			buf[2] = ')';
			buf[3] = '\0';
		} else {
			return NULL;
		}
		break;
	default:
		return NULL;
	}
	return saved_buf;
}

void lh5801_print_insn(char *out, int size, const struct lh5801_insn *insn) {
	const struct lh5801_insn_class_desc *iclass =
		&lh5801_insn_class_descs[insn->iclass];
	const struct lh5801_insn_desc desc = lh5801_insn_descs[insn->type];
	const char *mnem = iclass->mnem;
	char mnembuf[4];
	char regbuf[8];

	/* Conditional instructions have special mnemonics. */
	if (desc.format & LH5801_IFMT_COND) {
		mnembuf[0] = mnem[0];	/* the first character is the same. */
		mnembuf[1] = "chzv"[(insn->opcode >> 2) % 4]; /* which flag */
		mnembuf[2] = (insn->opcode & 2)? 's':'r'; /* set or reset */
		mnembuf[3] = '\0';
		mnem = mnembuf;
	}

	/*
	 * operand print modes:
	 * IMM0:	rl/rh,		REG|LOW, REG|HIGH
	 *		r,		REG
	 *		(r),		REG|MEM  -> would MEM imply FD_MOD?
	 *		s,p		S, P
	 *		vej i		VEJ
	 * IMM1:	IMM0,i		IMM1
	 * 		a,i		ACCU
	 * IMM2:	ij (jump)
	 * 		(ij)
	 * 		s,ij	(ldi)
	 * IMM3:	(ij),k
	 */

	switch (desc.format & ~LH5801_IFMT_RMODE_MASK & ~LH5801_IFMT_COND
			& ~LH5801_IFMT_FD_MASK) {
	case LH5801_IFMT_VEJ:
		snprintf(out, size, "%s %02xh", mnem, insn->opcode);
		break;
	case LH5801_IFMT_IMM0:
		snprintf(out, size, "%s", mnem);
		break;
	case LH5801_IFMT_IMM0|LH5801_IFMT_RREG:
	case LH5801_IFMT_IMM0|LH5801_IFMT_AREG:
	case LH5801_IFMT_IMM0|LH5801_IFMT_SREG:
	case LH5801_IFMT_IMM0|LH5801_IFMT_PREG:
		snprintf(out, size, "%s %s", mnem, print_reg(regbuf, insn));
		break;
	case LH5801_IFMT_IMM1:
		snprintf(out, size, "%s %02xh", mnem, insn->imm[0]);
		break;
	case LH5801_IFMT_IMM1|LH5801_IFMT_RREG:
	case LH5801_IFMT_IMM1|LH5801_IFMT_AREG:
	case LH5801_IFMT_IMM1|LH5801_IFMT_SREG:
	case LH5801_IFMT_IMM1|LH5801_IFMT_PREG:
		snprintf(out, size, "%s %s, %02xh", mnem,
			print_reg(regbuf, insn), insn->imm[0]);
		break;
	case LH5801_IFMT_IMM1|LH5801_IFMT_BCH:
		snprintf(out, size, "%s %c%02xh", mnem,
			(insn->opcode & 0x10)? '-':'+', insn->imm[0]);
		break;
	case LH5801_IFMT_IMM2:
		if (desc.format & LH5801_IFMT_FD_MOD) {
			snprintf(out, size, "%s %s(%02x%02xh)", mnem,
				insn->fd? "#":"",
				insn->imm[0], insn->imm[1]);
		} else {
			snprintf(out, size, "%s %02x%02xh", mnem,
				insn->imm[0], insn->imm[1]);
		}
		break;
	case LH5801_IFMT_IMM3:
		if (desc.format & LH5801_IFMT_FD_MOD) {
			snprintf(out, size, "%s %s(%02x%02xh), %02xh", mnem,
				insn->fd? "#":"",
				insn->imm[0], insn->imm[1], insn->imm[2]);
		} else {
			snprintf(out,size, "imm3 invalid format");
		}
		break;
	default:
		snprintf(out, size, "%s, BUG: unknown format 0x%x -> 0x%x",
			mnem, desc.format,
			desc.format & ~LH5801_IFMT_RMODE_MASK &
			~LH5801_IFMT_COND & ~LH5801_IFMT_FD_MASK);
	}
}
