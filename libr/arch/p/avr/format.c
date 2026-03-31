/*
 * vAVRdisasm - AVR program disassembler.
 * Written by Vanya A. Sergeev - <vsergeev@gmail.com>
 * Copyright (C) 2007 Vanya A. Sergeev
 * Licensed under GPL v2 or later.
 */

#include "format.h"
#include "r_util.h"
#include "avr_disasm.h"

typedef struct {
	ut16 addr;
	const char *name;
} AvrIoReg;

static const AvrIoReg io_regs_common[] = {
	{ 0x3d, "spl" }, { 0x3e, "sph" }, { 0x3f, "sreg" }, { 0 }
};

static const AvrIoReg io_regs_atmega328p[] = {
	{ 0x03, "pinb" }, { 0x04, "ddrb" }, { 0x05, "portb" },
	{ 0x06, "pinc" }, { 0x07, "ddrc" }, { 0x08, "portc" },
	{ 0x09, "pind" }, { 0x0a, "ddrd" }, { 0x0b, "portd" },
	{ 0x15, "tifr0" }, { 0x16, "tifr1" }, { 0x17, "tifr2" },
	{ 0x18, "acsr" },
	{ 0x1b, "pcifr" }, { 0x1c, "eifr" }, { 0x1d, "eimsk" },
	{ 0x1e, "gpior0" }, { 0x1f, "eecr" },
	{ 0x20, "eedr" }, { 0x21, "eear" }, { 0x22, "eearh" },
	{ 0x23, "gtccr" }, { 0x24, "tccr0a" }, { 0x25, "tccr0b" },
	{ 0x26, "tcnt0" }, { 0x27, "otcr0a" }, { 0x28, "otcr0b" },
	{ 0x2a, "gpior1" }, { 0x2b, "gpior2" },
	{ 0x2c, "spcr" }, { 0x2d, "spsr" }, { 0x2e, "spdr" },
	{ 0x33, "smcr" }, { 0x34, "mcusr" }, { 0x35, "mcucr" },
	{ 0x37, "spmcsr" },
	{ 0 }
};

static const AvrIoReg io_regs_at90s1200[] = {
	{ 0x08, "acsr" }, { 0x10, "pind" },
	{ 0x11, "ddrd" }, { 0x12, "portd" },
	{ 0 }
};

static const char *io_reg_find(const AvrIoReg *regs, ut16 addr) {
	int i;
	for (i = 0; regs[i].name; i++) {
		if (regs[i].addr == addr) {
			return regs[i].name;
		}
	}
	return NULL;
}

static const char *avr_io_reg(const char *cpu, ut16 addr) {
	const char *name = io_reg_find (io_regs_common, addr);
	if (!name && !strcmp (cpu, "ATmega328p")) {
		name = io_reg_find (io_regs_atmega328p, addr);
	}
	if (!name && !strcmp (cpu, "AT90S1200")) {
		name = io_reg_find (io_regs_at90s1200, addr);
	}
	return name;
}

static int avr_format_operand(RArchSession *as, avrDisassembleContext *context, RStrBuf *sb, int operandNum, const disassembledInstruction di, formattingOptions fOptions) {
	if (operandNum >= AVR_MAX_NUM_OPERANDS) {
		return 0;
	}
	int op = di.operands[operandNum];
	switch (di.instruction->operandTypes[operandNum]) {
	case OPERAND_NONE:
	case OPERAND_REGISTER_GHOST:
		break;
	case OPERAND_REGISTER:
	case OPERAND_REGISTER_STARTR16:
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
	case OPERAND_REGISTER_EVEN_PAIR:
		r_strbuf_appendf (sb, "r%d", op);
		break;
	case OPERAND_DATA:
	case OPERAND_COMPLEMENTED_DATA:
		if (fOptions.options & FORMAT_OPTION_DATA_BIN) {
			char binary[9];
			int i;
			for (i = 7; i >= 0; i--) {
				binary[7 - i] = (op & (1 << i)) ? '1' : '0';
			}
			binary[8] = '\0';
			r_strbuf_appendf (sb, "0b%s", binary);
		} else if (fOptions.options & FORMAT_OPTION_DATA_DEC) {
			r_strbuf_appendf (sb, "%d", op);
		} else {
			r_strbuf_appendf (sb, "0x%02x", op);
		}
		break;
	case OPERAND_BIT:
		r_strbuf_appendf (sb, "%d", op);
		break;
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS:
		r_strbuf_appendf (sb, "0x%x", di.address + op);
		break;
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
		r_strbuf_appendf (sb, "0x%0*x", fOptions.addressFieldWidth, context->longAddress);
		break;
	case OPERAND_IO_REGISTER: {
		const char *name = avr_io_reg (r_str_get (as->config->cpu), op);
		if (name) {
			r_strbuf_append (sb, name);
		} else {
			r_strbuf_appendf (sb, "0x%x", op);
		}
		break;
	}
	case OPERAND_WORD_DATA:
		r_strbuf_appendf (sb, "0x%0*x", fOptions.addressFieldWidth, op);
		break;
	case OPERAND_DES_ROUND:
		r_strbuf_appendf (sb, "0x%02x", op);
		break;
	case OPERAND_YPQ: r_strbuf_appendf (sb, "y+%d", op); break;
	case OPERAND_ZPQ: r_strbuf_appendf (sb, "z+%d", op); break;
	case OPERAND_X: r_strbuf_append (sb, "x"); break;
	case OPERAND_XP: r_strbuf_append (sb, "x+"); break;
	case OPERAND_MX: r_strbuf_append (sb, "-x"); break;
	case OPERAND_Y: r_strbuf_append (sb, "y"); break;
	case OPERAND_YP: r_strbuf_append (sb, "y+"); break;
	case OPERAND_MY: r_strbuf_append (sb, "-y"); break;
	case OPERAND_Z: r_strbuf_append (sb, "z"); break;
	case OPERAND_ZP: r_strbuf_append (sb, "z+"); break;
	case OPERAND_MZ: r_strbuf_append (sb, "-z"); break;
	default:
		return ERROR_UNKNOWN_OPERAND;
	}
	return 0;
}

int avr_format_insn(RArchSession *as, avrDisassembleContext *context, char *out, int out_len, const disassembledInstruction di, formattingOptions fOptions) {
	if (context->status == AVR_LONG_INSTRUCTION_FOUND) {
		return 0;
	}
	int i;
	RStrBuf *sb = r_strbuf_new (di.instruction->mnemonic);
	if (di.instruction->numOperands > 0) {
		r_strbuf_append (sb, " ");
	}
	for (i = 0; i < di.instruction->numOperands; i++) {
		if (i > 0) {
			r_strbuf_append (sb, ", ");
		}
		int ret = avr_format_operand (as, context, sb, i, di, fOptions);
		if (ret < 0) {
			r_strbuf_free (sb);
			return ret;
		}
	}
	r_str_ncpy (out, r_strbuf_get (sb), out_len);
	r_strbuf_free (sb);
	return 1;
}

int parse_registerpair(const char *operand) {
	int res = -1;
	char *op = strdup (operand);
	char *save_ptr = NULL;
	char *first = r_str_tok_r (op, ":", &save_ptr);

	if (!first || strlen (first) < 2) {
		free (op);
		return -1;
	}

	char *second = r_str_tok_r (NULL, ":", &save_ptr);
	if (second && strlen (second) < 2) {
		if (first[0] == 'r' && second[0] == 'r') {
			int fnum = atoi (first + 1);
			int snum = atoi (second + 1);
			if (fnum > snum && snum >= 0 && snum <= 30) {
				res = snum / 2;
			}
		} else if (first[0] >= 'x' && first[0] <= 'z'
				&& second[0] >= 'x' && second[0] <= 'z'
				&& first[1] == 'h' && second[1] == 'l') {
			res = (2 - ('z' - first[0])) + 12;
		}
	} else {
		if (first[0] == 'r') {
			int snum = atoi (first + 1);
			if (snum >= 0 && snum <= 30) {
				res = snum / 2;
			}
		} else if (first[0] >= 'x' && first[0] <= 'z') {
			res = (2 - ('z' - first[0])) + 12;
		}
	}
	free (op);
	return res;
}
