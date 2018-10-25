/* radare2 - LGPL - Copyright 2018 - thestr4ng3r */

#include "pic_baseline.h"

static const PicBaselineOpInfo pic_baseline_op_info[PIC_BASELINE_OPCODE_INVALID] = {
		{ "nop", PIC_BASELINE_OP_ARGS_NONE },
		{ "option", PIC_BASELINE_OP_ARGS_NONE },
		{ "sleep", PIC_BASELINE_OP_ARGS_NONE },
		{ "clrwdt", PIC_BASELINE_OP_ARGS_NONE },
		{ "tris", PIC_BASELINE_OP_ARGS_3F },
		{ "movlb", PIC_BASELINE_OP_ARGS_3K },
		{ "return", PIC_BASELINE_OP_ARGS_NONE },
		{ "retfie", PIC_BASELINE_OP_ARGS_NONE },
		{ "movwf", PIC_BASELINE_OP_ARGS_5F },
		{ "clrf", PIC_BASELINE_OP_ARGS_5F },
		{ "clrw", PIC_BASELINE_OP_ARGS_NONE },
		{ "subwf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "decf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "iorwf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "andwf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "xorwf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "andwf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "movf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "comf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "incf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "decfsz", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "rrf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "rlf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "swapf", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "incfsz", PIC_BASELINE_OP_ARGS_1D_5F },
		{ "bcf", PIC_BASELINE_OP_ARGS_3B_5F },
		{ "bsf", PIC_BASELINE_OP_ARGS_3B_5F },
		{ "btfsc", PIC_BASELINE_OP_ARGS_3B_5F },
		{ "btfss", PIC_BASELINE_OP_ARGS_3B_5F },
		{ "retlw", PIC_BASELINE_OP_ARGS_8K },
		{ "call", PIC_BASELINE_OP_ARGS_8K },
		{ "goto", PIC_BASELINE_OP_ARGS_9K },
		{ "movlw", PIC_BASELINE_OP_ARGS_8K },
		{ "iorlw", PIC_BASELINE_OP_ARGS_8K },
		{ "andlw", PIC_BASELINE_OP_ARGS_8K },
		{ "xorlw", PIC_BASELINE_OP_ARGS_8K }
};

PicBaselineOpcode pic_baseline_get_opcode(ut16 instr) {
	if (instr & 0xf000) {
		return PIC_BASELINE_OPCODE_INVALID;
	}

	switch ((instr >> 6) & 0x3f) { // first 6 bits
	case 0x7: // 0b000111
		return PIC_BASELINE_OPCODE_ADDWF;
	case 0x5: // 0b000101
		return PIC_BASELINE_OPCODE_ANDWF;
	case 0x1: // 0b000001
		if (instr & (1 << 5)) {
			return PIC_BASELINE_OPCODE_CLRF;
		}
		if ((instr & 0x1f) == 0) { // last 5 bits
			return PIC_BASELINE_OPCODE_CLRW;
		}
		return PIC_BASELINE_OPCODE_INVALID;
	case 0x9: // 0b001001
		return PIC_BASELINE_OPCODE_COMF;
	case 0x3: // 0b000011
		return PIC_BASELINE_OPCODE_DECF;
	case 0xb: // 0b001011
		return PIC_BASELINE_OPCODE_DECFSZ;
	case 0xa: // 0b001010
		return PIC_BASELINE_OPCODE_INCF;
	case 0xf: // 0b001111
		return PIC_BASELINE_OPCODE_INCFSZ;
	case 0x4: // 0b000100
		return PIC_BASELINE_OPCODE_IORWF;
	case 0x8: // 0b001000
		return PIC_BASELINE_OPCODE_MOVF;
	case 0x0:
		if (instr & (1 << 5)) {
			return PIC_BASELINE_OPCODE_MOVWF;
		} else {
			switch (instr & 0x1f) { // last 5 bits
			case 0x0: // 0b00000
				return PIC_BASELINE_OPCODE_NOP;
			case 0x4: // 0b00100
				return PIC_BASELINE_OPCODE_CLRWDT;
			case 0x2: // 0b00010
				return PIC_BASELINE_OPCODE_OPTION;
			case 0x3: // 0b00011
				return PIC_BASELINE_OPCODE_SLEEP;
			case 0x1: // 0b00001
			case 0x5: // 0b00101
			case 0x6: // 0b00110
			case 0x7: // 0b00111
				return PIC_BASELINE_OPCODE_TRIS;
			case 0x10: // 0b10000
			case 0x11: // 0b10001
			case 0x12: // 0b10010
			case 0x13: // 0b10011
			case 0x14: // 0b10100
			case 0x15: // 0b10101
			case 0x16: // 0b10110
			case 0x17: // 0b10111
				return PIC_BASELINE_OPCODE_MOVLB;
			case 0x1e: // 0b11110
				return PIC_BASELINE_OPCODE_RETURN;
			case 0x1f: // 0b11111
				return PIC_BASELINE_OPCODE_RETFIE;
			default:
				return PIC_BASELINE_OPCODE_INVALID;
			}
		}
	case 0xd: // 0b001101
		return PIC_BASELINE_OPCODE_RLF;
	case 0xc: // 0b001100
		return PIC_BASELINE_OPCODE_RRF;
	case 0x2: // 0b000010
		return PIC_BASELINE_OPCODE_SUBWF;
	case 0xe: // 0b001110
		return PIC_BASELINE_OPCODE_SWAPF;
	case 0x6: // 0b000110
		return PIC_BASELINE_OPCODE_XORWF;
	case 0x10: // 0b010000
	case 0x11: // 0b010001
	case 0x12: // 0b010010
	case 0x13: // 0b010011
		return PIC_BASELINE_OPCODE_BCF;
	case 0x14: // 0b010100
	case 0x15: // 0b010101
	case 0x16: // 0b010110
	case 0x17: // 0b010111
		return PIC_BASELINE_OPCODE_BSF;
	case 0x18: // 0b011000
	case 0x19: // 0b011001
	case 0x1a: // 0b011010
	case 0x1b: // 0b011011
		return PIC_BASELINE_OPCODE_BTFSC;
	case 0x1c: // 0b011100
	case 0x1d: // 0b011101
	case 0x1e: // 0b011110
	case 0x1f: // 0b011111
		return PIC_BASELINE_OPCODE_BTFSS;
	case 0x38: // 0b111000
	case 0x39: // 0b111001
	case 0x3a: // 0b111010
	case 0x3b: // 0b111011
		return PIC_BASELINE_OPCODE_ANDLW;
	case 0x24: // 0b100100
	case 0x25: // 0b100101
	case 0x26: // 0b100110
	case 0x27: // 0b100111
		return PIC_BASELINE_OPCODE_CALL;
	case 0x28: // 0b101000
	case 0x29: // 0b101001
	case 0x2a: // 0b101010
	case 0x2b: // 0b101011
	case 0x2c: // 0b101100
	case 0x2d: // 0b101101
	case 0x2e: // 0b101110
	case 0x2f: // 0b101111
		return PIC_BASELINE_OPCODE_GOTO;
	case 0x34: // 0b110100
	case 0x35: // 0b110101
	case 0x36: // 0b110110
	case 0x37: // 0b110111
		return PIC_BASELINE_OPCODE_IORLW;
	case 0x30: // 0b110000
	case 0x31: // 0b110001
	case 0x32: // 0b110010
	case 0x33: // 0b110011
		return PIC_BASELINE_OPCODE_MOVLW;
	case 0x20: // 0b100000
	case 0x21: // 0b100001
	case 0x22: // 0b100010
	case 0x23: // 0b100011
		return PIC_BASELINE_OPCODE_RETLW;
	case 0x3c: // 0b111100
	case 0x3d: // 0b111101
	case 0x3e: // 0b111110
	case 0x3f: // 0b111111
		return PIC_BASELINE_OPCODE_XORLW;
	default:
		return PIC_BASELINE_OPCODE_INVALID;
	}
}


const PicBaselineOpInfo *pic_baseline_get_op_info(PicBaselineOpcode opcode) {
	if (opcode >= PIC_BASELINE_OPCODE_INVALID) {
		return NULL;
	}
	return &pic_baseline_op_info[opcode];
}


int pic_baseline_disassemble(RAsmOp *op, char *opbuf, const ut8 *b, int l) {
#define EMIT_INVALID { \
	op->size = 1; \
	strcpy (opbuf, "invalid"); \
	return 1; \
}
	if (!b || l < 2) {
		EMIT_INVALID
	}

	ut16 instr = r_read_le16 (b);
	PicBaselineOpcode opcode = pic_baseline_get_opcode (instr);
	if (opcode == PIC_BASELINE_OPCODE_INVALID) {
		EMIT_INVALID
	}

	const PicBaselineOpInfo *op_info = pic_baseline_get_op_info(opcode);
	if (!op_info) {
		EMIT_INVALID
	}

#undef EMIT_INVALID

	op->size = 2;

	const char *buf_asm = "invalid";
	switch (op_info->args) {
	case PIC_BASELINE_OP_ARGS_NONE:
		buf_asm = op_info->mnemonic;
		break;
	case PIC_BASELINE_OP_ARGS_2F:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_2F_MASK_F);
		break;
	case PIC_BASELINE_OP_ARGS_3F:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_3F_MASK_F);
		break;
	case PIC_BASELINE_OP_ARGS_3K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_3K_MASK_K);
		break;
	case PIC_BASELINE_OP_ARGS_1D_5F:
		buf_asm = sdb_fmt ("%s 0x%x, %c", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_1D_5F_MASK_F,
				  (instr & PIC_BASELINE_OP_ARGS_1D_5F_MASK_D) >> 5 ? 'f' : 'w');
		break;
	case PIC_BASELINE_OP_ARGS_5F:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_5F_MASK_F);
		break;
	case PIC_BASELINE_OP_ARGS_3B_5F:
		buf_asm = sdb_fmt ("%s 0x%x, 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_3B_5F_MASK_F,
				  (instr & PIC_BASELINE_OP_ARGS_3B_5F_MASK_B) >> 5);
		break;
	case PIC_BASELINE_OP_ARGS_8K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_8K_MASK_K);
		break;
	case PIC_BASELINE_OP_ARGS_9K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_BASELINE_OP_ARGS_9K_MASK_K);
		break;
	}
	strcpy (opbuf, buf_asm);

	return op->size;
}
