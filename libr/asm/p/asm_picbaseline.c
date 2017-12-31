/* radare2 - LGPL - Copyright 2017 - thestr4ng3r */

#include <r_asm.h>
#include <r_lib.h>

typedef enum {
	PIC_BASELINE_OP_ARGS_NONE = 0,
	PIC_BASELINE_OP_ARGS_2F,
	PIC_BASELINE_OP_ARGS_3F,
	PIC_BASELINE_OP_ARGS_3K,
	PIC_BASELINE_OP_ARGS_1D_5F,
	PIC_BASELINE_OP_ARGS_5F,
	PIC_BASELINE_OP_ARGS_3B_5F,
	PIC_BASELINE_OP_ARGS_8K,
	PIC_BASELINE_OP_ARGS_9K
} PicBaselineOpArgs;

typedef struct _picbaseline_op {
	const char *mnemonic;
	PicBaselineOpArgs args;
} PicBaselineOpInfo;

typedef enum {
	PIC_BASELINE_OPCODE_NOP = 0,
	PIC_BASELINE_OPCODE_OPTION,
	PIC_BASELINE_OPCODE_SLEEP,
	PIC_BASELINE_OPCODE_CLRWDT,
	PIC_BASELINE_OPCODE_TRIS,
	PIC_BASELINE_OPCODE_MOVLB,
	PIC_BASELINE_OPCODE_RETURN,
	PIC_BASELINE_OPCODE_RETFIE,
	PIC_BASELINE_OPCODE_MOVWF,
	PIC_BASELINE_OPCODE_CLRF,
	PIC_BASELINE_OPCODE_CLRW,
	PIC_BASELINE_OPCODE_SUBWF,
	PIC_BASELINE_OPCODE_DECF,
	PIC_BASELINE_OPCODE_IORWF,
	PIC_BASELINE_OPCODE_ANDWF,
	PIC_BASELINE_OPCODE_XORWF,
	PIC_BASELINE_OPCODE_ADDWF,
	PIC_BASELINE_OPCODE_MOVF,
	PIC_BASELINE_OPCODE_COMF,
	PIC_BASELINE_OPCODE_INCF,
	PIC_BASELINE_OPCODE_DECFSZ,
	PIC_BASELINE_OPCODE_RRF,
	PIC_BASELINE_OPCODE_RLF,
	PIC_BASELINE_OPCODE_SWAPF,
	PIC_BASELINE_OPCODE_INCFSZ,
	PIC_BASELINE_OPCODE_BCF,
	PIC_BASELINE_OPCODE_BSF,
	PIC_BASELINE_OPCODE_BTFSC,
	PIC_BASELINE_OPCODE_BTFSS,
	PIC_BASELINE_OPCODE_RETLW,
	PIC_BASELINE_OPCODE_CALL,
	PIC_BASELINE_OPCODE_GOTO,
	PIC_BASELINE_OPCODE_MOVLW,
	PIC_BASELINE_OPCODE_IORLW,
	PIC_BASELINE_OPCODE_ANDLW,
	PIC_BASELINE_OPCODE_XORLW,
	PIC_BASELINE_OPCODE_INVALID
} PicBaselineOpcode;

static const PicBaselineOpInfo picbaseline_op_info[PIC_BASELINE_OPCODE_INVALID] = {
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


static PicBaselineOpcode picbaseline_get_opcode(ut16 instr) {
	if (instr & 0xf000) {
		return PIC_BASELINE_OPCODE_INVALID;
	}

	switch ((instr >> 6) & 0b111111) {
	case 0b000111:
		return PIC_BASELINE_OPCODE_ADDWF;
	case 0b000101:
		return PIC_BASELINE_OPCODE_ANDWF;
	case 0b000001:
		if (instr & 0b100000) {
			return PIC_BASELINE_OPCODE_CLRF;
		} else if ((instr & 0x11111) == 0b00000) {
			return PIC_BASELINE_OPCODE_CLRW;
		} else {
			return PIC_BASELINE_OPCODE_INVALID;
		}
	case 0b001001:
		return PIC_BASELINE_OPCODE_COMF;
	case 0b000011:
		return PIC_BASELINE_OPCODE_DECF;
	case 0b001011:
		return PIC_BASELINE_OPCODE_DECFSZ;
	case 0b001010:
		return PIC_BASELINE_OPCODE_INCF;
	case 0b001111:
		return PIC_BASELINE_OPCODE_INCFSZ;
	case 0b000100:
		return PIC_BASELINE_OPCODE_IORWF;
	case 0b001000:
		return PIC_BASELINE_OPCODE_MOVF;
	case 0b000000:
		if (instr & 0b100000) {
			return PIC_BASELINE_OPCODE_MOVWF;
		} else {
			switch (instr & 0b11111) {
			case 0b00000:
				return PIC_BASELINE_OPCODE_NOP;
			case 0b00100:
				return PIC_BASELINE_OPCODE_CLRWDT;
			case 0b00010:
				return PIC_BASELINE_OPCODE_OPTION;
			case 0b00011:
				return PIC_BASELINE_OPCODE_SLEEP;
			case 0b00001:
			case 0b00101:
			case 0b00110:
			case 0b00111:
				return PIC_BASELINE_OPCODE_TRIS;
			case 0b10000:
			case 0b10001:
			case 0b10010:
			case 0b10011:
			case 0b10100:
			case 0b10101:
			case 0b10110:
			case 0b10111:
				return PIC_BASELINE_OPCODE_MOVLB;
			case 0b11110:
				return PIC_BASELINE_OPCODE_RETURN;
			case 0b11111:
				return PIC_BASELINE_OPCODE_RETFIE;
			default:
				return PIC_BASELINE_OPCODE_INVALID;
			}
		}
	case 0b001101:
		return PIC_BASELINE_OPCODE_RLF;
	case 0b001100:
		return PIC_BASELINE_OPCODE_RRF;
	case 0b000010:
		return PIC_BASELINE_OPCODE_SUBWF;
	case 0b001110:
		return PIC_BASELINE_OPCODE_SWAPF;
	case 0b000110:
		return PIC_BASELINE_OPCODE_XORWF;
	case 0b010000:
	case 0b010001:
	case 0b010010:
	case 0b010011:
		return PIC_BASELINE_OPCODE_BCF;
	case 0b010100:
	case 0b010101:
	case 0b010110:
	case 0b010111:
		return PIC_BASELINE_OPCODE_BSF;
	case 0b011000:
	case 0b011001:
	case 0b011010:
	case 0b011011:
		return PIC_BASELINE_OPCODE_BTFSC;
	case 0b011100:
	case 0b011101:
	case 0b011110:
	case 0b011111:
		return PIC_BASELINE_OPCODE_BTFSS;
	case 0b111000:
	case 0b111001:
	case 0b111010:
	case 0b111011:
		return PIC_BASELINE_OPCODE_ANDLW;
	case 0b100100:
	case 0b100101:
	case 0b100110:
	case 0b100111:
		return PIC_BASELINE_OPCODE_CALL;
	case 0b101000:
	case 0b101001:
	case 0b101010:
	case 0b101011:
	case 0b101100:
	case 0b101101:
	case 0b101110:
	case 0b101111:
		return PIC_BASELINE_OPCODE_GOTO;
	case 0b110100:
	case 0b110101:
	case 0b110110:
	case 0b110111:
		return PIC_BASELINE_OPCODE_IORLW;
	case 0b110000:
	case 0b110001:
	case 0b110010:
	case 0b110011:
		return PIC_BASELINE_OPCODE_MOVLW;
	case 0b100000:
	case 0b100001:
	case 0b100010:
	case 0b100011:
		return PIC_BASELINE_OPCODE_RETLW;
	case 0b111100:
	case 0b111101:
	case 0b111110:
	case 0b111111:
		return PIC_BASELINE_OPCODE_XORLW;
	default:
		return PIC_BASELINE_OPCODE_INVALID;
	}
}

static int asm_picbaseline_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
#define EMIT_INVALID { \
	op->size = 1; \
	strncpy (op->buf_asm, "invalid", R_ASM_BUFSIZE); \
	return 1; \
}
	if (!b || l<2) {
		EMIT_INVALID
	}

	ut16 instr = r_read_le16 (b);
	PicBaselineOpcode opcode = picbaseline_get_opcode (instr);
	if (opcode == PIC_BASELINE_OPCODE_INVALID) {
		EMIT_INVALID
	}

	const PicBaselineOpInfo *op_info = &picbaseline_op_info[opcode];
	op->size = 2;

	switch (op_info->args) {
	case PIC_BASELINE_OP_ARGS_NONE:
		strncpy (op->buf_asm, op_info->mnemonic, R_ASM_BUFSIZE);
		break;
	case PIC_BASELINE_OP_ARGS_2F:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0b11);
		break;
	case PIC_BASELINE_OP_ARGS_3F:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0b111);
		break;
	case PIC_BASELINE_OP_ARGS_3K:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0b111);
		break;
	case PIC_BASELINE_OP_ARGS_1D_5F:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x, %c",
				  op_info->mnemonic,
				  instr & 0b11111,
				  (instr & (1 << 5)) >> 5 ? 'f' : 'w');
		break;
	case PIC_BASELINE_OP_ARGS_5F:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0b11111);
		break;
	case PIC_BASELINE_OP_ARGS_3B_5F:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x, 0x%x",
				  op_info->mnemonic,
				  instr & 0b11111,
				  (instr & (0b111 << 5)) >> 5);
		break;
	case PIC_BASELINE_OP_ARGS_8K:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0xff);
		break;
	case PIC_BASELINE_OP_ARGS_9K:
		snprintf (op->buf_asm, R_ASM_BUFSIZE + 1, "%s 0x%x",
				  op_info->mnemonic,
				  instr & 0b111111111);
		break;
	}

	return op->size;
}

RAsmPlugin r_asm_plugin_picbaseline = {
	.name = "picbaseline",
	.arch = "picbaseline",
	.bits = 8,
	.license = "LGPL3",
	.desc = "PIC Baseline (PIC10/12/16) disassembler",
	.disassemble = &asm_picbaseline_disassemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_picbaseline
};
#endif
