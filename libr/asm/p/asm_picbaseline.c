/* radare2 - LGPL - Copyright 2017 - thestr4ng3r */

#include <r_asm.h>
#include <r_lib.h>

static int asm_picbaseline_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
#define EMIT_INVALID { \
	op->size = 1; \
	strncpy (op->buf_asm, "invalid", R_ASM_BUFSIZE); \
	return 1; \
}
	if (!b || l<2) {
		EMIT_INVALID
	}

	ut16 instr = r_read_le16(b);
	op->size = 2;

	//instr &= 0xfff;
	if (instr & 0xf000) {
		EMIT_INVALID
	}


	switch ((instr >> 6) & 0b111111) {
		case 0b000111:
			strncpy (op->buf_asm, "addwf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000101:
			strncpy (op->buf_asm, "andwf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000001:
			if (instr & 0b100000) {
				strncpy (op->buf_asm, "clrf f", R_ASM_BUFSIZE);
			} else if ((instr & 0x11111) == 0b11111) {
				strncpy (op->buf_asm, "clrw", R_ASM_BUFSIZE);
			} else {
				EMIT_INVALID
			}
			break;
		case 0b001001:
			strncpy (op->buf_asm, "comf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000011:
			strncpy (op->buf_asm, "decf f, d", R_ASM_BUFSIZE);
			break;
		case 0b001011:
			strncpy (op->buf_asm, "decfsz f, d", R_ASM_BUFSIZE);
			break;
		case 0b001010:
			strncpy (op->buf_asm, "incf f, d", R_ASM_BUFSIZE);
			break;
		case 0b001111:
			strncpy (op->buf_asm, "incf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000100:
			strncpy (op->buf_asm, "iorwf f, d", R_ASM_BUFSIZE);
			break;
		case 0b001000:
			strncpy (op->buf_asm, "movf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000000:
			if (instr & 0b100000) {
				strncpy (op->buf_asm, "movwf f", R_ASM_BUFSIZE);
			} else {
				switch (instr & 0b11111) {
					case 0b00000:
						strncpy (op->buf_asm, "nop", R_ASM_BUFSIZE);
						break;
					case 0b00100:
						strncpy (op->buf_asm, "clrwdt", R_ASM_BUFSIZE);
						break;
					case 0b00010:
						strncpy (op->buf_asm, "option", R_ASM_BUFSIZE);
						break;
					case 0b00011:
						strncpy (op->buf_asm, "sleep", R_ASM_BUFSIZE);
						break;
					case 0b00101:
					case 0b00110:
					case 0b00111:
						strncpy (op->buf_asm, "tris f", R_ASM_BUFSIZE);
						break;
					default:
						EMIT_INVALID
					break;
				}
			}
			break;
		case 0b001101:
			strncpy (op->buf_asm, "rlf f, d", R_ASM_BUFSIZE);
			break;
		case 0b001100:
			strncpy (op->buf_asm, "rrf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000010:
			strncpy (op->buf_asm, "subwf f, d", R_ASM_BUFSIZE);
			break;
		case 0b001110:
			strncpy (op->buf_asm, "swapf f, d", R_ASM_BUFSIZE);
			break;
		case 0b000110:
			strncpy (op->buf_asm, "xorwf f, d", R_ASM_BUFSIZE);
			break;
		case 0b010000:
		case 0b010001:
		case 0b010010:
		case 0b010011:
			strncpy (op->buf_asm, "bcf f, b", R_ASM_BUFSIZE);
			break;
		case 0b010100:
		case 0b010101:
		case 0b010110:
		case 0b010111:
			strncpy (op->buf_asm, "bsf f, b", R_ASM_BUFSIZE);
			break;
		case 0b011000:
		case 0b011001:
		case 0b011010:
		case 0b011011:
			strncpy (op->buf_asm, "btfsc f, b", R_ASM_BUFSIZE);
			break;
		case 0b011100:
		case 0b011101:
		case 0b011110:
		case 0b011111:
			strncpy (op->buf_asm, "btfss f, b", R_ASM_BUFSIZE);
			break;
		case 0b111000:
		case 0b111001:
		case 0b111010:
		case 0b111011:
			strncpy (op->buf_asm, "addlw k", R_ASM_BUFSIZE);
			break;
		case 0b100100:
		case 0b100101:
		case 0b100110:
		case 0b100111:
			strncpy (op->buf_asm, "call k", R_ASM_BUFSIZE);
			break;
		case 0b101000:
		case 0b101001:
		case 0b101010:
		case 0b101011:
		case 0b101100:
		case 0b101101:
		case 0b101110:
		case 0b101111:
			strncpy (op->buf_asm, "goto k", R_ASM_BUFSIZE);
			break;
		case 0b110100:
		case 0b110101:
		case 0b110110:
		case 0b110111:
			strncpy (op->buf_asm, "iorlw k", R_ASM_BUFSIZE);
			break;
		case 0b110000:
		case 0b110001:
		case 0b110010:
		case 0b110011:
			strncpy (op->buf_asm, "movlw k", R_ASM_BUFSIZE);
			break;
		case 0b100000:
		case 0b100001:
		case 0b100010:
		case 0b100011:
			strncpy (op->buf_asm, "retlw k", R_ASM_BUFSIZE);
			break;
		case 0b111100:
		case 0b111101:
		case 0b111110:
		case 0b111111:
			strncpy (op->buf_asm, "xorlw k", R_ASM_BUFSIZE);
			break;
		default:
			EMIT_INVALID
			break;
	}

	return op->size;

#undef EMIT_INVALID
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
