/* radare - LGPL3 - Copyright 2017 - maijin */

#include <r_asm.h>
#include <r_lib.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	ut16 opcode = r_read_be16 (b);
	uint8_t x = (opcode >> 8) & 0x0F;
	uint8_t y = (opcode >> 4) & 0x0F;
	uint8_t nibble = opcode & 0x0F;
	uint16_t nnn = opcode & 0x0FFF;
	uint8_t kk = opcode & 0xFF;
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00E0) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "cls");
		} else if (opcode == 0x00EE) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "ret");
		} else if ((opcode & 0xFFF0) == 0x00C0) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "scd  0x%01x", nibble);
		} else if (opcode == 0x00FB) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "scr");
		} else if (opcode == 0x00FC) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "scl");
		} else if (opcode == 0x00FD) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "exit");
		} else if (opcode == 0x00FE) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "low");
		} else if (opcode == 0x00FF) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "high");
		}
		break;
	case 0x1000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "jp 0x%03x", nnn); break;
	case 0x2000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "call 0x%03x", nnn); break;
	case 0x3000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "se v%1x, 0x%02x", x, kk); break;
	case 0x4000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "sne v%1x, 0x%02x", x, kk); break;
	case 0x5000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "se v%1x, v%1x", x, y); break;
	case 0x6000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, 0x%02x", x, kk); break;
	case 0x7000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "add v%1x, 0x%02x", x, kk); break;
	case 0x8000: {
		switch (nibble) {
		case 0x0: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, v%1x", x, y); break;
		case 0x1: snprintf (op->buf_asm, R_ASM_BUFSIZE, "or v%1x, v%1x", x, y); break;
		case 0x2: snprintf (op->buf_asm, R_ASM_BUFSIZE, "and v%1x, v%1x", x, y); break;
		case 0x3: snprintf (op->buf_asm, R_ASM_BUFSIZE, "xor v%1x, v%1x", x, y); break;
		case 0x4: snprintf (op->buf_asm, R_ASM_BUFSIZE, "add v%1x, v%1x", x, y); break;
		case 0x5: snprintf (op->buf_asm, R_ASM_BUFSIZE, "sub v%1x, v%1x", x, y); break;
		case 0x6: snprintf (op->buf_asm, R_ASM_BUFSIZE, "shr v%1x, v%1x", x, y); break;
		case 0x7: snprintf (op->buf_asm, R_ASM_BUFSIZE, "subn v%1x, v%1x", x, y); break;
		case 0xE: snprintf (op->buf_asm, R_ASM_BUFSIZE, "shl v%1x, v%1x", x, y); break;
		}
	} break;
	case 0x9000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "sne v%1x, v%1x", x, y); break;
	case 0xA000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld i, 0x%03x", nnn); break;
	case 0xB000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "jp v0, 0x%03x", nnn); break;
	case 0xC000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "rnd v%1x, 0x%02x", x, kk); break;
	case 0xD000: snprintf (op->buf_asm, R_ASM_BUFSIZE, "drw v%1x, v%1x, 0x%01x", x, y, nibble); break;
	case 0xE000: {
		if (kk == 0x9E) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "skp v%1x", x);
		} else if (kk == 0xA1) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "sknp v%1x", x);
		}
	} break;
	case 0xF000: {
		switch (kk) {
		case 0x07: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, dt", x); break;
		case 0x0A: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, k", x); break;
		case 0x15: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld dt, v%1x", x); break;
		case 0x18: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld st, v%1x", x); break;
		case 0x1E: snprintf (op->buf_asm, R_ASM_BUFSIZE, "add i, v%1x", x); break;
		case 0x29: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld f, v%1x", x); break;
		case 0x33: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld b, v%1x", x); break;
		case 0x55: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld [i], v%1x", x); break;
		case 0x65: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, [i]", x); break;
		case 0x30: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld hf, v%1x", x); break;
		case 0x75: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld r, v%1x", x); break;
		case 0x85: snprintf (op->buf_asm, R_ASM_BUFSIZE, "ld v%1x, r", x); break;
		}
	} break;
	}
	op->size = 2;
	return op->size;
}

RAsmPlugin r_asm_plugin_chip8 = {
	.name = "chip8",
	.arch = "chip8",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Chip8 disassembler",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_chip8
		.version = R2_VERSION
};
#endif
