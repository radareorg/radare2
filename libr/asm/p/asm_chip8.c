/* radare - LGPL3 - Copyright 2017-2018 - maijin */

#include <r_asm.h>
#include <r_lib.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	ut16 opcode = r_read_be16 (b);
	uint8_t x = (opcode >> 8) & 0x0F;
	uint8_t y = (opcode >> 4) & 0x0F;
	uint8_t nibble = opcode & 0x0F;
	uint16_t nnn = opcode & 0x0FFF;
	uint8_t kk = opcode & 0xFF;
	const char *buf_asm = "invalid";
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00E0) {
			buf_asm = "cls";
		} else if (opcode == 0x00EE) {
			buf_asm = "ret";
		} else if ((opcode & 0xFFF0) == 0x00C0) {
			buf_asm = sdb_fmt ("scd 0x%01x", nibble);
		} else if (opcode == 0x00FB) {
			buf_asm = "scr";
		} else if (opcode == 0x00FC) {
			buf_asm = "scl";
		} else if (opcode == 0x00FD) {
			buf_asm = "exit";
		} else if (opcode == 0x00FE) {
			buf_asm = "low";
		} else if (opcode == 0x00FF) {
			buf_asm = "high";
		}
		break;
	case 0x1000: buf_asm = sdb_fmt ("jp 0x%03x", nnn); break;
	case 0x2000: buf_asm = sdb_fmt ("call 0x%03x", nnn); break;
	case 0x3000: buf_asm = sdb_fmt ("se v%1x, 0x%02x", x, kk); break;
	case 0x4000: buf_asm = sdb_fmt ("sne v%1x, 0x%02x", x, kk); break;
	case 0x5000: buf_asm = sdb_fmt ("se v%1x, v%1x", x, y); break;
	case 0x6000: buf_asm = sdb_fmt ("ld v%1x, 0x%02x", x, kk); break;
	case 0x7000: buf_asm = sdb_fmt ("add v%1x, 0x%02x", x, kk); break;
	case 0x8000: {
		switch (nibble) {
		case 0x0: buf_asm = sdb_fmt ("ld v%1x, v%1x", x, y); break;
		case 0x1: buf_asm = sdb_fmt ("or v%1x, v%1x", x, y); break;
		case 0x2: buf_asm = sdb_fmt ("and v%1x, v%1x", x, y); break;
		case 0x3: buf_asm = sdb_fmt ("xor v%1x, v%1x", x, y); break;
		case 0x4: buf_asm = sdb_fmt ("add v%1x, v%1x", x, y); break;
		case 0x5: buf_asm = sdb_fmt ("sub v%1x, v%1x", x, y); break;
		case 0x6: buf_asm = sdb_fmt ("shr v%1x, v%1x", x, y); break;
		case 0x7: buf_asm = sdb_fmt ("subn v%1x, v%1x", x, y); break;
		case 0xE: buf_asm = sdb_fmt ("shl v%1x, v%1x", x, y); break;
		}
		break;
	}
	case 0x9000: buf_asm = sdb_fmt ("sne v%1x, v%1x", x, y); break;
	case 0xA000: buf_asm = sdb_fmt ("ld i, 0x%03x", nnn); break;
	case 0xB000: buf_asm = sdb_fmt ("jp v0, 0x%03x", nnn); break;
	case 0xC000: buf_asm = sdb_fmt ("rnd v%1x, 0x%02x", x, kk); break;
	case 0xD000: buf_asm = sdb_fmt ("drw v%1x, v%1x, 0x%01x", x, y, nibble); break;
	case 0xE000: {
		if (kk == 0x9E) {
			buf_asm = sdb_fmt ("skp v%1x", x);
		} else if (kk == 0xA1) {
			buf_asm = sdb_fmt ("sknp v%1x", x);
		}
		break;
	}
	case 0xF000: {
		switch (kk) {
		case 0x07: buf_asm = sdb_fmt ("ld v%1x, dt", x); break;
		case 0x0A: buf_asm = sdb_fmt ("ld v%1x, k", x); break;
		case 0x15: buf_asm = sdb_fmt ("ld dt, v%1x", x); break;
		case 0x18: buf_asm = sdb_fmt ("ld st, v%1x", x); break;
		case 0x1E: buf_asm = sdb_fmt ("add i, v%1x", x); break;
		case 0x29: buf_asm = sdb_fmt ("ld f, v%1x", x); break;
		case 0x33: buf_asm = sdb_fmt ("ld b, v%1x", x); break;
		case 0x55: buf_asm = sdb_fmt ("ld [i], v%1x", x); break;
		case 0x65: buf_asm = sdb_fmt ("ld v%1x, [i]", x); break;
		case 0x30: buf_asm = sdb_fmt ("ld hf, v%1x", x); break;
		case 0x75: buf_asm = sdb_fmt ("ld r, v%1x", x); break;
		case 0x85: buf_asm = sdb_fmt ("ld v%1x, r", x); break;
		}
		break;
	}
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_chip8,
	.version = R2_VERSION
};
#endif
