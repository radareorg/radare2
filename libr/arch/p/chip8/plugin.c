/* radare - LGPL-3.0-only - Copyright 2017-2024 - maijin, pancake */

#include <r_arch.h>

static bool chip8_anop(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	char fmtstr[128];
#define fmt(x,...) fmtstr,snprintf (fmtstr, sizeof (fmtstr), x, __VA_ARGS__)
	const ut64 addr = op->addr;
	if (op->size < 2) {
		return -1;
	}

	ut16 opcode = r_read_be16 (op->bytes);
	uint8_t x = (opcode >> 8) & 0x0F;
	uint8_t y = (opcode >> 4) & 0x0F;
	uint8_t nibble = opcode & 0x0F;
	uint16_t nnn = opcode & 0x0FFF;
	uint8_t kk = opcode & 0xFF;
	op->size = 2;
	op->type = R_ANAL_OP_TYPE_UNK;
	const char *buf_asm = "invalid";
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00E0) {
			buf_asm = "cls";
		} else if (opcode == 0x00EE) {
			op->type = R_ANAL_OP_TYPE_RET;
			buf_asm = "ret";
		} else if ((opcode & 0xFFF0) == 0x00C0) {
			buf_asm = fmt ("scd 0x%01x", nibble);
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
	case 0x1000:
		buf_asm = fmt ("jp 0x%03x", nnn);
		op->jump = nnn;
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x2000:
		op->type = R_ANAL_OP_TYPE_CALL;
		buf_asm = fmt ("call 0x%03x", nnn);
		op->jump = nnn;
		op->fail = addr + op->size;
		break;
	case 0x3000:
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->jump = addr + (op->size * 2);
		op->fail = addr + op->size;
		buf_asm = fmt ("se v%1x, 0x%02x", x, kk);
		break;
	case 0x4000:
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->jump = addr + (op->size * 2);
		op->fail = addr + op->size;
		buf_asm = fmt ("sne v%1x, 0x%02x", x, kk);
		break;
	case 0x5000:
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->jump = addr + op->size * 2;
		op->fail = addr + op->size;
		buf_asm = fmt ("se v%1x, v%1x", x, y);
		break;
	case 0x6000:
		op->type = R_ANAL_OP_TYPE_MOV;
		buf_asm = fmt ("ld v%1x, 0x%02x", x, kk);
		break;
	case 0x7000:
		op->type = R_ANAL_OP_TYPE_ADD;
		buf_asm = fmt ("add v%1x, 0x%02x", x, kk);
		break;
	case 0x8000:
		switch (nibble) {
		case 0x0:
			op->type = R_ANAL_OP_TYPE_MOV;
			buf_asm = fmt ("ld v%1x, v%1x", x, y);
			break;
		case 0x1:
			buf_asm = fmt ("or v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 0x2:
			buf_asm = fmt ("and v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0x3:
			buf_asm = fmt ("xor v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0x4:
			buf_asm = fmt ("add v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x5:
			buf_asm = fmt ("sub v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0x6:
			buf_asm = fmt ("shr v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case 0x7:
			buf_asm = fmt ("subn v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0xE:
			buf_asm = fmt ("shl v%1x, v%1x", x, y);
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		}
		break;
	case 0x9000:
		buf_asm = fmt ("sne v%1x, v%1x", x, y);
		if (nibble == 0) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->jump = addr + (op->size * 2);
			op->fail = addr + op->size;
		}
		break;
	case 0xA000:
		op->type = R_ANAL_OP_TYPE_MOV;
		buf_asm = fmt ("ld i, 0x%03x", nnn);
		break;
	case 0xB000:
		op->type = R_ANAL_OP_TYPE_JMP;
		/* FIXME: this is wrong as op->jump depends on register V0 */
		op->jump = nnn;
		buf_asm = fmt ("jp v0, 0x%03x", nnn);
		break;
	case 0xC000:
		buf_asm = fmt ("rnd v%1x, 0x%02x", x, kk);
		break;
	case 0xD000:
		buf_asm = fmt ("drw v%1x, v%1x, 0x%01x", x, y, nibble);
		break;
	case 0xE000:
		if (kk == 0x9E) {
			buf_asm = fmt ("skp v%1x", x);
		} else if (kk == 0xA1) {
			buf_asm = fmt ("sknp v%1x", x);
		}
		if (kk == 0x9E || kk == 0xA1) {
			// r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, "KEYPAD");
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + (op->size * 2);
			op->fail = addr + op->size;
		}
		break;
	case 0xF000:
		switch (kk) {
		case 0x07:
			op->type = R_ANAL_OP_TYPE_MOV;
			buf_asm = fmt ("ld v%1x, dt", x);
			break;
		case 0x0A:
			// r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, "KEYPAD");
			op->type = R_ANAL_OP_TYPE_MOV;
			buf_asm = fmt ("ld v%1x, k", x);
			break;
		case 0x15:
			op->type = R_ANAL_OP_TYPE_MOV;
			buf_asm = fmt ("ld dt, v%1x", x);
			break;
		case 0x18:
			op->type = R_ANAL_OP_TYPE_MOV;
			buf_asm = fmt ("ld st, v%1x", x);
			break;
		case 0x1E:
			op->type = R_ANAL_OP_TYPE_ADD;
			buf_asm = fmt ("add i, v%1x", x);
			break;
		case 0x29:
			op->type = R_ANAL_OP_TYPE_LOAD;
			buf_asm = fmt ("ld f, v%1x", x);
			break;
		case 0x30:
			buf_asm = fmt ("ld hf, v%1x", x);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x33:
			buf_asm = fmt ("ld b, v%1x", x);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x55:
			buf_asm = fmt ("ld [i], v%1x", x);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x65:
			buf_asm = fmt ("ld v%1x, [i]", x);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x75:
			buf_asm = fmt ("ld r, v%1x", x);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x85:
			buf_asm = fmt ("ld v%1x, r", x);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		}
		break;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (buf_asm);
	}
	return true;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MAXOP_SIZE:
		return 2;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
	}
	return 1; /* :D */
}

const RArchPlugin r_arch_plugin_chip8 = {
	.meta = {
		.name = "chip8",
		.author = "maijin",
		.desc = "CHIP-8 virtual CPU",
		.license = "LGPL-3.0-only",
	},
	.arch = "chip8",
	.info = archinfo,
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = &chip8_anop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_chip8,
	.version = R2_VERSION
};
#endif
