/* radare - LGPL - Copyright 2015-2022 - condret */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "optable.h"

struct snes_asm_flags {
	ut8 M;
	ut8 X;
};

static bool snes_init(RArchSession *s) {
	r_return_val_if_fail (s && !s->data, false);
	s->data = R_NEW0 (struct snes_asm_flags);
	return s->data? true: false;
}

static bool snes_fini(RArchSession *s) {
	R_FREE (s->data);
	return true;
}

static char *snes_disass(struct snes_asm_flags snesflags, ut64 pc, const ut8 *buf, int len) {
	int M_flag = snesflags.M;
	int X_flag = snesflags.X;
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = snes_op_get_size (M_flag, X_flag, s_op);
	if (len < op_len) {
		return 0;
	}
	const char *buf_asm = "invalid";
	r_strf_buffer (64);
	switch (s_op->flags) {
	case SNES_OP_8BIT:
		buf_asm = s_op->name;
		break;
	case SNES_OP_16BIT:
		if (*buf % 0x20 == 0x10 || *buf == 0x80) { // relative branch
			buf_asm = r_strf (s_op->name, (ut32)(pc + 2 + (st8)buf[1]));
		} else {
			buf_asm = r_strf (s_op->name, buf[1]);
		}
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			buf_asm = r_strf (s_op->name, buf[1], buf[2]);
		} else if (*buf == 0x82) { // brl
			buf_asm = r_strf (s_op->name, pc + 3 + (st16)ut8p_bw(buf + 1));
		} else {
			buf_asm = r_strf (s_op->name, ut8p_bw (buf + 1));
		}
		break;
	case SNES_OP_32BIT:
		buf_asm = r_strf (s_op->name, buf[1]|buf[2]<<8|buf[3]<<16);
		break;
	case SNES_OP_IMM_M:
		if (M_flag) {
			buf_asm = r_strf ("%s #0x%02x", s_op->name, buf[1]);
		} else {
			buf_asm = r_strf ("%s #0x%04x", s_op->name, ut8p_bw (buf + 1));
		}
		break;
	case SNES_OP_IMM_X:
		if (X_flag) {
			buf_asm = r_strf ("%s #0x%02x", s_op->name, buf[1]);
		} else {
			buf_asm = r_strf ("%s #0x%04x", s_op->name, ut8p_bw (buf + 1));
		}
		break;
	}
	return strdup (buf_asm);
}

static int snes_info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 1;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		// some ops accept newline terminated strings of arbitrary len...
		return 3;
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
		return 1;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 1;
	}
	return -1;
}

static bool snes_anop(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	struct snes_asm_flags *snesflags = as->data;
	const ut64 addr = op->addr;
	const ut8 *data = op->bytes;
	const int len = op->size;

	int opsize = snes_op_get_size (snesflags->M, snesflags->X, &snes_op[data[0]]);
	op->size = opsize;
	if (opsize > len) {
		r_anal_op_set_mnemonic (op, addr, "truncated");
		op->size = 1;
		return false;
	}
	op->nopcode = 1;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = snes_disass (*snesflags, addr, data, len);
	}
	switch (data[0]) {
	case 0xea: // nop
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0xfb: // xce
		op->type = R_ANAL_OP_TYPE_XCHG;
		break;
	case 0x00: // brk
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case 0x02: // cop
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0x1b: // tcs
	case 0x3b: // tsc
	case 0x5b: // tcd
	case 0x7b: // tdc
	case 0x8a: // txa
	case 0x98: // tya
	case 0x9a: // txs
	case 0x9b: // txy
	case 0xa8: // tay
	case 0xaa: // tax
	case 0xba: // tsx
	case 0xbb: // tyx
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x48: // pha
	case 0x8b: // phb
	case 0x0b: // phd
	case 0x4b: // phk
	case 0x08: // php
	case 0xda: // phx
	case 0x5a: // phy
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case 0x68: // pla
	case 0xab: // plb
	case 0x2b: // pld
	case 0x28: // plp
	case 0xfa: // plx
	case 0x7a: // ply
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	// adc
	case 0x61: case 0x63: case 0x65: case 0x67: case 0x69: case 0x6d:
	case 0x6f: case 0x71: case 0x72: case 0x73: case 0x75: case 0x77:
	case 0x79: case 0x7d: case 0x7f:
	// inc
	case 0x1a: case 0xe6: case 0xee: case 0xf6: case 0xfe:
	case 0xe8: // inx
	case 0xc8: // iny
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	// and
	case 0x23: case 0x25: case 0x27: case 0x29: case 0x2d: case 0x2f:
	case 0x31: case 0x32: case 0x33: case 0x35: case 0x37: case 0x39:
	case 0x3d: case 0x3f:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	// bit
	case 0x24: case 0x2c: case 0x34: case 0x3c: case 0x89:
		op->type = R_ANAL_OP_TYPE_ACMP;
		break;
	// cmp
	case 0xc1: case 0xc3: case 0xc5: case 0xc7: case 0xc9: case 0xcd:
	case 0xcf: case 0xd1: case 0xd2: case 0xd3: case 0xd5: case 0xd7:
	case 0xd9: case 0xdd: case 0xdf:
	// cpx
	case 0xe0: case 0xe4: case 0xec:
	// cpy
	case 0xc0: case 0xc4: case 0xcc:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	// ora
	case 0x01: case 0x03: case 0x05: case 0x07: case 0x09: case 0x0d:
	case 0x0f: case 0x11: case 0x12: case 0x13: case 0x15: case 0x17:
	case 0x19: case 0x1d: case 0x1f:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	// eor
	case 0x41: case 0x43: case 0x45: case 0x47: case 0x49: case 0x4d:
	case 0x4f: case 0x51: case 0x52: case 0x53: case 0x55: case 0x57:
	case 0x59: case 0x5d: case 0x5f:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	// asl
	case 0x06: case 0x0a: case 0x0e: case 0x16: case 0x1e:
		op->type = R_ANAL_OP_TYPE_SAL;
		break;
	// lsr
	case 0x46: case 0x4a: case 0x4e: case 0x56: case 0x5e:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	// rol
	case 0x26: case 0x2a: case 0x2e: case 0x36: case 0x3e:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	// ror
	case 0x66: case 0x6a: case 0x6e: case 0x76: case 0x7e:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	// sei
	case 0x78:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	// sbc
	case 0xe1: case 0xe3: case 0xe5: case 0xe7: case 0xe9: case 0xed:
	case 0xef: case 0xf1: case 0xf2: case 0xf3: case 0xf5: case 0xf7:
	case 0xf9: case 0xfd: case 0xff:
	// dec
	case 0x3a: case 0xc6: case 0xce: case 0xd6: case 0xde:
	case 0xca: // dex
	case 0x88: // dey
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	// sta
	case 0x81: case 0x83: case 0x85: case 0x87: case 0x8d: case 0x8f:
	case 0x91: case 0x92: case 0x93: case 0x95: case 0x97: case 0x99:
	case 0x9d: case 0x9f:
	// stx
	case 0x86: case 0x8e: case 0x96:
	// sty
	case 0x84: case 0x8c: case 0x94:
	// stz
	case 0x64: case 0x74: case 0x9c: case 0x9e:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	// lda
	case 0xa1: case 0xa3: case 0xa5: case 0xa7: case 0xa9: case 0xad:
	case 0xaf: case 0xb1: case 0xb2: case 0xb3: case 0xb5: case 0xb7:
	case 0xb9: case 0xbd: case 0xbf:
	// ldx
	case 0xa2: case 0xa6: case 0xae: case 0xb6: case 0xbe:
	// ldy
	case 0xa0: case 0xa4: case 0xac: case 0xb4: case 0xbc:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x4c: // jmp addr
		op->eob = true;
		op->jump = (addr & 0xFF0000) | ut8p_bw (data + 1);
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x5c: // jmp long
		op->eob = true;
		op->jump = data[1] | data[2] << 8 | data[3] << 16;
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x80: // bra
		op->eob = true;
		op->jump = addr + 2 + (st8)data[1];
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x82: // brl
		op->eob = true;
		op->jump = addr + 3 + (st16)ut8p_bw (data + 1);
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x6c: // jmp (addr)
	case 0x7c: // jmp (addr,X)
	case 0xdc: // jmp [addr]
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case 0x10: // bpl
	case 0x30: // bmi
	case 0x50: // bvc
	case 0x70: // bvs
	case 0x90: // bcc
	case 0xb0: // bcs
		op->eob = true;
		op->jump = addr + 2 + (st8)data[1];
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0xd0: // bne
		op->eob = true;
		op->cond = R_ANAL_COND_NE;
		op->jump = addr + 2 + (st8)data[1];
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0xf0: // beq
		op->eob = true;
		op->cond = R_ANAL_COND_EQ;
		op->jump = addr + 2 + (st8)data[1];
		op->fail = addr + 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0x20: // jsr addr
		op->jump = (addr & 0xFF0000) | ut8p_bw (data+1);
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0x22: // jsr long
		op->jump = data[1] | data[2] << 8 | data[3] << 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xfc: // jsr (addr,X)
		op->type = R_ANAL_OP_TYPE_UCALL;
		break;
	case 0x40: // rti
	case 0x60: // rts
	case 0x6b: // rtl
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 0xc2: // rep
		if (((st8)data[1]) & 0x10) {
			snesflags->X = 0;
		}
		if (((st8)data[1]) & 0x20) {
			snesflags->M = 0;
		}
		break;
	case 0xe2: // sep
		if (((st8)data[1]) & 0x10) {
			snesflags->X = 1;
		}
		if (((st8)data[1]) & 0x20) {
			snesflags->M = 1;
		}
		break;
	}
	return true;
}

const RArchPlugin r_arch_plugin_snes = {
	.meta = {
		.name = "snes",
		.desc = "SNES analysis plugin",
		.license = "LGPL3",
		.author = "pancake",
	},
	.arch = "snes", // modified 6502 ?
	.bits = R_SYS_BITS_PACK2 (8, 16),
	.decode = snes_anop,
	.info = snes_info,
	.init = snes_init,
	.fini = snes_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_snes,
	.version = R2_VERSION
};
#endif
