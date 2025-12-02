/* radare - GPL - Copyright 2002-2025 - pancake, condret, unlogic, Bas Wijnen <wijnen@debian.org>, Jan Wilmans <jw@dds.nl> */

#include <r_arch.h>
#include "z80_tab.h"

#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "asm.z80"

#ifndef R_API_I
#define R_API_I
#endif
#include "z80asm.h"
#include "z80dis.h"

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	int ilen = 0;
	ut8 data[4] = { 0 };
	if (op->size < 1) {
		return false;
	}
	memcpy (data, op->bytes, R_MIN (len, 4));
	z80_op_size (data, len, &ilen, &op->nopcode);
	if (ilen < 1) {
		return false;
	}

	op->size = ilen;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = z80dis (data, len);
	}
	switch (data[0]) {
	case 0x00:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0x03:
	case 0x04:
	case 0x0c:
	case 0x13:
	case 0x14:
	case 0x1c:
	case 0x23:
	case 0x24:
	case 0x2c:
	case 0x33:
	case 0x34:
	case 0x3c:
		op->type = R_ANAL_OP_TYPE_ADD; // INC
		break;
	case 0x09:
	case 0x19:
	case 0x29:
	case 0x39:
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0xc6:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x96:
	case 0x97:
	case 0xd6:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x22: // ld (**), hl
		op->type = R_ANAL_OP_TYPE_STORE;
		op->refptr = 2;
		op->ptr = data[1] | data[2] << 8;
		break;
	case 0x32: // ld (**), a
		op->type = R_ANAL_OP_TYPE_STORE;
		op->refptr = 1;
		op->ptr = data[1] | data[2] << 8;
		break;
	case 0x2a: // ld hl, (**)
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->refptr = 2;
		op->ptr = data[1] | data[2] << 8;
		break;
	case 0x3a: // ld a, (**)
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->refptr = 1;
		op->ptr = data[1] | data[2] << 8;
		break;
	case 0xc0:
	case 0xc8:
	case 0xd0:
	case 0xd8:
	case 0xe0:
	case 0xe8:
	case 0xf0:
	case 0xf8:
		op->type = R_ANAL_OP_TYPE_CRET;
		break;
	case 0xc9:
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
		break;
	case 0xed:
		switch (data[1]) {
		case 0x43:
		case 0x53:
		case 0x63:
		case 0x73:
			op->type = R_ANAL_OP_TYPE_STORE;
			op->refptr = 2;
			op->ptr = data[2] | data[3] << 8;
			break;
		case 0x4b:
		case 0x5b:
		case 0x6b:
		case 0x7b:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->refptr = 2;
			op->ptr = data[2] | data[3] << 8;
			break;
		case 0x45: // retn
		case 0x4d: // reti
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			break;
		}
		break;
	case 0xdd: // IX ops prefix
	case 0xfd: // IY ops prefix
		switch (data[1]) {
		case 0x22: // ld (**), ix; ld (**), iy
			op->type = R_ANAL_OP_TYPE_STORE;
			op->refptr = 2;
			op->ptr = data[2] | data[3] << 8;
			break;
		case 0x2a: // ld ix, (**); ld ix, (**)
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->refptr = 2;
			op->ptr = data[2] | data[3] << 8;
			break;
		}
		break;
	case 0x05:
	case 0x0b:
	case 0x0d:
	case 0x15:
	case 0x1b:
	case 0x1d:
	case 0x25:
	case 0x2b:
	case 0x2d:
	case 0x35:
	case 0x3b:
	case 0x3d:
		// XXXX: DEC
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0xc5:
	case 0xd5:
	case 0xe5:
	case 0xf5:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case 0xc1:
	case 0xd1:
	case 0xe1:
	case 0xf1:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	// ld from register to register
	case 0x40:
	case 0x49:
	case 0x52:
	case 0x5b:
	case 0x64:
	case 0x6d:
	case 0x7f:
		break;
	case 0x76:
		op->type = R_ANAL_OP_TYPE_TRAP; // HALT
		break;

	case 0x10: // djnz
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + (st8)data[1] + ilen;
		op->fail = addr + ilen;
		break;
	case 0x18: // jr xx
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + (st8)data[1] + ilen;
		break;
	// jr cond, xx
	case 0x20:
	case 0x28:
	case 0x30:
	case 0x38:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + ((len > 1)? (st8)data[1]: 0) + ilen;
		op->fail = addr + ilen;
		break;
	// conditional jumps
	case 0xc2:
	case 0xca:
	case 0xd2:
	case 0xda:
	case 0xe2:
	case 0xea:
	case 0xf2:
	case 0xfa:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = data[1] | data[2] << 8;
		op->fail = addr + ilen;
		break;
	case 0xc3: // jp xx
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = data[1] | (data[2] << 8);
		break;
	case 0xe9: // jp (HL)
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;

	case 0xc7: // rst 0
		op->jump = 0x00;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xcf: // rst 8
		op->jump = 0x08;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xd7: // rst 16
		op->jump = 0x10;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xdf: // rst 24
		op->jump = 0x18;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xe7: // rst 32
		op->jump = 0x20;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xef: // rst 40
		op->jump = 0x28;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xf7: // rst 48
		op->jump = 0x30;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xff: // rst 56
		op->jump = 0x38;
		op->type = R_ANAL_OP_TYPE_SWI;
		break; // condret: i think that foo resets some regs, but i'm not sure

	// conditional call
	case 0xc4: // nz
	case 0xd4: // nc
	case 0xe4: // po
	case 0xf4: // p

	case 0xcc: // z
	case 0xdc: // c
	case 0xec: // pe
	case 0xfc: // m
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->jump = (len > 2)? data[1] | data[2] << 8: 0;
		op->fail = addr + ilen;
		break;

	// call
	case 0xcd:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		op->jump = data[1] | data[2] << 8;
		break;
	case 0xcb: // the same as for gameboy
		switch (data[1] / 8) {
		case 0:
		case 2:
		case 4:
		case 6: // swap
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case 1:
		case 3:
		case 5:
		case 7:
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			op->type = R_ANAL_OP_TYPE_AND;
			break; // bit
		case 16:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 23:
			op->type = R_ANAL_OP_TYPE_XOR;
			break; // set
		case 24:
		case 25:
		case 26:
		case 27:
		case 28:
		case 29:
		case 30:
		case 31:
			op->type = R_ANAL_OP_TYPE_MOV;
			break; // res
		}
		break;
	}
	return ilen;
}

static char *regs(RArchSession *as) {
	const char *p =
		"=PC	mpc\n"
		"=SP	sp\n"
		"=SN	a\n"
		"=A0	af\n"
		"=A1	bc\n"
		"=A2	de\n"
		"=A3	hl\n"

		"gpr	mpc	.32	0	0\n"
		"gpr	pc	.16	0	0\n"
		"gpr	m	.16	2	0\n"

		"gpr	sp	.16	4	0\n"

		"gpr	af	.16	6	0\n"
		"gpr	f	.8	6	0\n"
		"gpr	a	.8	7	0\n"
		"gpr	Z	.1	.55	0\n"
		"gpr	N	.1	.54	0\n"
		"gpr	H	.1	.53	0\n"
		"gpr	C	.1	.52	0\n"

		"gpr	bc	.16	8	0\n"
		"gpr	c	.8	8	0\n"
		"gpr	b	.8	9	0\n"

		"gpr	de	.16	10	0\n"
		"gpr	e	.8	10	0\n"
		"gpr	d	.8	11	0\n"

		"gpr	hl	.16	12	0\n"
		"gpr	l	.8	12	0\n"
		"gpr	h	.8	13	0\n"

		"gpr	mbcrom	.16	14	0\n"
		"gpr	mbcram	.16	16	0\n"

		"gpr	ime	.1	18	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 3;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 1;
}

static bool encode(RArchSession *s, RAnalOp *op, ut32 mask) {
	R_RETURN_VAL_IF_FAIL (s->data, false);

	PluginData *pd = s->data;
	ut8 data[32] = { 0 };
	const int len = z80asm (pd, data, op->mnemonic);
	if (len > 0) {
		r_anal_op_set_bytes (op, op->addr, data, len);
		return true;
	}
	return false;
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	s->data = R_NEW0 (PluginData);
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_z80 = {
	.meta = {
		.name = "z80",
		.author = "pancake,condret,unlogic,Bas Wijnen,Jan Wilmans",
		.desc = "Zilog Z80 microprocessor",
		.license = "GPL-3.0-only",
	},
	.arch = "z80",
	.bits = R_SYS_BITS_PACK (16),
	.info = archinfo,
	.decode = decode,
	.encode = encode,
	.regs = regs,
	.init = init,
	.fini = fini,
#if 0
	.op = z80_anal_op,
	.opasm = z80_anal_opasm,
#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_z80,
	.version = R2_VERSION
};
#endif
