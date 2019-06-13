/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
				2013 - condret		*/

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/z80/z80_tab.h"

static void z80_op_size(const ut8 *data, int len, int *size, int *size_prefix) {
	int type = 0;
	if (len <1) {
		return;
	}
	switch (data[0]) {
	case 0xed:
		if (len > 1) {
			int idx = z80_ed_branch_index_res (data[1]);
			type = ed[idx].type;
		}
		break;
	case 0xcb:
		type = Z80_OP16;
		break;
	case 0xdd:
		if (len >1) {
			type = dd[z80_fddd_branch_index_res(data[1])].type;
		}
		break;
	case 0xfd:
		if (len > 1) {
			type = fd[z80_fddd_branch_index_res(data[1])].type;
		}
		break;
	default:
		type = z80_op[data[0]].type;
		break;
	}

	if (type & Z80_OP8) {
		*size_prefix = 1;
	} else if (type & Z80_OP16) {
		*size_prefix = 2;
	} else if (type & Z80_OP24) {
		*size_prefix = 3;
	}

	if (type & Z80_ARG16) {
		*size = *size_prefix + 2;
	} else if (type & Z80_ARG8) {
		*size = *size_prefix + 1;
	} else {
		*size = *size_prefix;
	}
}

static int z80_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	int ilen = 0;
	z80_op_size (data, len, &ilen, &op->nopcode);

	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->size = ilen;
	op->type = R_ANAL_OP_TYPE_UNK;

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
		switch(data[1]) {
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
		case 0x45:	//retn
		case 0x4d:	//reti
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
		op->jump = addr + (st8)data[1] + ilen ;
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
		op->jump = addr + ((len>1)? (st8)data[1]:0) + ilen;
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
		op->jump = (len > 2)? data[1] | data[2] << 8: 0;
		op->fail = addr + ilen;
		break;
	case 0xc3: // jp xx
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (len > 2)? data[1] | data[2] << 8: 0;
		break;
	case 0xe9: // jp (HL)
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;

	case 0xc7:				//rst 0
		op->jump = 0x00;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xcf:				//rst 8
		op->jump = 0x08;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xd7:				//rst 16
		op->jump = 0x10;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xdf:				//rst 24
		op->jump = 0x18;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xe7:				//rst 32
		op->jump = 0x20;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xef:				//rst 40
		op->jump = 0x28;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xf7:				//rst 48
		op->jump = 0x30;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xff:				//rst 56
		op->jump = 0x38;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;				// condret: i think that foo resets some regs, but i'm not sure

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
		op->jump = (len>2)? data[1] | data[2] << 8: 0;
		op->fail = addr + ilen;
		break;

	// call
	case 0xcd:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		op->jump = data[1] | data[2] << 8;
		break;
	case 0xcb:			//the same as for gameboy
		switch(data[1]/8) {
		case 0:
		case 2:
		case 4:
		case 6:				//swap
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
			break;			//bit
		case 16:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 23:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;			//set
		case 24:
		case 25:
		case 26:
		case 27:
		case 28:
		case 29:
		case 30:
		case 31:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;			//res
		}
		break;
	}
	return ilen;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	mpc\n"
		"=SP	sp\n"
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
	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	return 1;
}

RAnalPlugin r_anal_plugin_z80 = {
	.name = "z80",
	.arch = "z80",
	.license = "LGPL3",
	.bits = 16,
	.set_reg_profile = &set_reg_profile,
	.desc = "Z80 CPU code analysis plugin",
	.archinfo = archinfo,
	.op = &z80_anal_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_z80,
	.version = R2_VERSION
};
#endif
