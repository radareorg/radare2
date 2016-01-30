/* radare2 - LGPL - Copyright 2016 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>


static int xtensa_length(const ut8 *insn) {
	static int length_table[16] = { 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 8, 8 };
	return length_table[*insn & 0xf];
}

static ut64 decodeRelative (ut64 addr, const ut8 *buf) {
	ut64 res;
	int align = 4 - (((buf[0] >> 4) & 0xf) % 4);
	int min = align + ((buf[0] >> 4) & 0xf);
	ut64 baddr = addr + min;
	short delta = buf[1] + ((buf[2]) << 8);
	res = baddr + (0x10 * delta);
	res >>= 2;
	res <<= 2;
	return res;
}

// XXX the branch calculation code is wrong. this is just an initial PoC
static int xtensa_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (op == NULL)
		return 1;
	memset (op, 0, sizeof (RAnalOp));
	r_strbuf_init (&op->esil);

	op->size = xtensa_length (buf);
	bool is_call = (buf[0] & 0xf) == 5;
	bool is_jmp = (buf[0] & 0xf) == 6;
	bool is_jmp2 = (buf[0]>=0x80 && (buf[0] & 0xf) == 0xc);
	//bool is_bl = (buf[0] & 0xf) == 7;
	if (is_call) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = decodeRelative (addr, buf);
		op->fail = addr + op->size;
	} else if (is_jmp2) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + buf[1] + 4;
		op->fail = addr + op->size;
	} else if (is_jmp) {
		if (((buf[0] >> 4)&0x3) == 0) {
			op->type = R_ANAL_OP_TYPE_JMP;
			if (buf[0] == 0x86) {
				op->jump = addr + (buf[1] * 4 ) + (buf[0]&0xf) + (buf[2]<<8);
			}else {
				op->jump = addr + 0x10 - (buf[1] + (buf[2]<<8)) + 1;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + buf[2] + 4;
		}
		op->fail = addr + op->size;
	} else {
		switch (buf[0]) {
		case 0xcc: // cjmp
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + buf[1] + 4;
			op->fail = addr + op->size;
			break;
		case 0xc0: // call0 
			if (buf[1] <= 0xf) {
				op->type = R_ANAL_OP_TYPE_UCALL;
			}
			break;
		case 0x80: // call0 
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 0x0d: // call0 
			if ((buf[1] >> 4) == 0xf) {
				op->type = R_ANAL_OP_TYPE_RET;
			} else if ((buf[1] >> 4) == 0x0) {
				op->type = R_ANAL_OP_TYPE_MOV;
			} else {
				op->type = R_ANAL_OP_TYPE_ILL;
			}
			break;
		case 0xff:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		}
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC	a15\n"
		"=BP	a14\n"
		"=SP	a13\n" // XXX
		"=A0	a0\n"
		"=A1	a1\n"
		"=A2	a2\n"
		"=A3	a3\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	8	0\n"
		"gpr	a4	.32	8	0\n"
		"gpr	a5	.32	8	0\n"
		"gpr	a6	.32	8	0\n"
		"gpr	a7	.32	8	0\n"
		"gpr	a8	.32	8	0\n"
		"gpr	a9	.32	8	0\n"
		"gpr	a10	.32	8	0\n"
		"gpr	a11	.32	8	0\n"
		"gpr	a12	.32	8	0\n"
		"gpr	a13	.32	8	0\n"
		"gpr	a14	.32	8	0\n"
		"gpr	a15	.32	8	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_xtensa = {
	.name = "xtensa",
	.desc = "Xtensa disassembler",
	.license = "LGPL3",
	.arch = "xtensa",
	.bits = 8,
	.esil = true,
	.op = &xtensa_op,
	.set_reg_profile = set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_xtensa,
	.version = R2_VERSION
};
#endif
