/* radare - LGPL - Copyright 2008-2010 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../asm/arch/csr/dis.c"

#if 0
static int get_num(int num, int shift) {
	int tmp;
	char x = (char) ((num >> shift) & 0xff);
	tmp = x;
	tmp <<= shift;
	return tmp;
}

static int get_operand(struct state *s, struct directive *d) {
	int total = get_num (d->d_inst.in_operand, 0);
	if (s->s_prefix == 2)
		total += get_num (s->s_prefix_val, 16);
	else total += get_num (s->s_prefix_val, 8);
	return total;
}
#endif

static int label_off(struct directive *d) {
	int off = d->d_operand;
	int lame = off & 0x80;

	if (!d->d_prefix) { // WTF
		off = (char) (off & 0xff);
	} else if (d->d_prefix == 1) {
		off = (short) (off & 0xffff);
		if (lame)
			off -= 0x100;
	} else {
		off = (int) (off & 0xffffff);
		if (off & 0x800000)
			off |= 0xff000000;
		if (off & 0x8000)
			off -= 0x10000;
		if (lame)
			off -= 0x100;
	}
	return d->d_off + off;
}

static inline ut16 i2ut16(struct instruction *in) {
	return *((uint16_t*)in);
}

static int csr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *bytes, int len) {
	struct instruction *in = (struct instruction *)bytes;
	ut16 lol, ins;
	struct directive d;
	struct state s;

	if (op == NULL)
		return 2;

	memcpy (&ins, bytes, sizeof (ins));
	memcpy (&lol, bytes, sizeof (ins));
	s.s_buf = (void *)bytes;
	s.s_off = addr;
	s.s_out = NULL;
	s.s_prefix = 0;
	memset (&d, '\0', sizeof (struct directive));
	memcpy (&d.d_inst, s.s_buf, sizeof (d.d_inst));
	d.d_off = (s.s_off+=2);
	csr_decode (&s, &d);
	d.d_operand = get_operand (&s, &d);

	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 2;

	switch (i2ut16 (in)) {
	case INST_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case INST_BRK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BC:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BRXL:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		switch (in->in_opcode) {
		case 0:
			switch (lol&0xf) {
			case 1:
			case 2:
			case 3:
			case 0xa:
				op->type = R_ANAL_OP_TYPE_PUSH;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
			case 0xe:
				op->type = R_ANAL_OP_TYPE_POP;
				break;
			}
			break;
		case 1:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case 2:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case 3:
		case 4:
		case 7:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 5:
		case 6:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 8:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 9:
			switch(in->in_reg) {
			case 0:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case 1:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case 2:
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			case 3:
				// BSR
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = label_off (&d);
				if (op->jump&1)
					op->jump+=3;
				op->fail = addr+2;
				op->eob = 1;
				break;
			}
			break;
		case 0xb:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 0xc:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xd:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xe:
			switch (in->in_reg) {
			case 0: // BRA
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = label_off (&d)+4;
				if (op->jump&1)
					op->jump+=3;
				op->eob = 1;
				break;
			case 1:
				// BLT
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = label_off (&d);
				if (op->jump&1)
					op->jump+=3;
				op->fail = addr + 2;
				op->eob = 1;
				break;
			case 2:
				// BPL
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = label_off (&d);
				if (op->jump&1)
					op->jump+=3;
				op->fail = addr + 2;
				op->eob = 1;
				break;
			case 3:
				// BMI
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = label_off (&d);
				if (op->jump&1)
					op->jump+=3;
				op->fail = addr + 2;
				op->eob = 1;
				break;
			}
			break;
		case 0xf:
			switch (in->in_reg) {
			case 0: // BNE
			case 1: // BEQ
			case 2: // BCC
			case 3: // BCS
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = label_off (&d);
				if (op->jump&1)
					op->jump+=3;
				op->fail = addr+2;
				break;
			}
			break;
		}
		break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_csr = {
	.name = "csr",
	.desc = "CSR code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_CSR,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &csr_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_csr
};
#endif
