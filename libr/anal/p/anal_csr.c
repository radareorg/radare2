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

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *bytes, int len) {
	struct instruction *in = (struct instruction *)bytes;
	ut16 lol, ins;
	struct directive d;
	struct state s;
	int rel = 0;

	if (aop == NULL)
		return 2;

	memcpy (&ins, bytes, sizeof (ins));
	memcpy (&lol, bytes, sizeof (ins));
	s.s_buf = (void *)bytes;
	s.s_off = addr;
	s.s_out = NULL;
	memset (&d, '\0', sizeof (struct directive));
	memcpy (&d.d_inst, s.s_buf, sizeof (d.d_inst));
	d.d_off = (s.s_off+=2);
	csr_decode (&s, &d);
	d.d_operand = get_operand (&s, &d);

	memset (aop, 0, sizeof (RAnalOp));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->length = 2;

	switch (i2ut16 (in)) {
	case INST_NOP:
		aop->type = R_ANAL_OP_TYPE_NOP;
		break;
	case INST_BRK:
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BC:
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case INST_BRXL:
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		switch (in->in_opcode) {
		case 0:
			switch (lol&0xf) {
			case 1:
			case 2:
			case 3:
			case 0xa:
				aop->type = R_ANAL_OP_TYPE_PUSH;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
			case 0xe:
				aop->type = R_ANAL_OP_TYPE_POP;
				break;
			}
			break;
		case 1:
			aop->type = R_ANAL_OP_TYPE_POP;
			break;
		case 2:
			aop->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case 3:
		case 4:
		case 7:
			aop->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 5:
		case 6:
			aop->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 8:
			aop->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 9:
			switch(in->in_reg) {
			case 0:
				aop->type = R_ANAL_OP_TYPE_MUL;
				break;
			case 1:
				aop->type = R_ANAL_OP_TYPE_DIV;
				break;
			case 2:
				aop->type = R_ANAL_OP_TYPE_CMP;
				break;
			case 3:
				// BSR
				aop->type = R_ANAL_OP_TYPE_CALL;
				if (in->in_mode == ADDR_MODE_RELATIVE)
					rel = 1;
				aop->jump = label_off (&d);
				rel = 0;
				if (aop->jump&1)
					aop->jump+=3;
				aop->fail = addr+2;
				aop->eob = 1;
				break;
				
			}
			break;
		case 0xb:
			aop->type = R_ANAL_OP_TYPE_OR;
			break;
		case 0xc:
			aop->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xd:
			aop->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xe:
			if (in->in_mode == ADDR_MODE_RELATIVE)
				rel = 1;
			switch (in->in_reg) {
			case 0: // BRA
				aop->type = R_ANAL_OP_TYPE_JMP;
				aop->jump = label_off (&d)+4;
				if (aop->jump&1)
					aop->jump+=3;
				aop->eob = 1;
				break;
			case 1:
				// BLT
				aop->type = R_ANAL_OP_TYPE_CJMP;
				aop->jump = label_off (&d);
				if (aop->jump&1)
					aop->jump+=3;
				aop->fail = addr + 2;
				aop->eob = 1;
				break;
			case 2:
				// BPL
				aop->type = R_ANAL_OP_TYPE_CJMP;
				aop->jump = label_off (&d);
				if (aop->jump&1)
					aop->jump+=3;
				aop->fail = addr + 2;
				aop->eob = 1;
				break;
			case 3:
				// BMI
				aop->type = R_ANAL_OP_TYPE_CJMP;
				aop->jump = label_off (&d);
				if (aop->jump&1)
					aop->jump+=3;
				aop->fail = addr + 2;
				aop->eob = 1;
				break;
			}
			break;
		case 0xf:
			switch (in->in_reg) {
			case 0: // BNE
			case 1: // BEQ
			case 2: // BCC
			case 3: // BCS
				aop->type = R_ANAL_OP_TYPE_CJMP;
				rel = 0;
				aop->jump = label_off (&d);
				if (aop->jump&1)
					aop->jump+=3;
				aop->fail = addr+2;
				break;
			}
			break;
		}
		break;
	}
	return aop->length;
}

struct r_anal_plugin_t r_anal_plugin_csr = {
	.name = "csr",
	.desc = "CSR code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop,
	.set_reg_profile = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_csr
};
#endif
