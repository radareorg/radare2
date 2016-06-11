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

static inline ut64 xtensa_offset (ut64 addr, const ut8 *buf) {
	ut32 offset = ((buf[0] >> 4) & 0xc) | (((ut32)buf[1]) << 4) | (((ut32)buf[2]) << 12);
	if (offset & 0x80000)
		return (addr + 4 + offset - 0x100000) & ~3;
	return (addr + 4 + offset) & ~3;
}

static inline ut64 xtensa_imm18s (ut64 addr, const ut8 *buf) {
	ut32 offset = (buf[0] >> 6) | (((ut32)buf[1]) << 2) | (((ut32)buf[2]) << 10);
	if (offset & 0x20000)
		return addr + 4 + offset - 0x40000;
	return addr + 4 + offset;
}

static inline ut64 xtensa_imm6s (ut64 addr, const ut8 *buf) {
	ut8 imm6 = (buf[1] >> 4) | (buf[0] & 0x30);
	if (imm6 & 0x20)
		return (addr + 4 + imm6 - 0x40);
	return (addr + 4 + imm6);
}

static inline ut64 xtensa_imm8s (ut64 addr, ut8 imm8) {
	if (imm8 & 0x80)
		return (addr + 4 + imm8 - 0x100);
	return (addr + 4 + imm8);
}

static inline ut64 xtensa_imm12s (ut64 addr, const ut8 *buf) {
	ut16 imm12 = (buf[1] >> 4) | (((ut16)buf[2]) << 4);
	if (imm12 & 0x800)
		return (addr + 4 + imm12 - 0x1000);
	return (addr + 4 + imm12);
}

typedef void (*XtensaOpFn) (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf);

static void xtensa_null_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_NULL;
}

static void xtensa_unk_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void xtensa_mov_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_MOV;
}

static void xtensa_load_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_LOAD;
}

static void xtensa_store_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_STORE;
}

static void xtensa_add_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_ADD;
}

static void xtensa_sub_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_SUB;
}

static void xtensa_mul_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_MUL;
}

static void xtensa_div_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_DIV;
}

static void xtensa_mod_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_MOD;
}

static void xtensa_and_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_AND;
}

static void xtensa_or_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_OR;
}

static void xtensa_xor_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_XOR;
}

static void xtensa_shl_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_SHL;
}

static void xtensa_shr_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_SHR;
}

static void xtensa_l32r_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	op->ptr = ((addr + 3) & ~3) + ((buf[2] << 8 | buf[1]) << 2) - 0x40000;
}

static void xtensa_snm0_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[0] >> 4) & 0xf) {
	case 0x0: case 0x1: case 0x2: case 0x3:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case 0x8: case 0x9:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 0xa:
		op->type = R_ANAL_OP_TYPE_UJMP;
		break;
	case 0xc: case 0xd: case 0xe: case 0xf:
		op->type = R_ANAL_OP_TYPE_UCALL;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_sync_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[0] >> 4) & 0xf) {
	case 0x0: case 0x1: case 0x2: case 0x3:
	case 0x8:
	case 0xc: case 0xd:
		/* Wait/sync instructions? */
		op->type = R_ANAL_OP_TYPE_NULL;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_rfei_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[0] >> 4) & 0xf) {
	case 0x0:
		switch (buf[1] & 0xf) {
		case 0x0: case 0x1: case 0x2:
		case 0x4: case 0x5:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		default:
			xtensa_unk_op (anal, op, addr, buf);
			break;
		}
		break;
	case 0x1: case 0x2:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_st0_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[1] >> 4) & 0xf) {
	case 0x0:
		xtensa_snm0_op (anal, op, addr, buf);
		break;
	case 0x1:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case 0x2:
		xtensa_sync_op (anal, op, addr, buf);
		break;
	case 0x3:
		xtensa_rfei_op (anal, op, addr, buf);
		break;
	case 0x4:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case 0x5: case 0x6: case 0x7:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0x8: case 0x9: case 0xa: case 0xb:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_st1_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[1] >> 4) & 0xf) {
	case 0x0: case 0x1: case 0x2: case 0x3:
	case 0x4:
		/* Set shift-amount-register */
		op->type = R_ANAL_OP_TYPE_NULL;
		/*op->type = R_ANAL_OP_TYPE_MOV;*/
		break;
	case 0x6: case 0x7:
		op->type = R_ANAL_OP_TYPE_IO;
		/*op->type = R_ANAL_OP_TYPE_MOV;*/
		break;
	case 0x8:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xe: case 0xf:
		op->type = R_ANAL_OP_TYPE_NULL;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_rt0_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch (buf[1] & 0xf) {
	case 0:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case 1:
		/*op->type = R_ANAL_OP_TYPE_ABS;*/
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_tlb_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[2] >> 4) & 0xf) {
	case 0x3:
	case 0x4: case 0x5: case 0x6: case 0x7:
	case 0xb:
	case 0xc: case 0xd: case 0xe: case 0xf:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_accer_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[2] >> 4) & 0xf) {
	case 0x0:
	case 0x8:
		op->type = R_ANAL_OP_TYPE_IO;
		/*op->type = R_ANAL_OP_TYPE_MOV;*/
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_imp_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[1] >> 4) & 0xf) {
	case 0x0: case 0x1: case 0x2: case 0x3:
	case 0x8: case 0x9:
		op->type = R_ANAL_OP_TYPE_NULL;
		break;
	case 0xe:
		if (((buf[0] >> 4) & 0xf) <= 1)
			op->type = R_ANAL_OP_TYPE_RET;
		else
			xtensa_unk_op (anal, op, addr, buf);
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static XtensaOpFn xtensa_rst0_fns[] = {
	xtensa_st0_op,
	xtensa_and_op,
	xtensa_or_op,
	xtensa_xor_op,
	xtensa_st1_op,
	xtensa_tlb_op,
	xtensa_rt0_op,
	xtensa_unk_op,
	xtensa_add_op,
	xtensa_add_op,
	xtensa_add_op,
	xtensa_add_op,
	xtensa_sub_op,
	xtensa_sub_op,
	xtensa_sub_op,
	xtensa_sub_op
};

static XtensaOpFn xtensa_rst1_fns[] = {
	xtensa_shl_op,
	xtensa_shl_op,
	xtensa_shr_op,
	xtensa_shr_op,
	xtensa_shr_op,
	xtensa_unk_op,
	xtensa_null_op,
	xtensa_accer_op,
	xtensa_shr_op,
	xtensa_shr_op,
	xtensa_shl_op,
	xtensa_shr_op,
	xtensa_mul_op,
	xtensa_mul_op,
	xtensa_unk_op,
	xtensa_imp_op
};

static XtensaOpFn xtensa_rst2_fns[] = {
	xtensa_and_op,
	xtensa_and_op,
	xtensa_or_op,
	xtensa_or_op,
	xtensa_xor_op,
	xtensa_unk_op,
	xtensa_unk_op,
	xtensa_unk_op,
	xtensa_mul_op,
	xtensa_unk_op,
	xtensa_mul_op,
	xtensa_mul_op,
	xtensa_div_op,
	xtensa_div_op,
	xtensa_mod_op,
	xtensa_mod_op
};

static void xtensa_rst0_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	xtensa_rst0_fns[(buf[2] >> 4) & 0xf] (anal, op, addr, buf);
}
static void xtensa_rst1_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	xtensa_rst1_fns[(buf[2] >> 4) & 0xf] (anal, op, addr, buf);
}

static void xtensa_rst2_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	xtensa_rst2_fns[(buf[2] >> 4) & 0xf] (anal, op, addr, buf);
}

static void xtensa_lsc4_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[2] >> 4) & 0xf) {
	case 0x0:
		xtensa_load_op (anal, op, addr, buf);
		break;
	case 0x4:
		xtensa_store_op (anal, op, addr, buf);
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_lscx_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->family = R_ANAL_OP_FAMILY_FPU;
	switch ((buf[2] >> 4) & 0xf) {
	case 0x0: case 0x1:
		xtensa_load_op (anal, op, addr, buf);
		break;
	case 0x4: case 0x5:
		xtensa_store_op (anal, op, addr, buf);
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_fp0_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->family = R_ANAL_OP_FAMILY_FPU;
	switch ((buf[2] >> 4) & 0xf) {
	case 0x0: case 0x4:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x1: case 0x5:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x2:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case 0x8: case 0x9: case 0xa: case 0xb:
	case 0xc: case 0xd: case 0xe:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xf:
		switch ((buf[0] >> 4) & 0xf) {
		case 0x0: case 0x4: case 0x5:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0x1:
			op->type = R_ANAL_OP_TYPE_ABS;
			break;
		case 0x6:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		default:
			xtensa_unk_op (anal, op, addr, buf);
			break;
		}
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_fp1_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->family = R_ANAL_OP_FAMILY_FPU;
	switch ((buf[2] >> 4) & 0xf) {
	case 0x1: case 0x2: case 0x3:
	case 0x4: case 0x5: case 0x6: case 0x7:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x8: case 0x9: case 0xa: case 0xb:
	case 0xc: case 0xd:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static XtensaOpFn xtensa_qrst_fns[] = {
	xtensa_rst0_op,
	xtensa_rst1_op,
	xtensa_rst2_op,
	xtensa_mov_op, /*xtensa_rst3_op,*/
	xtensa_null_op, /*xtensa_extui_op,*/
	xtensa_null_op, /*xtensa_extui_op,*/
	xtensa_unk_op, /*xtensa_cust0_op,*/
	xtensa_unk_op, /*xtensa_cust1_op,*/
	xtensa_lscx_op,
	xtensa_lsc4_op,
	xtensa_fp0_op,
	xtensa_fp1_op,
	xtensa_unk_op,
	xtensa_unk_op,
	xtensa_unk_op,
	xtensa_unk_op
};

static void xtensa_qrst_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	xtensa_qrst_fns[buf[2] & 0xf] (anal, op, addr, buf);
}

static XtensaOpFn xtensa_lsai_fns[] = {
	xtensa_load_op,
	xtensa_load_op,
	xtensa_load_op,
	xtensa_unk_op,
	xtensa_store_op,
	xtensa_store_op,
	xtensa_store_op,
	xtensa_null_op, /*xtensa_cache_op,probably not interesting for anal?*/
	xtensa_unk_op,
	xtensa_load_op,
	xtensa_mov_op,
	xtensa_load_op,
	xtensa_add_op,
	xtensa_add_op,
	xtensa_store_op,
	xtensa_store_op
};

static void xtensa_lsai_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	xtensa_lsai_fns[(buf[1] >> 4) & 0xf] (anal, op, addr, buf);
}
static void xtensa_lsci_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	ut8 r = buf[1] >> 4;
	op->family = R_ANAL_OP_FAMILY_FPU;
	if ((r & 3) == 0) {
		if (r & 4)
			xtensa_store_op (anal, op, addr, buf);
		else
			xtensa_load_op (anal, op, addr, buf);
	} else {
		xtensa_unk_op (anal, op, addr, buf);
	}
}
static void xtensa_calln_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_CALL;
	op->fail = addr + op->size;
	op->jump = xtensa_offset (addr, buf);
}

static void xtensa_b_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->fail = addr + op->size;
	op->jump = xtensa_imm8s (addr, buf[2]);
}

static void xtensa_si_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	ut8 n = (buf[0] >> 4) & 3;
	ut8 m = (buf[0] >> 6);
	switch (n) {
	case 0:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = xtensa_imm18s (addr, buf);
		break;
	case 1:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = addr + op->size;
		op->jump = xtensa_imm12s (addr, buf);
		break;
	case 2:
		xtensa_b_op (anal, op, addr, buf);
		break;
	case 3:
		switch (m) {
		case 0:
			op->type = R_ANAL_OP_TYPE_UPUSH;
			break;
		case 1:
			switch (buf[1] >> 4) {
			case 0: case 1:
				xtensa_b_op (anal, op, addr, buf);
				break;
			case 0x8: case 0x9: case 0xa:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				op->jump = addr + 4 + buf[2];
				break;
			default:
				xtensa_unk_op (anal, op, addr, buf);
				break;
			}
			break;
		case 2: case 3:
			xtensa_b_op (anal, op, addr, buf);
			break;
		default:
			xtensa_unk_op (anal, op, addr, buf);
			break;
		}
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static void xtensa_st2n_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	if (buf[0] & 0x80) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = addr + op->size;
		op->jump = xtensa_imm6s (addr, buf);
	} else {
		op->type = R_ANAL_OP_TYPE_MOV;
	}
}

static void xtensa_st3n_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf) {
	switch ((buf[1] >> 4) & 0xf) {
	case 0x0:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xf:
		switch ((buf[0] >> 4) & 0xf) {
		case 0: case 1:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 2:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case 3:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 6:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		default:
			xtensa_unk_op (anal, op, addr, buf);
			break;
		}
		break;
	default:
		xtensa_unk_op (anal, op, addr, buf);
		break;
	}
}

static XtensaOpFn xtensa_op0_fns[] = {
	xtensa_qrst_op,
	xtensa_l32r_op,
	xtensa_lsai_op,
	xtensa_lsci_op,
	xtensa_null_op, /*xtensa_mac16_op,*/
	xtensa_calln_op,
	xtensa_si_op,
	xtensa_b_op,

	xtensa_load_op,
	xtensa_store_op,
	xtensa_add_op,
	xtensa_add_op,
	xtensa_st2n_op,
	xtensa_st3n_op,
	xtensa_null_op, /*xtensa_xt_format1_op,*/ /*TODO*/
	xtensa_null_op  /*xtensa_xt_format2_op*/ /*TODO*/
};

static int xtensa_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (op == NULL)
		return 1;
	memset (op, 0, sizeof (RAnalOp));
	r_strbuf_init (&op->esil);

	op->size = xtensa_length (buf);
	if (op->size > len)
		return 1;

	xtensa_op0_fns[(buf[0] & 0xf)] (anal, op, addr, buf);
	return op->size;
}

static char *get_reg_profile(RAnal *anal) {
	return strdup (
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
		"gpr	a15	.32	8	0\n"
	);
}

struct r_anal_plugin_t r_anal_plugin_xtensa = {
	.name = "xtensa",
	.desc = "Xtensa disassembler",
	.license = "LGPL3",
	.arch = "xtensa",
	.bits = 8,
	.esil = true,
	.op = &xtensa_op,
	.get_reg_profile = get_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_xtensa,
	.version = R2_VERSION
};
#endif
