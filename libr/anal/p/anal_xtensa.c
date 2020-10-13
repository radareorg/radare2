/* radare2 - LGPL - Copyright 2016-2018 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <xtensa-isa.h>

#define CM ","
#define XTENSA_MAX_LENGTH 8

#if defined(_MSC_VER)
__declspec(dllimport)
#endif
extern xtensa_isa xtensa_default_isa;

static int xtensa_length(const ut8 *insn) {
	static int length_table[16] = { 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 8, 8 };
	return length_table[*insn & 0xf];
}

static inline ut64 xtensa_offset (ut64 addr, const ut8 *buf) {
	ut32 offset = ((buf[0] >> 4) & 0xc) | (((ut32)buf[1]) << 4) | (((ut32)buf[2]) << 12);
	if (offset & 0x80000) {
		return (addr + 4 + offset - 0x100000) & ~3;
	}
	return (addr + 4 + offset) & ~3;
}

static inline ut64 xtensa_imm18s (ut64 addr, const ut8 *buf) {
	ut32 offset = (buf[0] >> 6) | (((ut32)buf[1]) << 2) | (((ut32)buf[2]) << 10);
	if (offset & 0x20000) {
		return addr + 4 + offset - 0x40000;
	}
	return addr + 4 + offset;
}

static inline ut64 xtensa_imm6s (ut64 addr, const ut8 *buf) {
	ut8 imm6 = (buf[1] >> 4) | (buf[0] & 0x30);
	return (addr + 4 + imm6);
}

static inline ut64 xtensa_imm8s (ut64 addr, ut8 imm8) {
	if (imm8 & 0x80) {
		return (addr + 4 + imm8 - 0x100);
	}
	return (addr + 4 + imm8);
}

static inline ut64 xtensa_imm12s (ut64 addr, const ut8 *buf) {
	ut16 imm12 = (buf[1] >> 4) | (((ut16)buf[2]) << 4);
	if (imm12 & 0x800) {
		return (addr + 4 + imm12 - 0x1000);
	}
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
		if (((buf[0] >> 4) & 0xf) <= 1) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else {
			xtensa_unk_op (anal, op, addr, buf);
		}
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
		if (r & 4) {
			xtensa_store_op (anal, op, addr, buf);
		} else {
			xtensa_load_op (anal, op, addr, buf);
		}
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

static inline void sign_extend(st32 *value, ut8 bit) {
	if (*value & (1 << bit)) {
		*value |= 0xFFFFFFFF << bit;
	}
}

static inline void sign_extend2(st32 *value, ut8 bit1, ut8 bit2, ut8 shift) {
	if (((*value >> bit1) & 1) && ((*value >> bit2) & 1)) {
		*value |= UT32_MAX << (32 - shift);
	}
}

static void xtensa_check_stack_op(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	st32 imm;
	ut32 dst;
	ut32 src;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &src);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &imm);

	// wide form of addi requires sign extension
	if (opcode == 39) {
		sign_extend (&imm, 7);
	}

	// a1 = stack
	if (dst == 1 && src == 1) {
		op->val = imm;
		op->stackptr = -imm;
		op->stackop = R_ANAL_STACK_INC;
	}
}

static void esil_push_signed_imm(RStrBuf * esil, st32 imm) {
	if (imm >= 0) {
		r_strbuf_appendf (esil, "0x%x" CM, imm);
	} else {
		r_strbuf_appendf (
			esil,
			"0x%x"	CM
			"0x0"	CM
			"-"	CM,
			- imm
		);
	}
}

static void esil_sign_extend(RStrBuf *esil, ut8 bit) {
	// check sign bit, and, if needed, apply or mask

	ut32 bit_mask = 1 << bit;
	ut32 extend_mask = 0xFFFFFFFF << bit;

	r_strbuf_appendf (
		esil,
		"DUP"	CM
		"0x%x"	CM
		"&"	CM
		"0"	CM
		"==,$z,!"	CM
		"?{"	CM
			"0x%x"	CM
			"|"	CM
		"}"	CM,
		bit_mask,
		extend_mask
	);
}

static void esil_load_imm(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 offset;
	ut32 reg_d;
	ut32 reg_a;
	ut8 sign_extend_bit;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg_d);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &reg_a);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &offset);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	// example: l32i a2, a1, 0x10
	//          0x10,a1,+, // address on stack
	//          [x], // read data
	//          a2, // push data reg
	//			= // assign to data reg

	ut8 data_size = opcode == 82 ? 2 // l16ui
			: opcode == 83 ? 2 // l16si
			: opcode == 84 ? 4 // l32i
			: opcode == 31 ? 4 // l32i.n
			: 1; // opcode == 86 ? 1 : 1; // l8ui

	sign_extend_bit = 0;

	switch (opcode) {
	case 84: // l32i
	case 31: // l32i.n
		offset <<= 2;
		break;
	case 83: // l16si
		sign_extend_bit = 15;
		/* no break */
	case 82: // l16ui
		offset <<= 1;
		break;
	}

	r_strbuf_appendf (
		&op->esil,
			"0x%x"	CM
			"%s%d"	CM
			"+"	CM
			"[%d]"	CM,
		// offset
		offset,
		// address
		xtensa_regfile_shortname (isa, src_rf),
		reg_a,
		// size
		data_size
	);

	if (sign_extend_bit != 0) {
		esil_sign_extend (&op->esil, sign_extend_bit);
	}

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"=",
		// data
		xtensa_regfile_shortname (isa, dst_rf),
		reg_d
	);
}

static void esil_load_relative(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 offset;
	st32 dst;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, (ut32 *) &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &offset);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);

	// example: l32r a2, 0x10
	//          0x10,$$,3,+ // l32r address + 3 on stack
	//          0xFFFFFFFC,&, // clear 2 lsb
	//          -, // subtract offset
	//          [4], // read data
	//          a2, // push data reg
	//          = // assign to data reg

	offset = - ((offset | 0xFFFF0000) << 2);

	r_strbuf_appendf (
		&op->esil,
			"0x%x" 		CM
			"$$"   		CM
			"3"		CM
			"+"		CM
			"0xFFFFFFFC"	CM
			"&" 		CM
			"-"    		CM
			"[4]"		CM
			"%s%d" 		CM
			"=",
		// offset
		offset,
		// data
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_add_imm(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	st32 imm;
	ut32 dst;
	ut32 src;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &src);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &imm);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	// example: addi a3, a4, 0x01
	//          a4,0x01,+,a3,=

	// wide form of addi requires sign extension
	if (opcode == 39) {
		sign_extend (&imm, 7);
	}

	r_strbuf_appendf (&op->esil, "%s%d" CM, xtensa_regfile_shortname (isa, src_rf), src);
	esil_push_signed_imm (&op->esil, imm);
	r_strbuf_appendf (
		&op->esil,
			"+"    CM
			"%s%d" CM
			"=",
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_store_imm(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {

	ut32 offset;
	ut32 reg_d;
	ut32 reg_a;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg_d);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &reg_a);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &offset);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	// example: s32i a2, a1, 0x10
	//          a2, // push data
	//          0x10,a1,+, // address on stack
	//          =[x] // write data

	ut8 data_size =
		opcode == 453 ? 4 // s32cli
		: opcode == 36 ? 4 // s32i.n
		: opcode == 100 ? 4 // s32i
		: opcode == 99 ? 2 // s16i
		: 1; // opcode == 101 ? 1 : 1; // s8i

	switch (opcode) {
	case 100: // s32i
	case 453: // s32cli
	case 36: // s32i.n
		offset <<= 2;
		break;
	case 99: // s16i
		offset <<= 1;
		break;
	}

	r_strbuf_appendf (
		&op->esil,
			"%s%d" CM
			"0x%x" CM
			"%s%d" CM
			"+"    CM
			"=[%d]",
		// data
		xtensa_regfile_shortname (isa, dst_rf),
		reg_d,
		// offset
		offset,
		// address
		xtensa_regfile_shortname (isa, src_rf),
		reg_a,
		// size
		data_size
	);
}

static void esil_move_imm(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	st32 imm;
	ut32 reg;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, (ut32 *) &imm);

	xtensa_regfile rf = xtensa_operand_regfile (isa, opcode, 0);

	// sign extension
	// 90: movi
	if (opcode == 90) {
		sign_extend (&imm, 11);
	}

	// 33: movi.n
	if (opcode == 33) {
		sign_extend2 (&imm, 6, 5, 25);
	}

	esil_push_signed_imm (&op->esil, imm);

	r_strbuf_appendf (
		&op->esil,
			"%s%d" CM
			"=",
		xtensa_regfile_shortname (isa, rf),
		reg
	);
}

static void esil_move(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 dst;
	ut32 src;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &src);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	r_strbuf_appendf (
		&op->esil,
			"%s%d" CM
			"%s%d" CM
			"=",
		xtensa_regfile_shortname (isa, src_rf),
		src,
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_move_conditional(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 dst;
	ut32 src;
	ut32 cond;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &src);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &cond);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);
	xtensa_regfile cond_rf = xtensa_operand_regfile (isa, opcode, 2);

	const char *compare_op = "";

	switch (opcode) {
	case 91:	/* moveqz */
		compare_op = "==,$z";
		break;
	case 92:	/* movnez */
		compare_op = "==,$z,!";
		break;
	case 93:	/* movltz */
		compare_op = "<";
		break;
	case 94:	/* movgez */
		compare_op = ">=";
		break;
	}

	// example: moveqz a3, a4, a5
	//          0,
	//          a5,
	//          ==,
	//          ?{,
	//            a4,
	//            a3,
	//            =,
	//          }

	r_strbuf_appendf (
		&op->esil,
			"0"	CM
			"%s%d"	CM
			"%s"	CM
			"?{"	CM
				"%s%d"	CM
				"%s%d"	CM
				"="	CM
			"}",
		xtensa_regfile_shortname (isa, cond_rf),
		cond,
		compare_op,
		xtensa_regfile_shortname (isa, src_rf),
		src,
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_add_sub(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 dst;
	ut32 op1;
	ut32 op2;
	bool is_add;
	ut8 shift;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &op1);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &op2);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile op1_rf = xtensa_operand_regfile (isa, opcode, 1);
	xtensa_regfile op2_rf = xtensa_operand_regfile (isa, opcode, 2);

	is_add =
		(opcode == 26) ||
		(opcode == 41) ||
		(opcode == 43) ||
		(opcode == 44) ||
		(opcode == 45);

	switch (opcode) {
	case 43:
	case 46:
		shift = 1;
		break;
	case 44:
	case 47:
		shift = 2;
		break;
	case 45:
	case 48:
		shift = 3;
		break;
	default:
		shift = 0;
		break;
	}

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"%d"    CM
			"%s%d"	CM
			"<<"    CM
			"%s"	CM
			"%s%d"	CM
			"=",
		xtensa_regfile_shortname (isa, op2_rf),
		op2,
		shift,
		xtensa_regfile_shortname (isa, op1_rf),
		op1,
		(is_add ? "+" : "-"),
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_branch_compare_imm(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 cmp_reg;
	// Unsigned immediate operands still fit in st32
	st32 cmp_imm;
	st32 branch_imm;

	const char *compare_op = "";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &cmp_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, (ut32 *) &cmp_imm);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &branch_imm);

	xtensa_regfile cmp_rf = xtensa_operand_regfile (isa, opcode, 0);

	// TODO: unsigned comparisons
	switch (opcode) {
	case 52:	/* beqi */
		compare_op = "==,$z";
		break;
	case 53:	/* bnei */
		compare_op = "==,$z,!";
		break;
	case 58:	/* bgeui */
	case 54:	/* bgei */
		compare_op = ">=";
		break;
	case 59:	/* bltui */
	case 55:	/* blti */
		compare_op = "<";
		break;
	}

	// example: beqi a4, 4, offset
	//            a4, // push data reg
	//            0x4, // push imm operand
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	r_strbuf_appendf (
		&op->esil,
		"%s%d" CM,
		// data reg
		xtensa_regfile_shortname (isa, cmp_rf),
		cmp_reg
	);

	esil_push_signed_imm (&op->esil, cmp_imm);

	r_strbuf_appendf (&op->esil, "%s" CM, compare_op);
	r_strbuf_appendf (&op->esil, "?{" CM);

	// ISA defines branch target as offset + 4,
	// but at the time of ESIL evaluation
	// PC will be already incremented by 3
	esil_push_signed_imm (&op->esil, branch_imm + 4 - 3);

	r_strbuf_appendf (&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_compare(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 op1_reg;
	ut32 op2_reg;
	st32 branch_imm;

	const char *compare_op = "";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &op1_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &op2_reg);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &branch_imm);

	xtensa_regfile op1_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile op2_rf = xtensa_operand_regfile (isa, opcode, 1);

	switch (opcode) {
	case 60:	/* beq */
		compare_op = "==,$z";
		break;
	case 61:	/* bne */
		compare_op = "==,$z,!";
		break;
	case 62:	/* bge */
	case 64:	/* bgeu */
		compare_op = ">=";
		break;
	case 63:	/* blt */
	case 65:	/* bltu */
		compare_op = "<";
		break;
	}

	sign_extend (&branch_imm, 7);
	branch_imm += 4 - 3;

	// example: beq a4, a3, offset
	//            a3, // push op1
	//            a4, // push op2
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"%s%d"	CM
			"%s"	CM
			"?{"	CM,
		xtensa_regfile_shortname (isa, op2_rf),
		op2_reg,
		xtensa_regfile_shortname (isa, op1_rf),
		op1_reg,
		compare_op
	);

	esil_push_signed_imm (&op->esil, branch_imm);

	r_strbuf_append (&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_compare_single(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 op_reg;
	st32 branch_imm;

	const char *compare_op = "";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &op_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, (ut32 *) &branch_imm);

	xtensa_regfile op_rf = xtensa_operand_regfile (isa, opcode, 0);

	switch (opcode) {
	case 72:	/* beqz */
	case 28:	/* beqz.n */
		compare_op = "==,$z";
		break;
	case 73:	/* bnez */
	case 29:	/* bnez.n */
		compare_op = "==,$z,!";
		break;
	case 74:	/* bgez */
		compare_op = ">=";
		break;
	case 75:	/* bltz */
		compare_op = "<";
		break;
	}

	sign_extend (&branch_imm, 12);
	branch_imm += 4 - 3;

	// example: beqz a4, 0, offset
	//            0,  // push 0
	//            a4, // push op
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	r_strbuf_appendf (
		&op->esil,
			"0"	CM
			"%s%d"	CM
			"%s"	CM
			"?{"	CM,
		xtensa_regfile_shortname (isa, op_rf),
		op_reg,
		compare_op
	);

	esil_push_signed_imm (&op->esil, branch_imm);

	r_strbuf_append (&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_check_mask(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 op1_reg;
	ut32 op2_reg;
	st32 branch_imm;

	const char *compare_op = "";
	char compare_val[4] = "0";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &op1_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &op2_reg);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &branch_imm);

	xtensa_regfile op1_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile op2_rf = xtensa_operand_regfile (isa, opcode, 1);

	switch (opcode) {
	case 69:	/* bnall */
	case 66:	/* bany */
		compare_op = "==,$z,!";
		break;
	case 68:	/* ball */
	case 67:	/* bnone */
		compare_op = "==,$z";
		break;
	}

	switch (opcode) {
	case 69:	/* bnall */
	case 68:	/* ball */
		snprintf(
			compare_val,
			sizeof(compare_val),
			"%s%d",
			xtensa_regfile_shortname (isa, op2_rf),
			op2_reg
		);
		break;
	}

	sign_extend (&branch_imm, 7);
	branch_imm += 4 - 3;

	// example: bnall a4, a3, offset
	//            a4, // push op1
	//            a3, // push op2
	//            &,
	//            a3,
	//            ==,!,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"%s%d"	CM
			"&"	CM
			"%s%d"	CM
			"%s"	CM
			"?{"	CM,
		xtensa_regfile_shortname (isa, op1_rf),
		op1_reg,
		xtensa_regfile_shortname (isa, op2_rf),
		op2_reg,
		xtensa_regfile_shortname (isa, op2_rf),
		op2_reg,
		compare_op
	);

	esil_push_signed_imm (&op->esil, branch_imm);

	r_strbuf_append (&op->esil, "pc" CM "+=" CM "}");
}

static void esil_bitwise_op(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 dst;
	ut32 op1;
	ut32 op2;
	char bop;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &op1);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &op2);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile op1_rf = xtensa_operand_regfile (isa, opcode, 1);
	xtensa_regfile op2_rf = xtensa_operand_regfile (isa, opcode, 2);

	switch (opcode) {
	case 49:	/* and */
		bop = '&';
		break;
	case 50:	/* or */
		bop = '|';
		break;
	case 51:	/* xor */
		bop = '^';
		break;
	default:
		bop = '=';
		break;
	}

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"%s%d"	CM
			"%c"    CM
			"%s%d"	CM
			"=",
		xtensa_regfile_shortname (isa, op1_rf),
		op1,
		xtensa_regfile_shortname (isa, op2_rf),
		op2,
		bop,
		xtensa_regfile_shortname (isa, dst_rf),
		dst
	);
}

static void esil_branch_check_bit_imm(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 src_reg;
	ut32 imm_bit;
	st32 imm_offset;
	ut8 bit_clear;
	ut32 mask;
	const char *cmp_op;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &src_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &imm_bit);
	xtensa_operand_decode (isa, opcode, 1, &imm_bit);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &imm_offset);

	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 0);

	bit_clear = opcode == 56;
	cmp_op = bit_clear ? "==,$z" : "==,$z,!";
	mask = 1 << imm_bit;

	sign_extend (&imm_offset, 7);
	imm_offset += 4 - 3;

	// example: bbsi a4, 2, offset
	//          a4,
	//          mask,
	//          &,
	//          0,
	//          ==,
	//          ?{,
	//            offset,
	//            pc,
	//            +=,
	//          }

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"0x%x"	CM
			"&"	CM
			"0"	CM
			"%s"	CM
			"?{"	CM,
		xtensa_regfile_shortname (isa, src_rf),
		src_reg,
		mask,
		cmp_op
	);

	esil_push_signed_imm (&op->esil, imm_offset);

	r_strbuf_appendf (
		&op->esil,
			"pc"	CM
			"+="	CM
			"}"
	);
}

static void esil_branch_check_bit(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 src_reg;
	ut32 bit_reg;
	st32 imm_offset;

	ut8 bit_clear;
	const char *cmp_op;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &src_reg);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &bit_reg);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, (ut32 *) &imm_offset);

	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile bit_rf = xtensa_operand_regfile (isa, opcode, 1);

	// bbc
	bit_clear = opcode == 70;
	cmp_op = bit_clear ? "==,$z" : "==,$z,!";

	sign_extend (&imm_offset, 7);
	imm_offset += 4 - 3;

	// example: bbc a4, a2, offset
	//          a2,
	//          1,
	//          <<,
	//          a4,
	//          &
	//          0
	//          ==,
	//          ?{,
	//            offset,
	//            pc,
	//            +=,
	//          }

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"1"	CM
			"<<"	CM
			"%s%d"	CM
			"&"	CM
			"0"	CM
			"%s"	CM
			"?{"	CM,
		xtensa_regfile_shortname (isa, bit_rf),
		bit_reg,
		xtensa_regfile_shortname (isa, src_rf),
		src_reg,
		cmp_op
	);

	esil_push_signed_imm (&op->esil, imm_offset);

	r_strbuf_appendf (
		&op->esil,
			"pc"	CM
			"+="	CM
			"}"
	);
}

static void esil_abs_neg(xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
		size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 src_reg;
	ut32 dst_reg;

	ut8 neg;

	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &dst_reg);
	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &src_reg);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 1);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 0);

	neg = opcode == 95;

	if (!neg) {
		r_strbuf_appendf (
			&op->esil,
				"0"	CM
				"%s%d"	CM
				"<"	CM
				"?{"	CM
				"0"     CM
				"%s%d"	CM
				"-"     CM
				"}"	CM
				"0"	CM
				"%s%d"	CM
				">="	CM
				"?{"	CM
				"%s%d"	CM
				"}"	CM,
			xtensa_regfile_shortname (isa, src_rf),
			src_reg,
			xtensa_regfile_shortname (isa, src_rf),
			src_reg,
			xtensa_regfile_shortname (isa, src_rf),
			src_reg,
			xtensa_regfile_shortname (isa, src_rf),
			src_reg
		);
	} else {
		r_strbuf_appendf (
			&op->esil,
				"0"	CM
				"%s%d"	CM
				"-"	CM,
			xtensa_regfile_shortname (isa, src_rf),
			src_reg
		);
	}

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"="	CM,
		xtensa_regfile_shortname (isa, dst_rf),
		dst_reg
	);
}

static void esil_call(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	bool call = opcode == 76;
	st32 imm_offset;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer,
			(ut32 *) &imm_offset);

	if (call) {
		r_strbuf_append(
			&op->esil,
			"pc"	CM
			"a0"	CM
			"="	CM
		);
	}

	sign_extend (&imm_offset, 17);

	if (call) {
		imm_offset <<= 2;
	}

	imm_offset += 4 - 3;

	esil_push_signed_imm (&op->esil, imm_offset);

	r_strbuf_append (&op->esil, "pc" CM "+=");
}

static void esil_callx(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	bool callx = opcode == 77;
	ut32 dst_reg;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &dst_reg);
	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);

	r_strbuf_appendf (
		&op->esil,
		"%s%d" CM "0" CM "+" CM,
		xtensa_regfile_shortname (isa, dst_rf),
		dst_reg
	);

	if (callx) {
		r_strbuf_append (
			&op->esil,
			"pc"	CM
			"a0"	CM
			"="	CM
		);
	}

	r_strbuf_append (&op->esil, "pc" CM "=");
}

static void esil_set_shift_amount(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 src_reg;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &src_reg);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 0);

	r_strbuf_appendf (
		&op->esil,
			"%s%d"	CM
			"sar"	CM
			"=",
		xtensa_regfile_shortname (isa, src_rf),
		src_reg
	);
}

static void esil_set_shift_amount_imm(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 sa_imm;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &sa_imm);
	xtensa_operand_decode (isa, opcode, 0, &sa_imm);

	r_strbuf_appendf (
		&op->esil,
			"0x%x"	CM
			"sar"	CM
			"=",
		sa_imm
	);
}

static void esil_shift_logic_imm(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 reg_dst;
	ut32 reg_src;
	ut32 imm_amount;

	const char *shift_op = "";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg_dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &reg_src);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &imm_amount);
	xtensa_operand_decode (isa, opcode, 2, &imm_amount);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	// srli
	if (opcode == 113) {
		shift_op = ">>";
	} else {
		shift_op = "<<";
	}

	r_strbuf_appendf (
		&op->esil,
			"0x%x"	CM
			"%s%d"	CM
			"%s"	CM
			"%s%d"	CM
			"=",
		imm_amount,
		xtensa_regfile_shortname (isa, src_rf),
		reg_src,
		shift_op,
		xtensa_regfile_shortname (isa, dst_rf),
		reg_dst
	);
}

static void esil_shift_logic_sar(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 reg_dst;
	ut32 reg_src;

	const char *shift_op = "";

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg_dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &reg_src);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	// srl
	if (opcode == 109) {
		shift_op = ">>";
	} else {
		shift_op = "<<";
	}

	r_strbuf_appendf (
		&op->esil,
			"sar"	CM
			"%s%d"	CM
			"%s"	CM
			"%s%d"	CM
			"=",
		xtensa_regfile_shortname (isa, src_rf),
		reg_src,
		shift_op,
		xtensa_regfile_shortname (isa, dst_rf),
		reg_dst
	);
}

static void esil_extract_unsigned(xtensa_isa isa, xtensa_opcode opcode,
		xtensa_format format, size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	ut32 reg_dst;
	ut32 reg_src;
	ut32 imm_shift;
	ut32 imm_mask;

	xtensa_operand_get_field (isa, opcode, 0, format, i, slot_buffer, &reg_dst);
	xtensa_operand_get_field (isa, opcode, 1, format, i, slot_buffer, &reg_src);
	xtensa_operand_get_field (isa, opcode, 2, format, i, slot_buffer, &imm_shift);
	xtensa_operand_get_field (isa, opcode, 3, format, i, slot_buffer, &imm_mask);

	xtensa_regfile dst_rf = xtensa_operand_regfile (isa, opcode, 0);
	xtensa_regfile src_rf = xtensa_operand_regfile (isa, opcode, 1);

	ut32 and_mask = (1 << (imm_mask + 1)) - 1;

	r_strbuf_appendf (
		&op->esil,
			"0x%x"	CM
			"%s%d"	CM
			">>"	CM
			"0x%x"	CM
			"&"	CM
			"%s%d"	CM
			"=",
		imm_shift,
		xtensa_regfile_shortname (isa, src_rf),
		reg_src,
		and_mask,
		xtensa_regfile_shortname (isa, dst_rf),
		reg_dst
	);
}

static void analop_esil (xtensa_isa isa, xtensa_opcode opcode, xtensa_format format,
						 size_t i, xtensa_insnbuf slot_buffer, RAnalOp *op) {
	switch (opcode) {
	case 26: /* add.n */
	case 41: /* add */
	case 43: /* addx2 */
	case 44: /* addx4 */
	case 45: /* addx8 */
	case 42: /* sub */
	case 46: /* subx2 */
	case 47: /* subx4 */
	case 48: /* subx8 */
		esil_add_sub (isa, opcode, format, i, slot_buffer, op);
		break;
	case 32: /* mov.n */
		esil_move (isa, opcode, format, i, slot_buffer, op);
		break;
	case 90: /* movi */
	case 33: /* movi.n */
		esil_move_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 0:  /* excw */
	case 34: /* nop.n */
		r_strbuf_setf (&op->esil, "%s", "");
		break;
	// TODO: s32cli (s32c1i) is conditional (CAS)
	// should it be handled here?
	case 453: /* s32c1i */
	case 36:  /* s32i.n */
	case 100: /* s32i */
	case 99:  /* s16i */
	case 101: /* s8i */
		esil_store_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 27: /* addi.n */
	case 39: /* addi */
		xtensa_check_stack_op (isa, opcode, format, i, slot_buffer, op);
		esil_add_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 98: /* ret */
	case 35: /* ret.n */
		r_strbuf_setf (&op->esil, "a0,pc,=");
		break;
	case 82: /* l16ui */
	case 83: /* l16si */
	case 84: /* l32i */
	case 31: /* l32i.n */
	case 86: /* l8ui */
		esil_load_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	// TODO: s32r
	// l32r is different because it is relative to LITBASE
	// which also may or may not be present
	case 85: /* l32r */
		esil_load_relative (isa, opcode, format, i, slot_buffer, op);
		break;
	case 40: /* addmi */
		break;
	case 49: /* and */
	case 50: /* or */
	case 51: /* xor */
		esil_bitwise_op (isa, opcode, format, i, slot_buffer, op);
		break;
	case 52: /* beqi */
	case 53: /* bnei */
	case 54: /* bgei */
	case 55: /* blti */
	case 58: /* bgeui */
	case 59: /* bltui */
		esil_branch_compare_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 56: /* bbci */
	case 57: /* bbsi */
		esil_branch_check_bit_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 60: /* beq */
	case 61: /* bne */
	case 62: /* bge */
	case 63: /* blt */
	case 64: /* bgeu */
	case 65: /* bltu */
		esil_branch_compare (isa, opcode, format, i, slot_buffer, op);
		break;
	case 66: /* bany */
	case 67: /* bnone */
	case 68: /* ball */
	case 69: /* bnall */
		esil_branch_check_mask (isa, opcode, format, i, slot_buffer, op);
		break;
	case 70: /* bbc */
	case 71: /* bbs */
		esil_branch_check_bit (isa, opcode, format, i, slot_buffer, op);
		break;
	case 72: /* beqz */
	case 73: /* bnez */
	case 28: /* beqz.n */
	case 29: /* bnez.n */
	case 74: /* bgez */
	case 75: /* bltz */
		esil_branch_compare_single (isa, opcode, format, i, slot_buffer, op);
		break;
	case 78: /* extui */
		esil_extract_unsigned (isa, opcode, format, i, slot_buffer, op);
		break;
	case 79: /* ill */
		r_strbuf_setf (&op->esil, "%s", "");
		break;
	// TODO: windowed calls?
	case 7: /* call4 */
		break;
	case 76: /* call0 */
	case 80: /* j */
		esil_call (isa, opcode, format, i, slot_buffer, op);
		break;
	case 81: /* jx */
	case 77: /* callx0 */
		esil_callx (isa, opcode, format, i, slot_buffer, op);
		break;
	case 91: /* moveqz */
	case 92: /* movnez */
	case 93: /* movltz */
	case 94: /* movgez */
		esil_move_conditional (isa, opcode, format, i, slot_buffer, op);
		break;
	case 96: /* abs */
	case 95: /* neg */
		esil_abs_neg (isa, opcode, format, i, slot_buffer, op);
		break;
	case 102: /* ssr */
	case 103: /* ssl */
		esil_set_shift_amount (isa, opcode, format, i, slot_buffer, op);
		break;
	case 111: /* slli */
	case 113: /* srli */
		esil_shift_logic_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 106: /* ssai */
		esil_set_shift_amount_imm (isa, opcode, format, i, slot_buffer, op);
		break;
	case 107: /* sll */
	case 109: /* srl */
		esil_shift_logic_sar (isa, opcode, format, i, slot_buffer, op);
		break;
	}
}

static int xtensa_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf_original, int len_original, RAnalOpMask mask) {
	if (!op) {
		return 1;
	}

	op->size = xtensa_length (buf_original);
	if (op->size > len_original) {
		return 1;
	}

	xtensa_op0_fns[(buf_original[0] & 0xf)] (anal, op, addr, buf_original);

	ut8 buffer[XTENSA_MAX_LENGTH] = { 0 };
	int len = R_MIN(op->size, XTENSA_MAX_LENGTH);
	memcpy (buffer, buf_original, len);

	unsigned int i;
	if (!xtensa_default_isa) {
		xtensa_default_isa = xtensa_isa_init (0, 0);
	}

	xtensa_opcode opcode;
	xtensa_isa isa = xtensa_default_isa;
	xtensa_format format;
	int nslots;

	static xtensa_insnbuf insn_buffer = NULL;
	static xtensa_insnbuf slot_buffer = NULL;

	if (!insn_buffer) {
		insn_buffer = xtensa_insnbuf_alloc (isa);
		slot_buffer = xtensa_insnbuf_alloc (isa);
	}

	memset (insn_buffer, 0,	xtensa_insnbuf_size (isa) * sizeof(xtensa_insnbuf_word));

	xtensa_insnbuf_from_chars (isa, insn_buffer, buffer, len);
	format = xtensa_format_decode (isa, insn_buffer);

	if (format == XTENSA_UNDEFINED) {
		return op->size;
	}

	nslots = xtensa_format_num_slots (isa, format);
	if (nslots < 1) {
		return op->size;
	}

	for (i = 0; i < nslots; i++) {
		xtensa_format_get_slot (isa, format, i, insn_buffer, slot_buffer);
		opcode = xtensa_opcode_decode (isa, format, i, slot_buffer);

		if (opcode == 39) { /* addi */
			xtensa_check_stack_op (isa, opcode, format, i, slot_buffer, op);
		}

		if (mask & R_ANAL_OP_MASK_ESIL) {
			analop_esil (isa, opcode, format, i, slot_buffer, op);
		}
	}

	return op->size;
}

static char *get_reg_profile(RAnal *anal) {
	return strdup (
		// Assuming call0 ABI
		"# a0		return address\n"
		"# a1		stack pointer\n"
		"# a2-a7	arguments\n"
		"# a2-a5	return value (call0 ABI)\n"
		"# a12-a15	callee-saved (call0 ABI)\n"
		"=PC	pc\n"
		"=BP	a14\n"
		"=SP	a1\n"
		"=A0	a2\n"
		"=A1	a3\n"
		"=A2	a4\n"
		"=A3	a5\n"
		"=A4	a6\n"
		"=A5	a7\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	16	0\n"
		"gpr	a4	.32	20	0\n"
		"gpr	a5	.32	24	0\n"
		"gpr	a6	.32	28	0\n"
		"gpr	a7	.32	32	0\n"
		"gpr	a8	.32	36	0\n"
		"gpr	a9	.32	40	0\n"
		"gpr	a10	.32	44	0\n"
		"gpr	a11	.32	48	0\n"
		"gpr	a12	.32	52	0\n"
		"gpr	a13	.32	56	0\n"
		"gpr	a14	.32	60	0\n"
		"gpr	a15	.32	64	0\n"

		// pc
		"gpr	pc	.32	68	0\n"

		// sr
		"gpr	sar	.32	72	0\n"
	);
}

RAnalPlugin r_anal_plugin_xtensa = {
	.name = "xtensa",
	.desc = "Xtensa disassembler",
	.license = "LGPL3",
	.arch = "xtensa",
	.bits = 8,
	.esil = true,
	.op = &xtensa_op,
	.get_reg_profile = get_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_xtensa,
	.version = R2_VERSION
};
#endif
