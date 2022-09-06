/* radare2 - LGPL - Copyright 2019-2022 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>
#include "../../asm/arch/or1k/or1k_disas.h"

struct operands {
	ut32 rd;
	ut32 ra;
	ut32 rb;
	ut32 n;
	ut32 k1;
	ut32 k2;
	ut32 k;
	ut32 i;
	ut32 l;
};

static R_TH_LOCAL ut32 cpu[32] = {0}; /* register contents */
static R_TH_LOCAL ut32 cpu_enable; /* allows to treat only registers with known value as valid */

static char *insn_to_str(RAnal *a, ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
	struct operands o = {0};
	insn_type_t type = type_of_opcode (descr, extra);
	insn_type_descr_t *type_descr = &types[INSN_X];

	/* only use type descriptor if it has some useful data */
	if (has_type_descriptor (type) && is_type_descriptor_defined (type)) {
		type_descr = &types[type];
	}

	o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
	o.ra = get_operand_value (insn, type_descr, INSN_OPER_A);
	o.rb = get_operand_value (insn, type_descr, INSN_OPER_B);
	o.k1 = get_operand_value (insn, type_descr, INSN_OPER_K1);
	o.k2 = get_operand_value (insn, type_descr, INSN_OPER_K2);
	o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
	o.k = get_operand_value (insn, type_descr, INSN_OPER_K);
	o.i = get_operand_value (insn, type_descr, INSN_OPER_I);
	o.l = get_operand_value (insn, type_descr, INSN_OPER_L);

	char *name = extra? extra->name: descr->name;
	if (!name || !type_descr->format) {
		/* this should not happen, give up */
		return strdup ("invalid");
	}

	switch (type) {
	case INSN_X:
		return r_str_newf (type_descr->format, name);
	case INSN_N:
		return r_str_newf (type_descr->format, name, (sign_extend(o.n, get_operand_mask (type_descr, INSN_OPER_N)) << 2) + addr);
	case INSN_K:
		return r_str_newf (type_descr->format, name, o.k);
	case INSN_DK:
		return r_str_newf (type_descr->format, name, o.rd, o.k);
	case INSN_DN:
		return r_str_newf (type_descr->format, name, o.rd, o.n << 13);
	case INSN_B:
		return r_str_newf (type_descr->format, name, o.rb);
	case INSN_D:
		return r_str_newf (type_descr->format, name, o.rd);
	case INSN_AI:
		return r_str_newf (type_descr->format, name, o.ra, o.i);
	case INSN_DAI:
		return r_str_newf (type_descr->format, name, o.rd, o.ra, o.i);
	case INSN_DAK:
		return r_str_newf (type_descr->format, name, o.rd, o.ra, o.i);
	case INSN_DAL:
		return r_str_newf (type_descr->format, name, o.rd, o.ra, o.l);
	case INSN_DA:
		return r_str_newf (type_descr->format, name, o.rd, o.ra);
	case INSN_DAB:
		return r_str_newf (type_descr->format, name, o.rd, o.ra, o.rb);
	case INSN_AB:
		return r_str_newf (type_descr->format, name, o.ra, o.rb);
	case INSN_IABI:
		return r_str_newf (type_descr->format, name, o.ra, o.rb, (o.k1 << 11) | o.k2);
	case INSN_KABK:
		return r_str_newf (type_descr->format, name, o.ra, o.rb, (o.k1 << 11) | o.k2);
	default:
		R_LOG_DEBUG ("Unhandled instruction type");
		break;
	}
	return strdup ("invalid");
}


/**
 * \brief Convert raw N operand to complete address
 *
 * \param n immediate, as appearing in instruction
 * \param mask n operand mask
 * \param addr address of current instruction
 *
 * \return 64-bit address
 */
static ut64 n_oper_to_addr(ut32 n, ut32 mask, ut64 addr) {
	/* sign extension returns 32b unsigned N, then it is multiplied by 4, made
	 * signed to support negative offsets, added to address and made unsigned
	 * again */
	return (ut64) ((st64) ((st32) (sign_extend(n, mask) << 2)) + addr);
}

static int insn_to_op(RAnal *a, RAnalOp *op, ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
	struct operands o = {0};
	insn_type_t type = type_of_opcode(descr, extra);
	insn_type_descr_t *type_descr = &types[INSN_X];

	/* only use type descriptor if it has some useful data */
	if (has_type_descriptor(type) && is_type_descriptor_defined(type)) {
		type_descr = &types[type];
	}

	op->type = extra? extra->insn_type: descr->insn_type;
	switch ((insn & INSN_OPCODE_MASK) >> INSN_OPCODE_SHIFT) {
	case 0x00: /* l.j */
		o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
		op->eob = true;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->delay = 1;
		break;
	case 0x01: /* l.jal */
		o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
		op->eob = true;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->delay = 1;
		break;
	case 0x03: /* l.bnf */
		o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
		op->cond = R_ANAL_COND_NE;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->fail = addr + 8;
		op->delay = 1;
		break;
	case 0x04: /* l.bf */
		o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
		op->cond = R_ANAL_COND_EQ;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->fail = addr + 8;
		op->delay = 1;
		break;
	case 0x11: /* l.jr */
		o.rb = get_operand_value (insn, type_descr, INSN_OPER_B);
		op->eob = true;
		if (cpu_enable & (1 << o.rb)) {
			op->jump = cpu[o.rb];
		}
		op->delay = 1;
		break;
	case 0x12: /* l.jalr */
		o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
		op->eob = true;
		if (cpu_enable & (1 << o.rb)) {
			op->jump = cpu[o.rb];
		}
		op->delay = 1;
		break;
	case 0x06: /* extended */
		switch (insn & (1 << 16)) {
		case 0: /* l.movhi */
			o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
			o.k = get_operand_value (insn, type_descr, INSN_OPER_K);
			cpu[o.rd] = o.k << 16;
			cpu_enable |= (1 << o.rd);
			break;
		case 1: /* l.macrc */
			break;
		}
		break;
	case 0x27: /* l.addi */
		o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
		o.ra = get_operand_value (insn, type_descr, INSN_OPER_A);
		o.i = get_operand_value (insn, type_descr, INSN_OPER_I);
		if (cpu_enable & (1 << o.ra) & cpu_enable & (1 << o.rd)) {
			cpu[o.rd] = cpu[o.ra] | o.i;
			cpu_enable |= (1 << o.rd);
			op->ptr = cpu[o.rd];
			op->direction = 8; /* reference */
		}
		break;
	case 0x2a: /* l.ori */
		o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
		o.ra = get_operand_value (insn, type_descr, INSN_OPER_A);
		o.i = get_operand_value (insn, type_descr, INSN_OPER_I);
		if (cpu_enable & (1 << o.ra)) {
			cpu[o.rd] = cpu[o.ra] | o.i;
			cpu_enable |= (1 << o.rd);
			op->ptr = cpu[o.rd];
			op->direction = 8; /* reference */
		}
		break;
	default:
		/* if unknown instruction encountered, better forget state */
		cpu_enable = 0;
	}

	/* temporary solution to prevent using wrong register values */
	if ((op->type & R_ANAL_OP_TYPE_JMP) == R_ANAL_OP_TYPE_JMP) {
		/* FIXME: handle delay slot after branches */
		cpu_enable = 0;
	}
	return 4;
}

static int or1k_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	insn_t *insn_descr;
	insn_extra_t *extra_descr;

	/* read instruction and basic opcode value */
	ut32 insn = r_read_be32 (data);
	op->size = 4;
	ut32 opcode = (insn & INSN_OPCODE_MASK);
	ut8 opcode_idx = (opcode >> INSN_OPCODE_SHIFT) & 0xff;

	/* make sure instruction descriptor table is not overflowed */
	if (opcode_idx >= insns_count) {
		return op->size;
	}

	/* if instruction is marked as invalid finish processing now */
	insn_descr = &or1k_insns[opcode_idx];
	if (insn_descr->type == INSN_INVAL) {
		return op->size;
	}

	/* if name is null, but extra is present, it means 6 most significant bits
	 * are not enough to decode instruction */
	char *line = NULL;
	if (!insn_descr->name && (insn_descr->extra)) {
		extra_descr = find_extra_descriptor (insn_descr->extra, insn);
		if (extra_descr) {
			insn_to_op (a, op, addr, insn_descr, extra_descr, insn);
			line = insn_to_str (a, addr, insn_descr, extra_descr, insn);
		}
	} else {
		/* otherwise basic descriptor is enough */
		insn_to_op (a, op, addr, insn_descr, NULL, insn);
		line = insn_to_str (a, addr, insn_descr, NULL, insn);
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		if (line) {
			op->mnemonic = line;
			line = NULL;
		} else {
			op->mnemonic = strdup ("invalid");
		}
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_or1k = {
	.name = "or1k",
	.desc = "OpenRISC 1000",
	.license = "LGPL3",
	.bits = 32,
	.arch = "or1k",
	.esil = false,
	.op = &or1k_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_or1k,
	.version = R2_VERSION
};
#endif
