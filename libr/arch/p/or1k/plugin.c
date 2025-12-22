/* radare2 - LGPL - Copyright 2019-2023 - v3l0c1r4pt0r */

#include <r_arch.h>
#include "or1k_disas.h"

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

// XXX remove globals and move into init/fini data pointer or just reimplement this into an ctual anal plugin for 5.9 so maybe its not worth
struct or1k_regs {
	ut32 cpu[32]; /* register contents */
	ut32 cpu_enable; /* allows to treat only registers with known value as valid */
};

static bool or1k_init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s && !s->data, false);
	s->data = R_NEW0 (struct or1k_regs);
	return s->data? true: false;
}

static bool or1k_fini(RArchSession *s) {
	R_FREE (s->data);
	return true;
}

static char *insn_to_str(ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
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
	 * signed to support negative offsets, added to address and made unsigned again */
	return (ut64) ((st64) ((st32) (sign_extend(n, mask) << 2)) + addr);
}

static int insn_to_op(struct or1k_regs *regs, RAnalOp *op, ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
	struct operands o = {0};
	insn_type_t type = type_of_opcode (descr, extra);
	insn_type_descr_t *type_descr = &types[INSN_X];

	/* only use type descriptor if it has some useful data */
	if (has_type_descriptor (type) && is_type_descriptor_defined (type)) {
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
		op->cond = R_ANAL_CONDTYPE_NE;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->fail = addr + 8;
		op->delay = 1;
		break;
	case 0x04: /* l.bf */
		o.n = get_operand_value (insn, type_descr, INSN_OPER_N);
		op->cond = R_ANAL_CONDTYPE_EQ;
		op->jump = n_oper_to_addr (o.n, get_operand_mask(type_descr, INSN_OPER_N), addr);
		op->fail = addr + 8;
		op->delay = 1;
		break;
	case 0x11: /* l.jr */
		o.rb = get_operand_value (insn, type_descr, INSN_OPER_B);
		op->eob = true;
		if (regs->cpu_enable & (1 << o.rb)) {
			op->jump = regs->cpu[o.rb];
		}
		op->delay = 1;
		break;
	case 0x12: /* l.jalr */
		o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
		op->eob = true;
		if (regs->cpu_enable & (1 << o.rb)) {
			op->jump = regs->cpu[o.rb];
		}
		op->delay = 1;
		break;
	case 0x06: /* extended */
		switch (insn & (1 << 16)) {
		case 0: /* l.movhi */
			o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
			o.k = get_operand_value (insn, type_descr, INSN_OPER_K);
			regs->cpu[o.rd] = o.k << 16;
			regs->cpu_enable |= (1 << o.rd);
			break;
		case 1: /* l.macrc */
			break;
		}
		break;
	case 0x27: /* l.addi */
		o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
		o.ra = get_operand_value (insn, type_descr, INSN_OPER_A);
		o.i = get_operand_value (insn, type_descr, INSN_OPER_I);
		if (regs->cpu_enable & (1 << o.ra) && regs->cpu_enable & (1 << o.rd)) {
			regs->cpu[o.rd] = regs->cpu[o.ra] | o.i;
			regs->cpu_enable |= (1 << o.rd);
			op->ptr = regs->cpu[o.rd];
			op->direction = 8; /* reference */
		}
		break;
	case 0x2a: /* l.ori */
		o.rd = get_operand_value (insn, type_descr, INSN_OPER_D);
		o.ra = get_operand_value (insn, type_descr, INSN_OPER_A);
		o.i = get_operand_value (insn, type_descr, INSN_OPER_I);
		if (regs->cpu_enable & (1 << o.ra)) {
			regs->cpu[o.rd] = regs->cpu[o.ra] | o.i;
			regs->cpu_enable |= (1 << o.rd);
			op->ptr = regs->cpu[o.rd];
			op->direction = 8; /* reference */
		}
		break;
	default:
		/* if unknown instruction encountered, better forget state */
		regs->cpu_enable = 0;
	}

	/* temporary solution to prevent using wrong register values */
	if ((op->type & R_ANAL_OP_TYPE_JMP) == R_ANAL_OP_TYPE_JMP) {
		/* FIXME: handle delay slot after branches */
		regs->cpu_enable = 0;
	}
	return 4;
}

static bool or1k_op(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	struct or1k_regs *regs = a->data;
	insn_t *insn_descr;
	insn_extra_t *extra_descr;
	const ut64 addr = op->addr;
	const size_t len = op->size;
	const ut8 *data = op->bytes;
	if (len < 4) {
		return false;
	}

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
			insn_to_op (regs, op, addr, insn_descr, extra_descr, insn);
			line = insn_to_str (addr, insn_descr, extra_descr, insn);
		}
	} else {
		/* otherwise basic descriptor is enough */
		insn_to_op (regs, op, addr, insn_descr, NULL, insn);
		line = insn_to_str (addr, insn_descr, NULL, insn);
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (line) {
			op->mnemonic = line;
			line = NULL;
		} else {
			op->mnemonic = strdup ("invalid");
		}
	}

	free (line);
	return op->size;
}

static int archinfo(RArchSession *a, ut32 q) {
	return 1;
}

const RArchPlugin r_arch_plugin_or1k = {
	.meta = {
		.name = "or1k",
		.author = "v3l0c1r4pt0r",
		.desc = "OpenRISC 1000",
		.license = "LGPL-3.0-only",
	},
	.bits = 32,
	.arch = "or1k",
	.info = archinfo,
	.decode = &or1k_op,
	.init = or1k_init,
	.fini = or1k_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_or1k,
	.version = R2_VERSION
};
#endif
