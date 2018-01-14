/* radare - LGPL - Copyright 2017 - wargio */
#include "libps.h"
#include "libps_internal.h"

ps_operand_t ps_operands_array[] = {
	{ 0, 0}, // No Operand
	{ 5, 16}, // FA
	{ 5, 11}, // FB
	{ 5, 6}, // FC
	{ 5, 21}, // FD/FS
	{ 3, 23}, //crfD,
	{ 1, 16}, //WB,
	{ 3, 12}, //IB,
	{ 1, 10}, //WC,
	{ 3, 7}, //IC,
	{ 5, 16}, // RA
	{ 5, 11}, // RB
	{ 5, 16}, //DRA,
	{ 5, 11}, //DRB,
};


ps_opcode_t ps_opcodes_array[] = {
	{ psq_lx, "psq_lx", OPM (4, 6), OPM_MASK, { OP_FD, OP_RA, OP_RB, OP_WC, OP_IC}, "Paired Single Quantized Load Indexed"},
	{ psq_stx, "psq_stx", OPM (4, 7), OPM_MASK, { OP_FS, OP_RA, OP_RB, OP_WC, OP_IC}, "Paired Single Quantized Store Indexed"},
	{ psq_lux, "psq_lux", OPM (4, 38), OPM_MASK, { OP_FD, OP_RA, OP_RB, OP_WC, OP_IC}, "Paired Single Quantized Load with update Indexed"},
	{ psq_stux, "psq_stux", OPM (4, 39), OPM_MASK, { OP_FS, OP_RA, OP_RB, OP_WC, OP_IC}, "Paired Single Quantized Store with update Indexed"},

	{ psq_l, "psq_l", OP (56), OP_MASK, { OP_FD, OP_DRA, OP_WB, OP_IB}, "Paired Single Quantized Load"},
	{ psq_lu, "psq_lu", OP (57), OP_MASK, { OP_FD, OP_DRA, OP_WB, OP_IB}, "Paired Single Quantized Load with Update"},
	{ psq_st, "psq_st", OP (60), OP_MASK, { OP_FS, OP_DRA, OP_WB, OP_IB}, "Paired Single Quantized Store"},
	{ psq_stu, "psq_stu", OP (61), OP_MASK, { OP_FS, OP_DRA, OP_WB, OP_IB}, "Paired Single Quantized Store with update"},

	{ ps_div, "ps_div", OPSC (4, 18, 0), OPS_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single Divide"}, 
	{ ps_div_dot, "ps_div.", OPSC (4, 18, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single Divide"},
	{ ps_sub, "ps_sub", OPSC (4, 20, 0), OPS_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single Subtract"},
	{ ps_sub_dot, "ps_sub.", OPSC (4, 20, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single Subtract"},
	{ ps_add, "ps_add", OPSC (4, 21, 0), OPS_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single Add"},
	{ ps_add_dot, "ps_add.", OPSC (4, 21, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single Add"},
	{ ps_sel, "ps_sel", OPSC (4, 23, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Select"},
	{ ps_sel_dot, "ps_sel.", OPSC (4, 23, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Select"},
	{ ps_res, "ps_res", OPSC (4, 24, 0), OPS_MASK, { OP_FD, OP_FB}, "Paired Single Reciprocal Estimate"},
	{ ps_res_dot, "ps_res.", OPSC (4, 24, 1), OPS_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Reciprocal Estimate"},
	{ ps_mul, "ps_mul", OPSC (4, 25, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply"},
	{ ps_mul_dot, "ps_mul.", OPSC (4, 25, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply"},
	{ ps_rsqrte, "ps_rsqrte", OPSC (4, 26, 0), OPS_MASK, { OP_FD, OP_FB}, "Paired Single Reciprocal Square Root Estimate"},
	{ ps_rsqrte_dot, "ps_rsqrte.", OPSC (4, 26, 1), OPS_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Reciprocal Square Root Estimate"},
	{ ps_msub, "ps_msub", OPSC (4, 28, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Subtract"},
	{ ps_msub_dot, "ps_msub.", OPSC (4, 28, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Subtract"},
	{ ps_madd, "ps_madd", OPSC (4, 29, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add"},
	{ ps_madd_dot, "ps_madd.", OPSC (4, 29, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add"},
	{ ps_nmsub, "ps_nmsub", OPSC (4, 30, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Negative Multiply-Subtract"},
	{ ps_nmsub_dot, "ps_nmsub.", OPSC (4, 30, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Negative Multiply-Subtract"},
	{ ps_nmadd, "ps_nmadd", OPSC (4, 31, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Negative Multiply-Add"},
	{ ps_nmadd_dot, "ps_nmadd.", OPSC (4, 31, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Negative Multiply-Add"},

	{ ps_neg, "ps_neg", OPLC (4, 40, 0), OPL_MASK, { OP_FD, OP_FB}, "Paired Single Negate"},
	{ ps_neg_dot, "ps_neg.", OPLC (4, 40, 1), OPL_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Negate"},
	{ ps_mr, "ps_mr", OPLC (4, 72, 0), OPL_MASK, { OP_FD, OP_FB}, "Paired Single Move Register"},
	{ ps_mr_dot, "ps_mr.", OPLC (4, 72, 1), OPL_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Move Register"},
	{ ps_nabs, "ps_nabs", OPLC (4, 136, 0), OPL_MASK, { OP_FD, OP_FB}, "Paired Single Negative Absolute Value"},
	{ ps_nabs_dot, "ps_nabs.", OPLC (4, 136, 1), OPL_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Negative Absolute Value"},
	{ ps_abs, "ps_abs", OPLC (4, 264, 0), OPL_MASK, { OP_FD, OP_FB}, "Paired Single Absolute Value"},
	{ ps_abs_dot, "ps_abs.", OPLC (4, 264, 1), OPL_MASK_DOT, { OP_FD, OP_FB}, "Paired Single Absolute Value"},

	{ ps_sum0, "ps_sum0", OPSC (4, 10, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single vector SUM high"},
	{ ps_sum0_dot, "ps_sum0.", OPSC (4, 10, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single vector SUM high"},
	{ ps_sum1, "ps_sum1", OPSC (4, 11, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single vector SUM low"},
	{ ps_sum1_dot, "ps_sum1.", OPSC (4, 11, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single vector SUM low"},
	{ ps_muls0, "ps_muls0", OPSC (4, 12, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply Scalar high"},
	{ ps_muls0_dot, "ps_muls0.", OPSC (4, 12, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply Scalar high"},
	{ ps_muls1, "ps_muls1", OPSC (4, 13, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply Scalar low"},
	{ ps_muls1_dot, "ps_muls1.", OPSC (4, 13, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC}, "Paired Single Multiply Scalar low"},
	{ ps_madds0, "ps_madds0", OPSC (4, 14, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add Scalar high"},
	{ ps_madds0_dot, "ps_madds0.", OPSC (4, 14, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add Scalar high"},
	{ ps_madds1, "ps_madds1", OPSC (4, 15, 0), OPS_MASK, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add Scalar low"},
	{ ps_madds1_dot, "ps_madds1.", OPSC (4, 15, 1), OPS_MASK_DOT, { OP_FD, OP_FA, OP_FC, OP_FB}, "Paired Single Multiply-Add Scalar low"},

	{ ps_cmpu0, "ps_cmpu0", OPL (4, 0), OPL_MASK, { OP_crfD, OP_FA, OP_FB}, "Paired Singles Compare Unordered High"},
	{ ps_cmpo0, "ps_cmpo0", OPL (4, 32), OPL_MASK, { OP_crfD, OP_FA, OP_FB}, "Paired Singles Compare Ordered High"},
	{ ps_cmpu1, "ps_cmpu1", OPL (4, 64), OPL_MASK, { OP_crfD, OP_FA, OP_FB}, "Paired Singles Compare Unordered Low"},
	{ ps_cmpo1, "ps_cmpo1", OPL (4, 96), OPL_MASK, { OP_crfD, OP_FA, OP_FB}, "Paired Singles Compare Ordered Low"},

	{ ps_merge00, "ps_merge00", OPLC (4, 528, 0), OPL_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE high"},
	{ ps_merge00_dot, "ps_merge00.", OPLC (4, 528, 1), OPL_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE high"},
	{ ps_merge01, "ps_merge01", OPLC (4, 560, 0), OPL_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE direct"},
	{ ps_merge01_dot, "ps_merge01.", OPLC (4, 560, 1), OPL_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE direct"},
	{ ps_merge10, "ps_merge10", OPLC (4, 592, 0), OPL_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE swapped"},
	{ ps_merge10_dot, "ps_merge10.", OPLC (4, 592, 1), OPL_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE swapped"},
	{ ps_merge11, "ps_merge11", OPLC (4, 624, 0), OPL_MASK, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE low"},
	{ ps_merge11_dot, "ps_merge11.", OPLC (4, 624, 1), OPL_MASK_DOT, { OP_FD, OP_FA, OP_FB}, "Paired Single MERGE low"},

	{ ps_dcbz_l, "dcbz_l", OPL (4, 1014), OPL_MASK, { OP_RA, OP_RB}, "Data Cache Block Set to Zero Locked"},

};

bool libps_decode(ut32 data, ppcps_t* ps) {
	ut32 op = (data & OP_MASK);

	if ((op == OP (4)) || (op == OP (56)) ||
		(op == OP (57)) || (op == OP (60)) ||
		(op == OP (61))) {
		ut32 size = sizeof (ps_opcodes_array) / sizeof (ps_opcode_t);
		ps_opcode_t* instruction = ps_opcodes_array;

		ut32 l, j;
		for (l = 0; l < size; l++) {
			if ((data & instruction->mask) == instruction->opcode) {
				j = 0;
				for (;j < 6 && instruction->operands[j] != 0; j++) {
					ppcps_field_t* field = &ps->operands[j];
					ps_operand_t* ps_operand = &ps_operands_array[instruction->operands[j]];

					int bits = (data >> ps_operand->shift) & ((1 << ps_operand->bits) - 1);
					//int ext_bits = (bits << (32 - ps_operand->bits)) >> (32 - ps_operand->bits);

					switch (instruction->operands[j]) {
					case OP_FA:
					case OP_FB:
					case OP_FC:
					case OP_FD:
					{
						field->type = TYPE_REG;
						field->value = bits;
						break;
					}

					case OP_RA:
					case OP_RB:
					{
						field->type = TYPE_REG;
						field->value = bits;
						break;
					}

					case OP_crfD:
					{
						field->type = TYPE_CR;
						field->value = bits;
						break;
					}
					case OP_WB:
					case OP_IB:
					case OP_WC:
					case OP_IC:
					{
						field->type = TYPE_IMM;
						field->value = bits;
						break;
					}

					case OP_DRA:
					{
						ut16 imm = (ut16) (data & 0x7FF);
						ut16 sign = (ut16) (data & 0x800);
						st16 displacement = 0;
						if (sign == 0) {
							displacement = imm;
						} else {
							displacement = -1 * imm;
						}
						field->type = TYPE_MEM;
						field->value = bits + displacement;
						break;
					}

					default:
						break;
					}
				}
				ps->n = j;
				ps->name = instruction->name;
				ps->op = instruction->insn;
				return true;
			}
			instruction++;
		}
	}
	return false;
}

void libps_snprint(char* str, int size, ut64 addr, ppcps_t* instr) {
	ut32 i;
	int bufsize = size, add = 0;
	add = snprintf (str, bufsize, "%s", instr->name);
	for (i = 0; add > 0 && i < instr->n && add < bufsize; ++i) {
		if (instr->operands[i].type == TYPE_REG) {
			add += snprintf (str + add, bufsize - add, " fr%u", instr->operands[i].value);
		} else if (instr->operands[i].type == TYPE_IMM) {
			add += snprintf (str + add, bufsize - add, " 0x%x", instr->operands[i].value);
		} else if (instr->operands[i].type == TYPE_MEM) {
			add += snprintf (str + add, bufsize - add, " 0x%x(r%d)", instr->operands[i].value, instr->operands[i + 1].value);
			i++;
		} else if (instr->operands[i].type == TYPE_CR) {
			add += snprintf (str + add, bufsize - add, " cr%u", instr->operands[i].value);
		}
	}
}
