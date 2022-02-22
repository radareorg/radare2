/* radare2 - LGPL - Copyright 2020-2021 - aemitt, pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <ht_uu.h>
#include <r_util/r_assert.h>
#include "encodings_dec.h"
#include "encodings_fmt.h"
#include "operations.h"
#include "arm64dis.h"

#define BITMASK_BY_WIDTH_COUNT 64
static const ut64 bitmask_by_width[BITMASK_BY_WIDTH_COUNT] = {
	0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff,
	0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff,
	0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 0x1ffffffLL, 0x3ffffffLL,
	0x7ffffffLL, 0xfffffffLL, 0x1fffffffLL, 0x3fffffffLL, 0x7fffffffLL, 0xffffffffLL,
	0x1ffffffffLL, 0x3ffffffffLL, 0x7ffffffffLL, 0xfffffffffLL, 0x1fffffffffLL,
	0x3fffffffffLL, 0x7fffffffffLL, 0xffffffffffLL, 0x1ffffffffffLL, 0x3ffffffffffLL,
	0x7ffffffffffLL, 0xfffffffffffLL, 0x1fffffffffffLL, 0x3fffffffffffLL, 0x7fffffffffffLL,
	0xffffffffffffLL, 0x1ffffffffffffLL, 0x3ffffffffffffLL, 0x7ffffffffffffLL,
	0xfffffffffffffLL, 0x1fffffffffffffLL, 0x3fffffffffffffLL, 0x7fffffffffffffLL,
	0xffffffffffffffLL, 0x1ffffffffffffffLL, 0x3ffffffffffffffLL, 0x7ffffffffffffffLL,
	0xfffffffffffffffLL, 0x1fffffffffffffffLL, 0x3fffffffffffffffLL, 0x7fffffffffffffffLL, 0xffffffffffffffffLL
};

#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)

#define ISIMM64(x) (insn->operands[x].operandClass == IMM32 || insn->operands[x].operandClass == IMM64  || insn->operands[x].operandClass == FIMM32)
#define ISREG64(x) (insn->operands[x].operandClass == REG || insn->operands[x].operandClass == MEM_REG)
#define ISMEM64(x) is_mem(insn->operands[x].operandClass)
#define ISCOND64(x) (insn->operands[x].operandClass == CONDITION)
#define REGID64(x) (insn->operands[x].reg[0])

static bool is_mem(OperandClass op) {
	return (
		op == MEM_REG      ||
		op == MEM_PRE_IDX  ||
		op == MEM_POST_IDX ||
		op == MEM_OFFSET   ||
		op == MEM_EXTENDED // dunno what these are
	);
}

#define REG64(x) (get_register_name(insn->operands[x].reg[0]))
#define REGSIZE64(x) (get_register_size(insn->operands[x].reg[0]))
#define REGBITS64(x) ((int)get_register_size(insn->operands[x].reg[0])*8)
#define GETIMM64(x) ((ut64)insn->operands[x].immediate)

#define MEMBASE64(x) (get_register_name(insn->operands[x].reg[0]))
#define MEMINDEX64(x) (get_register_name(insn->operands[x].reg[1]))
#define HASMEMINDEX64(x) (insn->operands[x].reg[1]) // uhh idk
#define MEMDISP64(x) ((ut64)insn->operands[x].immediate)

#define INSOP64(x) insn->operands[x]
#define OPCOUNT64() get_op_count(insn)

// #define ISWRITEBACK64() 0
#define ISPREINDEX32() ((OPCOUNT64() == 2) && (insn->operands[1].operandClass == MEM_PRE_IDX))
#define ISPOSTINDEX32() ((OPCOUNT64() == 3) && (insn->operands[1].operandClass == MEM_POST_IDX))
#define ISPREINDEX64() ((OPCOUNT64() == 3) && (insn->operands[2].operandClass == MEM_PRE_IDX))
#define ISPOSTINDEX64() ((OPCOUNT64() == 4) && (insn->operands[2].operandClass == MEM_POST_IDX))

static ut8 get_op_count(Instruction* insn) {
	ut8 i = 0;
	while (insn->operands[i].operandClass != NONE) i++;
	return i;
}

static int vas_size(ArrangementSpec vas) {
	switch (vas) {
	case ARRSPEC_NONE:
		return 0;
	case ARRSPEC_FULL: /* 128-bit v-reg unsplit, eg: REG_V0_Q0 */
		return 128;

	/* 128 bit v-reg considered as... */
	case ARRSPEC_2DOUBLES: /* (.2d) two 64-bit double-precision: REG_V0_D1, REG_V0_D0 */
		return 64;
	case ARRSPEC_4SINGLES: /* (.4s) four 32-bit single-precision: REG_V0_S3, REG_V0_S2, REG_V0_S1, REG_V0_S0 */
		return 32;
	case ARRSPEC_8HALVES: /* (.8h) eight 16-bit half-precision: REG_V0_H7, REG_V0_H6, (..., REG_V0_H0 */
		return 16;
	case ARRSPEC_16BYTES: /* (.16b) sixteen 8-bit values: REG_V0_B15, REG_V0_B14, (..., REG_V0_B01 */
		return 8;

	/* low 64-bit of v-reg considered as... */
	case ARRSPEC_1DOUBLE: /* (.d) one 64-bit double-precision: REG_V0_D0 */
		return 64;
	case ARRSPEC_2SINGLES: /* (.2s) two 32-bit single-precision: REG_V0_S1, REG_V0_S0 */
		return 32;
	case ARRSPEC_4HALVES: /* (.4h) four 16-bit half-precision: REG_V0_H3, REG_V0_H2, REG_V0_H1, REG_V0_H0 */
		return 16;
	case ARRSPEC_8BYTES: /* (.8b) eight 8-bit values: REG_V0_B7, REG_V0_B6, (..., REG_V0_B0 */
		return 8;

	/* low 32-bit of v-reg considered as... */
	case ARRSPEC_1SINGLE: /* (.s) one 32-bit single-precision: REG_V0_S0 */
		return 32;
	case ARRSPEC_2HALVES: /* (.2h) two 16-bit half-precision: REG_V0_H1, REG_V0_H0 */
		return 16;
	case ARRSPEC_4BYTES: /* (.4b) four 8-bit values: REG_V0_B3, REG_V0_B2, REG_V0_B1, REG_V0_B0 */
		return 8;

	/* low 16-bit of v-reg considered as... */
	case ARRSPEC_1HALF: /* (.h) one 16-bit half-precision: REG_V0_H0 */
		return 16;

	/* low 8-bit of v-reg considered as... */
	case ARRSPEC_1BYTE: /* (.b) one 8-bit byte: REG_V0_B0 */
		return 8;

	default:
		return 0;
	}
	return 0;
}

static int vas_count(ArrangementSpec vas) {
	switch (vas) {
	case ARRSPEC_NONE:
		return 0;
	case ARRSPEC_FULL: /* 128-bit v-reg unsplit, eg: REG_V0_Q0 */
		return 1;

	/* 128 bit v-reg considered as... */
	case ARRSPEC_2DOUBLES: /* (.2d) two 64-bit double-precision: REG_V0_D1, REG_V0_D0 */
		return 2;
	case ARRSPEC_4SINGLES: /* (.4s) four 32-bit single-precision: REG_V0_S3, REG_V0_S2, REG_V0_S1, REG_V0_S0 */
		return 4;
	case ARRSPEC_8HALVES: /* (.8h) eight 16-bit half-precision: REG_V0_H7, REG_V0_H6, (..., REG_V0_H0 */
		return 8;
	case ARRSPEC_16BYTES: /* (.16b) sixteen 8-bit values: REG_V0_B15, REG_V0_B14, (..., REG_V0_B01 */
		return 16;

	/* low 64-bit of v-reg considered as... */
	case ARRSPEC_1DOUBLE: /* (.d) one 64-bit double-precision: REG_V0_D0 */
		return 1;
	case ARRSPEC_2SINGLES: /* (.2s) two 32-bit single-precision: REG_V0_S1, REG_V0_S0 */
		return 2;
	case ARRSPEC_4HALVES: /* (.4h) four 16-bit half-precision: REG_V0_H3, REG_V0_H2, REG_V0_H1, REG_V0_H0 */
		return 4;
	case ARRSPEC_8BYTES: /* (.8b) eight 8-bit values: REG_V0_B7, REG_V0_B6, (..., REG_V0_B0 */
		return 8;

	/* low 32-bit of v-reg considered as... */
	case ARRSPEC_1SINGLE: /* (.s) one 32-bit single-precision: REG_V0_S0 */
		return 1;
	case ARRSPEC_2HALVES: /* (.2h) two 16-bit half-precision: REG_V0_H1, REG_V0_H0 */
		return 2;
	case ARRSPEC_4BYTES: /* (.4b) four 8-bit values: REG_V0_B3, REG_V0_B2, REG_V0_B1, REG_V0_B0 */
		return 4;

	/* low 16-bit of v-reg considered as... */
	case ARRSPEC_1HALF: /* (.h) one 16-bit half-precision: REG_V0_H0 */
	/* low 8-bit of v-reg considered as... */
	case ARRSPEC_1BYTE: /* (.b) one 8-bit byte: REG_V0_B0 */
		return 1;
		
	default:
		return 0;
	}
	return 0;
}

static const char *shift_type_name(ShiftType type) {
	switch (type) {
	case ShiftType_ASR:
		return "asr";
	case ShiftType_LSL:
		return "lsl";
	case ShiftType_LSR:
		return "lsr";
	case ShiftType_ROR:
		return "ror";
	/*case ARM_SFT_RRX:
		return "rrx";
	case ARM_SFT_ASR_REG:
		return "asr_reg";
	case ARM_SFT_LSL_REG:
		return "lsl_reg";
	case ARM_SFT_LSR_REG:
		return "lsr_reg";
	case ARM_SFT_ROR_REG:
		return "ror_reg";
	case ARM_SFT_RRX_REG:
		return "rrx_reg";*/
	default:
		return "";
	}
}


static const char *extender_name(ShiftType extender) {
	switch (extender) {
	case ShiftType_UXTB:
		return "uxtb";
	case ShiftType_UXTH:
		return "uxth";
	case ShiftType_UXTW:
		return "uxtw";
	case ShiftType_UXTX:
		return "uxtx";
	case ShiftType_SXTB:
		return "sxtb";
	case ShiftType_SXTH:
		return "sxth";
	case ShiftType_SXTW:
		return "sxtw";
	case ShiftType_SXTX:
		return "sxtx";
	default:
		return "";
	}
}

static int decode_sign_ext64(ShiftType extender) {
	switch (extender) {
	case ShiftType_UXTB:
	case ShiftType_UXTH:
	case ShiftType_UXTW:
	case ShiftType_UXTX:
		return 0;
	case ShiftType_SXTB:
		return 8;
	case ShiftType_SXTH:
		return 16;
	case ShiftType_SXTW:
		return 32;
	case ShiftType_SXTX:
		return 64;
	default:
		return 0;
	}
}


static const char *decode_shift_64(ShiftType shift) {
	static const char *E_OP_SR = ">>";
	static const char *E_OP_SL = "<<";
	static const char *E_OP_RR = ">>>";
	static const char *E_OP_AR = ">>>>";
	static const char *E_OP_VOID = "";

	switch (shift) {
	case ShiftType_ASR:
		return E_OP_AR;
	case ShiftType_LSR:
		return E_OP_SR;

	// need to include these "shifts"
	case ShiftType_SXTB:
	case ShiftType_SXTW:
	case ShiftType_SXTH:
	case ShiftType_SXTX:
	case ShiftType_UXTB:
	case ShiftType_UXTW:
	case ShiftType_UXTH:
	case ShiftType_UXTX:

	case ShiftType_LSL:
	case ShiftType_MSL:
		return E_OP_SL;

	case ShiftType_ROR:
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}

static void opex64(RStrBuf *buf, Instruction *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	Instruction *x = insn;
	for (i = 0; i < OPCOUNT64 (); i++) {
		InstructionOperand *op = x->operands + i;
		pj_o (pj);
		switch (op->operandClass) {
		case REG:
		case MULTI_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", get_register_name(op->reg[0]));
			break;
		case IMM32:
		case IMM64:
			pj_ks (pj, "type", "imm");
			pj_ki (pj, "value", op->immediate);
			break;
		case MEM_REG:
		case MEM_PRE_IDX:
		case MEM_POST_IDX:
		case MEM_OFFSET:
		case MEM_EXTENDED:
			pj_ks (pj, "type", "mem");
			if (op->operandClass == MEM_REG) {
				pj_ks (pj, "base", get_register_name(op->reg[0]));
			}
			if (op->reg[1]) {
				pj_ks (pj, "index", get_register_name(op->reg[1]));
			}
			/*pj_ki (pj, "scale", op->mem.scale);*/
			pj_ki (pj, "disp", op->immediate);
			break;
		case FIMM32:
			pj_ks (pj, "type", "fp");
			pj_kd (pj, "value", op->immediate);
			break;
		/*case ARM_OP_CIMM:
			pj_ks (pj, "type", "cimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_PIMM:
			pj_ks (pj, "type", "pimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_SETEND:
			pj_ks (pj, "type", "setend");
			switch (op->setend) {
			case ARM_SETEND_BE:
				pj_ks (pj, "value", "be");
				break;
			case ARM_SETEND_LE:
				pj_ks (pj, "value", "le");
				break;
			default:
				pj_ks (pj, "value", "invalid");
				break;
			}
			break;*/
		case SYS_REG:
			pj_ks (pj, "type", "sysreg");
			pj_ks (pj, "value", r_str_get_fail (get_system_register_name(op->sysreg), ""));
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		if (op->shiftType != ShiftType_NONE) {
			pj_ko (pj, "shift");
			switch (op->shiftType) {
			case ShiftType_ASR:
			case ShiftType_LSL:
			case ShiftType_LSR:
			case ShiftType_ROR:
				pj_ks (pj, "type", shift_type_name (op->shiftType));
				pj_kn (pj, "value", (ut64)op->shiftValue);
				break;
			/*case ARM_SFT_ASR_REG:
			case ARM_SFT_LSL_REG:
			case ARM_SFT_LSR_REG:
			case ARM_SFT_ROR_REG:
			case ARM_SFT_RRX_REG:
				pj_ks (pj, "type", shift_type_name (op->shift.type));
				pj_ks (pj, "value", cs_reg_name (handle, op->shift.value));
				break;*/
			default:
				break;
			}
			pj_end (pj); /* o shift */
		}
		if (op->extend != ShiftType_NONE) {
			pj_ks (pj, "ext", extender_name(op->extend));
		}
#if 0
		if (op->laneUsed) {
			pj_ki (pj, "vector_index", op->lane);
		}
#endif
		/*if (op->subtracted) {
			pj_kb (pj, "subtracted", true);
		}*/
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	if (x->setflags) {
		pj_kb (pj, "update_flags", true);
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}


#define VEC64_DST_APPEND(sb, n, i) vector64_dst_append(sb, insn, n, i)
#define SHIFTED_IMM64(n, sz) shifted_imm64(insn, n, sz)
#define LSHIFT2_64(n) (insn->operands[n].shiftValue)
#define EXT64(x) decode_sign_ext64 (insn->operands[x].extend)

// return postfix
const char* v35arm_prefix_cond(RAnalOp *op, Condition cond_type) {
	const char *close_cond[2];
	close_cond[0] = "\0";
	close_cond[1] = ",}\0";
	int close_type = 0;
	switch (cond_type) {
	case COND_EQ:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "zf,?{,");
		break;
	case COND_NE:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "zf,!,?{,");
		break;
	case COND_CS:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "cf,?{,");
		break;
	case COND_CC:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "cf,!,?{,");
		break;
	case COND_MI:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "nf,?{,");
		break;
	case COND_PL:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "nf,!,?{,");
		break;
	case COND_VS:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "vf,?{,");
		break;
	case COND_VC:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "vf,!,?{,");
		break;
	case COND_HI:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "cf,zf,!,&,?{,");
		break;
	case COND_LS:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "cf,!,zf,|,?{,");
		break;
	case COND_GE:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "nf,vf,^,!,?{,");
		break;
	case COND_LT:
		close_type = 1;
		r_strbuf_appendf (&op->esil, "nf,vf,^,?{,");
		break;
	case COND_GT:
		// zf == 0 && nf == vf
		close_type = 1;
		r_strbuf_appendf (&op->esil, "zf,!,nf,vf,^,!,&,?{,");
		break;
	case COND_LE:
		// zf == 1 || nf != vf
		close_type = 1;
		r_strbuf_appendf (&op->esil, "zf,nf,vf,^,|,?{,");
		break;
	case COND_AL:
		// always executed
		break;
	default:
		break;
	}
	return close_cond[close_type];
}

/*
static const char *cc_name64(Condition cc) {
	switch (cc) {
	case COND_EQ: // Equal
		return "eq";
	case COND_NE: // Not equal:                 Not equal, or unordered
		return "ne";
	case COND_CS: // Unsigned higher or same:   >, ==, or unordered
		return "hs";
	case COND_CC: // Unsigned lower or same:    Less than
		return "lo";
	case COND_MI: // Minus, negative:           Less than
		return "mi";
	case COND_PL: // Plus, positive or zero:    >, ==, or unordered
		return "pl";
	case COND_VS: // Overflow:                  Unordered
		return "vs";
	case COND_VC: // No overflow:               Ordered
		return "vc";
	case COND_HI: // Unsigned higher:           Greater than, or unordered
		return "hi";
	case COND_LS: // Unsigned lower or same:    Less than or equal
		return "ls";
	case COND_GE: // Greater than or equal:     Greater than or equal
		return "ge";
	case COND_LT: // Less than:                 Less than, or unordered
		return "lt";
	case COND_GT: // Signed greater than:       Greater than
		return "gt";
	case COND_LE: // Signed less than or equal: <, ==, or unordered
		return "le";
	default:
		return "";
	}
}
*/

static ut64 shifted_imm64(Instruction *insn, int n, int sz) {
	InstructionOperand op = INSOP64 (n);
	int sft = op.shiftValue;
	switch (op.shiftType) {
		case ShiftType_MSL:
			return (GETIMM64 (n) << sft) | ((1 << sft) - 1);
		case ShiftType_LSL:
			return GETIMM64 (n) << sft;
		case ShiftType_LSR:
			return GETIMM64 (n) >> sft;
		case ShiftType_ROR:
			return (GETIMM64 (n) >> sft)|(GETIMM64 (n) << (sz - sft));
		case ShiftType_ASR:
			switch (sz) {
				case 8:
					return (st8)GETIMM64 (n) >> sft;
				case 16:
					return (st16)GETIMM64 (n) >> sft;
				case 32:
					return (st32)GETIMM64 (n) >> sft;
				case 64:
				default:
					return (st64)GETIMM64 (n) >> sft;
			}
		default:
			return GETIMM64 (n);
	}
}
#define DECODE_SHIFT64(x) decode_shift_64(insn->operands[x].shiftType)

#define ARG64_APPEND(sb, n) arg64_append(sb, insn, n, -1, 0)
#define ARG64_SIGN_APPEND(sb, n, s) arg64_append(sb,insn, n, -1, s)
#define VECARG64_APPEND(sb, n, i, s) arg64_append(sb, insn, n, i, s)
#define COMMA(sb) r_strbuf_appendf (sb, ",")

// #define VEC64(n) insn->detail->arm64.operands[n].vess
#define VEC64_APPEND(sb, n, i) vector64_append(sb, insn, n, i)
#define VEC64_MASK(sh, sz) (bitmask_by_width[63]^(bitmask_by_width[sz-1]<<sh))

static void vector64_append(RStrBuf *sb, Instruction *insn, int n, int i) {
	InstructionOperand op = INSOP64 (n);
	if (op.laneUsed) {
		i = op.lane;
	}

	if (vas_size (op.arrSpec) && i != -1) {
		int size = vas_size (op.arrSpec);
		int shift = i * size;
		char *regc = "l";
		if (shift >= 64) {
			shift -= 64;
			regc = "h";
		}

		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		int width = size > 0? (size - 1) % s: 0;
		if (shift > 0) {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%d,%s%s,>>,&",
				bitmask_by_width[width], shift, REG64 (n), regc);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%s%s,&",
				bitmask_by_width[width], REG64 (n), regc);
		}
	} else {
		r_strbuf_appendf (sb, "%s", REG64 (n));
	}
}

static void vector64_dst_append(RStrBuf *sb, Instruction *insn, int n, int i) {
	InstructionOperand op = INSOP64 (n);
	
	if (op.laneUsed) {
		i = op.lane;
	}

	if (vas_size (op.arrSpec) && i != -1) {
		int size = vas_size (op.arrSpec);
		int shift = i * size;
		char *regc = "l";
		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		size_t index = size > 0? (size - 1) % s: 0;
		if (index >= BITMASK_BY_WIDTH_COUNT) {
			index = 0;
		}
		ut64 mask = bitmask_by_width[index];
		if (shift >= 64 && shift < 128) {
			shift -= 64;
			regc = "h";
		} else if (shift >= 128 || shift < 0) {
			shift = 0; // shouldnt happen
		}

		if (shift > 0 && shift < 64) {
			r_strbuf_appendf (sb, "%d,SWAP,0x%"PFMT64x",&,<<,%s%s,0x%"PFMT64x",&,|,%s%s",
				shift, mask, REG64 (n), regc, VEC64_MASK (shift, size), REG64 (n), regc);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x",&,%s%s,0x%"PFMT64x",&,|,%s%s",
				mask, REG64 (n), regc, VEC64_MASK (shift, size), REG64 (n), regc);
		}
	} else {
		r_strbuf_appendf (sb, "%s", REG64 (n));
	}
}

static void arg64_append(RStrBuf *sb, Instruction *insn, int n, int i, int sign) {
	InstructionOperand op = INSOP64 (n);
	int size = 64;
	if (ISREG64 (n)) {
		size = REGSIZE64 (n)*8;
	}

	const char *rn;
	if (ISIMM64 (n)) {
		ut64 imm = SHIFTED_IMM64 (n, size);
		r_strbuf_appendf (sb, "0x%"PFMT64x, imm);
		return;
	} else if (HASMEMINDEX64 (n)) {
		rn = MEMINDEX64 (n);
	} else {
		rn = REG64 (n);
	}

	int shift = LSHIFT2_64 (n);
	int signext = EXT64 (n);
	if (!signext) {
		// this is weird but signext+shift is all in shiftType?
		// not extend. why even have an extend field?
		// why not just shiftType = sx* with a shiftValue of 0? 
		signext = decode_sign_ext64 (op.shiftType);
	}
	if (sign && !signext) {
		signext = size;
	}

	if (signext) {
		r_strbuf_appendf (sb, "%d,", signext);
	}
	if (shift) {
		r_strbuf_appendf (sb, "%d,", shift);
	}

	if (op.laneUsed || vas_count (op.arrSpec)) {
		VEC64_APPEND (sb, n, i);
	} else {
		r_strbuf_appendf (sb, "%s", rn);
	}

	if (shift) {
		r_strbuf_appendf (sb, ",%s", DECODE_SHIFT64 (n));
	}
	if (signext) {
		r_strbuf_appendf (sb, ",~");
	}
}

#define OPCALL(opchar) arm64math(a, op, addr, buf, len, insn, opchar, 0, 0)
#define OPCALL_NEG(opchar) arm64math(a, op, addr, buf, len, insn, opchar, 1, 0)
#define OPCALL_SIGN(opchar, sign) arm64math(a, op, addr, buf, len, insn, opchar, 0, sign)

static void arm64math(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, Instruction *insn, const char *opchar, int negate, int sign) {
	InstructionOperand dst = INSOP64 (0);
	int i, c = (OPCOUNT64 () > 2) ? 1 : 0;

	int count = vas_count(dst.arrSpec);
	if (count) {
		int end = count;

		for (i = 0; i < end; i++) {
			VECARG64_APPEND (&op->esil, 2, i, sign);
			if (negate) {
				r_strbuf_appendf (&op->esil, ",-1,^");
			}
			COMMA (&op->esil);
			VECARG64_APPEND (&op->esil, 1, i, sign);
			r_strbuf_appendf (&op->esil, ",%s,", opchar);
			VEC64_DST_APPEND (&op->esil, 0, i);
			r_strbuf_appendf (&op->esil, ",=");
			if (i < end-1) COMMA (&op->esil);
		}
	} else {
		VECARG64_APPEND(&op->esil, c+1, -1, sign);
		if (negate) {
			r_strbuf_appendf (&op->esil, ",-1,^");
		}
		COMMA (&op->esil);
		VECARG64_APPEND (&op->esil, c, -1, sign);
		r_strbuf_appendf (&op->esil, ",%s,", opchar);
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_appendf (&op->esil, ",=");
	}
}

#define FPOPCALL(opchar) arm64fpmath(a, op, addr, buf, len, insn, opchar, 0)
#define FPOPCALL_NEGATE(opchar) arm64fpmath(a, op, addr, buf, len, insn, opchar, 1)

// floating point math instruction helper
static void arm64fpmath(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, Instruction *insn, const char *opchar, int negate) {
	int i, size = REGSIZE64 (1)*8;

	InstructionOperand dst = INSOP64 (0);
	int start = -1;
	int end = 0;
	int convert = size == 64 ? 0 : 1;
	int count = vas_count(dst.arrSpec);
	if (count) {
		start = 0;
		end = count;
	}

	for (i = start; i < end; i++) {
		if (convert) r_strbuf_appendf (&op->esil, "%d,DUP,", size);
		VEC64_APPEND (&op->esil, 2, i);
		if (convert) r_strbuf_appendf (&op->esil, ",F2D");
		if (negate) {
			r_strbuf_appendf (&op->esil, ",-F");
		}
		if (convert) r_strbuf_appendf (&op->esil, ",%d", size);
		COMMA (&op->esil);
		VEC64_APPEND (&op->esil, 1, i);
		if (convert) {
			r_strbuf_appendf (&op->esil, ",F2D,F%s,D2F,", opchar);	
		} else {
			r_strbuf_appendf (&op->esil, ",F%s,", opchar);	
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_appendf (&op->esil, ",=");
		if (i < end-1) COMMA (&op->esil);
	}
}

#define SET_FLAGS() r_strbuf_appendf (&op->esil, ",$z,zf,:=,%d,$s,nf,:=,%d,$c,cf,:=,%d,$o,vf,:=", REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) -1);

static void set_opdir(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		op->direction = R_ANAL_OP_DIR_READ;
		break;
	case R_ANAL_OP_TYPE_STORE:
		op->direction = R_ANAL_OP_DIR_WRITE;
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}


static void anop64(RAnal *a, RAnalOp *op, Instruction *insn) {
	ut64 addr = op->addr;

	/* grab family */
	/*if (cs_insn_group (handle, insn, ARM64_GRP_CRYPTO)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_CRC)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_PRIVILEGE)) {
		op->family = R_ANAL_OP_FAMILY_PRIV;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_NEON)) {
		op->family = R_ANAL_OP_FAMILY_MMX;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_FPARMV8)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
	} else {
		op->family = R_ANAL_OP_FAMILY_CPU;
	}

	op->cond = cond_cs2r2 (insn->detail->arm64.cc);
	if (op->cond == R_ANAL_COND_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}*/

	switch (insn->operation) {
	case ARM64_B_GE:
	case ARM64_B_GT:
	case ARM64_B_LE:
	case ARM64_B_LT:
		op->sign = true;
		break;
	default:
		break;
	}

	switch (insn->operation) {
	case ARM64_PACDA:
	case ARM64_PACDB:
	case ARM64_PACDZA:
	case ARM64_PACDZB:
	case ARM64_PACGA:
	case ARM64_PACIA:
	case ARM64_PACIA1716:
	case ARM64_PACIASP:
	case ARM64_PACIAZ:
	case ARM64_PACIB:
	case ARM64_PACIB1716:
	case ARM64_PACIBSP:
	case ARM64_PACIBZ:
	case ARM64_PACIZA:
	case ARM64_PACIZB:
	case ARM64_AUTDA:
	case ARM64_AUTDB:
	case ARM64_AUTDZA:
	case ARM64_AUTDZB:
	case ARM64_AUTIA:
	case ARM64_AUTIA1716:
	case ARM64_AUTIASP:
	case ARM64_AUTIAZ:
	case ARM64_AUTIB:
	case ARM64_AUTIB1716:
	case ARM64_AUTIBSP:
	case ARM64_AUTIBZ:
	case ARM64_AUTIZA:
	case ARM64_AUTIZB:
	case ARM64_XPACD:
	case ARM64_XPACI:
	case ARM64_XPACLRI:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
	case ARM64_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = GETIMM64(0);
		break;
	case ARM64_ADRP:
	case ARM64_ADR:
		op->type = R_ANAL_OP_TYPE_LEA;
		op->ptr = GETIMM64(1);
		break;
	case ARM64_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM64_SUB:
		if (ISREG64(0) && REGID64(0) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64(1)) {
				//sub sp, 0x54
				op->stackptr = GETIMM64(1);
			} else if (ISIMM64(2) && ISREG64(1) && REGID64(1) == REG_SP) {
				//sub sp, sp, 0x10
				op->stackptr = GETIMM64(2);
			}
			op->val = op->stackptr;
		} else {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_MSUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM64_FDIV:
	case ARM64_SDIV:
	case ARM64_UDIV:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ARM64_MUL:
	case ARM64_SMULL:
	case ARM64_FMUL:
	case ARM64_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case ARM64_ADD:
		if (ISREG64 (0) && REGID64 (0) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64 (1)) {
				//add sp, 0x54
				op->stackptr = -GETIMM64 (1);
			} else if (ISIMM64 (2) && ISREG64 (1) && REGID64 (1) == REG_SP) {
				//add sp, sp, 0x10
				op->stackptr = -GETIMM64 (2);
			}
			op->val = op->stackptr;
		} else {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_ADC:
	//case ARM64_ADCS:
	case ARM64_UMADDL:
	case ARM64_SMADDL:
	case ARM64_FMADD:
	case ARM64_MADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_CSEL:
	case ARM64_FCSEL:
	case ARM64_CSET:
	case ARM64_CINC:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case ARM64_MOV:
		if (REGID64(0) == REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_MOVI:
	case ARM64_MOVK:
	case ARM64_MOVN:
	case ARM64_SMOV:
	case ARM64_UMOV:
	case ARM64_FMOV:
	case ARM64_SBFX:
	case ARM64_UBFX:
	case ARM64_UBFM:
	case ARM64_SBFIZ:
	case ARM64_UBFIZ:
	case ARM64_BIC:
	case ARM64_BFI:
	case ARM64_BFXIL:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_MRS:
	case ARM64_MSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ARM64_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		op->val = GETIMM64(1);
		break;
	case ARM64_UXTB:
	case ARM64_SXTB:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM64_UXTH:
	case ARM64_SXTH:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_UXTW:
	case ARM64_SXTW:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_BRK:
	case ARM64_HLT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		// hlt stops the process, not skips some cycles like in x86
		break;
	case ARM64_DMB:
	case ARM64_DSB:
	case ARM64_ISB:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM64_IC: // instruction cache invalidate
	case ARM64_DC: // data cache invalidate
		op->type = R_ANAL_OP_TYPE_SYNC; // or cache
		break;
	//  XXX unimplemented instructions
	case ARM64_DUP:
	case ARM64_XTN:
	case ARM64_XTN2:
	case ARM64_REV64:
	case ARM64_EXT:
	case ARM64_INS:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_LSL:
		op->cycles = 1;
		/* fallthru */
	case ARM64_SHL:
	case ARM64_USHLL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_LSR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_ASR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ARM64_NEG:
	case ARM64_NEGS:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case ARM64_FCMP:
	case ARM64_CCMP:
	case ARM64_CCMN:
	case ARM64_CMP:
	case ARM64_CMN:
	case ARM64_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_ROR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM64_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM64_ORR:
	case ARM64_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM64_EOR:
	case ARM64_EON:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_STRB:
	case ARM64_STURB:
	case ARM64_STUR:
	case ARM64_STR:
	case ARM64_STP:
	case ARM64_STNP:
	case ARM64_STXR:
	case ARM64_STXRH:
	case ARM64_STLXR:
	case ARM64_STLXRH:
	case ARM64_STXRB:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (ISPREINDEX64 () && REGID64 (2) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && REGID64 (2) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -GETIMM64 (3);
		} else if (ISPREINDEX32 () && REGID64 (1) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -MEMDISP64 (1);
		} else if (ISPOSTINDEX32 () && REGID64 (1) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -GETIMM64 (2);
		}
		break;
	case ARM64_LDUR:
	case ARM64_LDURB:
	case ARM64_LDRSW:
	case ARM64_LDRSB:
	case ARM64_LDRSH:
	case ARM64_LDR:
	case ARM64_LDURSW:
	case ARM64_LDP:
	case ARM64_LDNP:
	case ARM64_LDPSW:
	case ARM64_LDRH:
	case ARM64_LDRB:
		if (ISPREINDEX64 () && REGID64 (2) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && REGID64 (2) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -GETIMM64 (3);
		} else if (ISPREINDEX32 () && REGID64 (1) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -MEMDISP64 (1);
		} else if (ISPOSTINDEX32 () && REGID64 (1) == REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -GETIMM64 (2);
		}
		if (0) { // REGID64(0) == REG_PC) { v35 has no REG_PC?
			op->type = R_ANAL_OP_TYPE_UJMP;
			/*if (insn->detail->arm.cc != ARM_CC_AL) {
				//op->type = R_ANAL_OP_TYPE_MCJMP;
				op->type = R_ANAL_OP_TYPE_UCJMP;
			}*/
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		switch (insn->operation) {
		case ARM64_LDPSW:
		case ARM64_LDRSW:
		case ARM64_LDRSH:
		case ARM64_LDRSB:
			op->sign = true;
			break;
		default:
			break;
		}
		if (REGID64 (1) == REG_X29) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		} else {
			if (ISIMM64(1)) {
				op->type = R_ANAL_OP_TYPE_LEA;
				op->ptr = GETIMM64(1);
				op->refptr = 8;
			} else {
				int d = (int)MEMDISP64(1);
				op->ptr = (d < 0)? -d: d;
				op->refptr = 4;
			}
		}
		break;
	case ARM64_BLRAA:
	case ARM64_BLRAAZ:
	case ARM64_BLRAB:
	case ARM64_BLRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case ARM64_LDRAA:
	case ARM64_LDRAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_RETAA:
	case ARM64_RETAB:
	case ARM64_ERETAA:
	case ARM64_ERETAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RET;
		break;

	case ARM64_ERET:
		op->family = R_ANAL_OP_FAMILY_PRIV;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_BL: // bl 0x89480
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = GETIMM64(0);
		op->fail = addr + 4;
		break;
	case ARM64_BLR: // blr x0
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->fail = addr + 4;
		//op->jump = IMM64(0);
		break;
	case ARM64_CBZ:
	case ARM64_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = GETIMM64(1);
		op->fail = addr+op->size;
		break;
	case ARM64_TBZ:
	case ARM64_TBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = GETIMM64(2);
		op->fail = addr+op->size;
		break;
	case ARM64_BR:
		op->type = R_ANAL_OP_TYPE_UJMP; // RJMP ?
		op->eob = true;
		break;
	case ARM64_B_AL:
	case ARM64_B:
		// BX LR == RET
		if (insn->operands[0].reg[0] == REG_X30) {
			op->type = R_ANAL_OP_TYPE_RET;
		/*} else if (insn->detail->arm64.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr + op->size;*/
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = GETIMM64(0);
		}
		break;
	case ARM64_B_CC:
	case ARM64_B_CS:
	case ARM64_B_EQ:
	case ARM64_B_GE:
	case ARM64_B_GT:
	case ARM64_B_HI:
	case ARM64_B_LE:
	case ARM64_B_LS:
	case ARM64_B_LT:
	case ARM64_B_MI:
	case ARM64_B_NE:
	// case ARM64_B_NV: return "b.nv"; uhh idk
	case ARM64_B_PL:
	case ARM64_B_VC:
	case ARM64_B_VS:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = GETIMM64(0);
		op->fail = addr + op->size;
		break;
	default:
		R_LOG_DEBUG ("ARM64 analysis: Op type %d at 0x%" PFMT64x " not handled\n", insn->operation, op->addr);
		break;
	}
}

static int analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, Instruction *insn) {

	const char *postfix = "";

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	/*if ISCOND64(1) {
		postfix = v35arm_prefix_cond (op, insn->operands[1].cond);
	} doesn't work this way is v35 */

	switch (insn->operation) {
	case ARM64_REV:
	case ARM64_REV64:
	// these REV* instructions were almost right, except in the cases like rev x0, x0
	// where the use of |= caused copies of the value to be erroneously present
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		int size = REGSIZE64 (1);
#if 0
		r_strbuf_setf (&op->esil,
			"0,%s,=,"               // dst = 0
			"%d,"                   // initial counter = size
			"DUP,"                  // counter: size -> 0 (repeat here)
			"DUP,1,SWAP,-,8,*,"     // counter to bits in source
			"DUP,0xff,<<,%s,&,>>,"  // src byte moved to LSB
			"SWAP,%d,-,8,*,"        // invert counter, calc dst bit
			"SWAP,<<,%s,|=,"        // shift left to there and insert
			"4,REPEAT",             // goto 5th instruction
			r0, size, r1, size, r0);
#endif
		if (size == 8) {
			r_strbuf_setf (&op->esil,
				"56,0xff,%s,&,<<,tmp,=,"
				"48,0xff,8,%s,>>,&,<<,tmp,|=,"
				"40,0xff,16,%s,>>,&,<<,tmp,|=,"
				"32,0xff,24,%s,>>,&,<<,tmp,|=,"
				"24,0xff,32,%s,>>,&,<<,tmp,|=,"
				"16,0xff,40,%s,>>,&,<<,tmp,|=,"
				"8,0xff,48,%s,>>,&,<<,tmp,|=,"
				"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
				r1, r1, r1, r1,
				r1, r1, r1, r1, r0);
		} else {
			r_strbuf_setf (&op->esil,
				"24,0xff,%s,&,<<,tmp,=,"
				"16,0xff,8,%s,>>,&,<<,tmp,|=,"
				"8,0xff,16,%s,>>,&,<<,tmp,|=,"
				"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
				r1, r1, r1, r1, r0);
		}
		break;
	}
	case ARM64_REV32:
		r_strbuf_setf (&op->esil,
			"24,0x000000ff000000ff,%s,&,<<,tmp,=,"
			"16,0x000000ff000000ff,8,%s,>>,&,<<,tmp,|=,"
			"8,0x000000ff000000ff,16,%s,>>,&,<<,tmp,|=,"
			"0x000000ff000000ff,24,%s,>>,&,tmp,|=,tmp,%s,=",
			REG64 (1), REG64 (1), REG64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_REV16:
		r_strbuf_setf (&op->esil,
			"8,0xff00ff00ff00ff00,%s,&,>>,tmp,=,"
			"8,0x00ff00ff00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
			REG64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_ADR:
		// TODO: must be 21bit signed
		r_strbuf_setf (&op->esil,
			"%"PFMT64u",%s,=", GETIMM64 (1), REG64 (0));
		break;
	case ARM64_SMADDL:
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,*,%s,+,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_UMADDL:
	case ARM64_MADD:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_MSUB:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,-,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_MNEG:
		r_strbuf_setf (&op->esil, "%s,%s,*,0,-,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_ADD:
	case ARM64_ADC: // Add with carry.
	//case ARM64_ADCS: // Add with carry.
		OPCALL("+");
		break;
	case ARM64_ADDS:
		OPCALL("+");
		SET_FLAGS();
		break;
	case ARM64_SUB:
		OPCALL("-");
		break;
	case ARM64_SUBS:
		OPCALL("-");
		r_strbuf_appendf (&op->esil,
			",$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) -1);

		break;
	case ARM64_SBC:
		// TODO have to check this more, VEX does not work
		r_strbuf_setf (&op->esil, "%s,cf,+,%s,-,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_SMULL2:
	case ARM64_SMULL:
		OPCALL_SIGN("*", REGBITS64 (1));
		break;
	case ARM64_UMULL2:
	case ARM64_UMULL:
	case ARM64_MUL:
		OPCALL("*");
		break;
	case ARM64_UMULH:
		r_strbuf_setf (&op->esil, "%s,%s,L*,SWAP,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_SMULH:
		// TODO this needs to be a 128 bit sign ext to be right
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,L*,SWAP,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_AND:
		OPCALL("&");
		break;
	case ARM64_ANDS:
		OPCALL("&");
		SET_FLAGS();
		break;
	case ARM64_ORR:
		OPCALL("|");
		break;
	case ARM64_ORRS:
		OPCALL("|");
		SET_FLAGS();
		break;
	case ARM64_EOR:
		OPCALL("^");
		break;
	case ARM64_EORS:
		OPCALL("+");
		SET_FLAGS();
		break;
	case ARM64_ORNS:
		OPCALL_NEG("|");
		SET_FLAGS();
		break;	
	case ARM64_ORN:
		OPCALL_NEG("|");
		break;
	case ARM64_EON:
		OPCALL_NEG("^");
		break;
	case ARM64_LSR:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64(2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND(&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = GETIMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL(">>");
		break;
	}
	case ARM64_LSL:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND(&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,<<,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,<<,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = GETIMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,<<,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL("<<");
		break;
	}
	case ARM64_ROR:
		OPCALL(">>>");
		break;
	case ARM64_NOP:
		r_strbuf_setf (&op->esil, ",");
		break;
	case ARM64_MOV:
	case ARM64_MOVI:
	case ARM64_FMOV:
	{
		if (0) {
			r_strbuf_setf (&op->esil, "%sh,%sh,=,%sl,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_appendf (&op->esil, ",");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_appendf (&op->esil, ",=");
		}
		break;
	}
	case ARM64_FCMP:
	case ARM64_FCMPE:
	case ARM64_FCCMP:
	case ARM64_FCCMPE:
		if (ISREG64 (1)) {
			r_strbuf_setf (&op->esil,
				"%d,%s,F2D,NAN,%d,%s,F2D,NAN,|,vf,:="
				",%d,%s,F2D,%d,%s,F2D,F==,vf,|,zf,:="
				",%d,%s,F2D,%d,%s,F2D,F<,vf,|,nf,:=",
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0)
			);	
		} else {
			r_strbuf_setf (&op->esil,
				"%d,%s,F2D,NAN,vf,:="
				",0,I2D,%d,%s,F2D,F==,vf,|,zf,:="
				",0,I2D,%d,%s,F2D,F<,vf,|,nf,:=",
				REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (0)
			);
		}

		if (insn->operation == ARM64_FCCMP || insn->operation == ARM64_FCCMPE) {
			r_strbuf_appendf (&op->esil, ",");
			//arm_prefix_cond(op, insn->operands[1].cond);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,0x%"PFMT64x",|,pstate,:=",
				GETIMM64(2) << 28);
		}
		break;
	case ARM64_FCVT:
		r_strbuf_setf (&op->esil, "%d,%d,%s,F2D,D2F,%s,=",
			REGBITS64 (0), REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_SCVTF:
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_SIGN_APPEND(&op->esil, 1, REGBITS64 (1));
		r_strbuf_appendf (&op->esil, ",S2D,D2F,");
		VEC64_DST_APPEND(&op->esil, 0, -1);
		r_strbuf_appendf (&op->esil, ",=");
		break;
	case ARM64_UCVTF:
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_APPEND(&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",U2D,D2F,");
		VEC64_DST_APPEND(&op->esil, 0, -1);
		r_strbuf_appendf (&op->esil, ",=");
		break;
	case ARM64_FCVTAU:
	case ARM64_FCVTAS:
	case ARM64_FCVTMU:
	case ARM64_FCVTMS:
	case ARM64_FCVTNU:
	case ARM64_FCVTNS:
	case ARM64_FCVTPU:
	case ARM64_FCVTPS:
	case ARM64_FCVTZU:
	case ARM64_FCVTZS:
		// TODO: unsigned int won't be right, idk entirely what it even means
		// also the rounding mode... idk i hate floats
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (1));
		ARG64_APPEND(&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",F2D,D2I,");
		VEC64_DST_APPEND(&op->esil, 0, -1);
		r_strbuf_appendf (&op->esil, ",=");
		break;
	case ARM64_FRINTA:
	case ARM64_FRINTI:
	case ARM64_FRINTN:
	case ARM64_FRINTX:
	case ARM64_FRINTZ:
	case ARM64_FRINTP:
	case ARM64_FRINTM:
	case ARM64_FRINT32X:
	case ARM64_FRINT32Z:
	case ARM64_FRINT64X:
	case ARM64_FRINT64Z:
	{
		char* rounder = "ROUND";
		if (insn->operation == ARM64_FRINTM) {
			rounder = "FLOOR";
		} else if (insn->operation == ARM64_FRINTP) {
			rounder = "CEIL";
		}
		r_strbuf_setf (&op->esil, "%d,DUP,", REGBITS64 (1));
		ARG64_APPEND(&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",F2D,%s,D2F,", rounder);
		VEC64_DST_APPEND(&op->esil, 0, -1);
		r_strbuf_appendf (&op->esil, ",=");
		break;
	}
	case ARM64_FABS:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,DUP,0,I2D,F<,?{,-F,},D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_FNEG:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_FSQRT:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,SQRT,D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_FMINNM:
	case ARM64_FMIN:
		r_strbuf_setf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<,?{,%s,}{,%s,},%s,=",
			REGBITS64 (2), REG64 (2),
			REGBITS64 (1), REG64 (1), REG64 (1), REG64 (2), REG64 (0));
		break;
	case ARM64_FMAXNM:
	case ARM64_FMAX:
		r_strbuf_setf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<,!,?{,%s,}{,%s,},%s,=",
			REGBITS64 (2), REG64 (2),
			REGBITS64 (1), REG64 (1), REG64 (1), REG64 (2), REG64 (0));
		break;
	case ARM64_FADD:
		FPOPCALL("+");
		break;
	case ARM64_FSUB:
		FPOPCALL("-");
		break;
	case ARM64_FMUL:
		FPOPCALL("*");
		break;
	case ARM64_FNMUL:
		FPOPCALL_NEGATE("*");
		break;
	case ARM64_FMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F+,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_FNMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F+,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_FMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F-,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_FNMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F-,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_FDIV:
		FPOPCALL("/");
		break;
	case ARM64_SDIV:
		// arm64 does not have a div-by-zero exception, just quietly sets R0 to 0
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL_SIGN ("~/", REGBITS64 (1));
		r_strbuf_appendf (&op->esil, ",}");
		break;
	case ARM64_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		// arm64 does not have a div-by-zero exception, just quietly sets R0 to 0
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL("/");
		r_strbuf_appendf (&op->esil, ",}");
		break;
	// TODO actually implement some kind of fake PAC or at least clear the bits
	// PAC B* instructions will not work without clearing PAC bits
	// but as long as the PAC* instruction is emulated too its fine
	// as those will be NOPS for now
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
	case ARM64_BR:
		r_strbuf_setf (&op->esil, "%s,pc,=", REG64 (0));
		break;
	case ARM64_BL:
		r_strbuf_setf (&op->esil, "pc,lr,=,%"PFMT64u",pc,=", GETIMM64 (0));
		break;
	case ARM64_BLRAA:
	case ARM64_BLRAAZ:
	case ARM64_BLRAB:
	case ARM64_BLRABZ:
	case ARM64_BLR:
		r_strbuf_setf (&op->esil, "pc,lr,=,%s,pc,=", REG64 (0));
		break;
	case ARM64_B_CC:
	case ARM64_B_CS:
	case ARM64_B_EQ:
	case ARM64_B_GE:
	case ARM64_B_GT:
	case ARM64_B_HI:
	case ARM64_B_LE:
	case ARM64_B_LS:
	case ARM64_B_LT:
	case ARM64_B_MI:
	case ARM64_B_NE:
	// case ARM64_B_NV: return "b.nv"; uhh idk
	case ARM64_B_PL:
	case ARM64_B_VC:
	case ARM64_B_VS:
		switch (insn->operation) {
		case ARM64_B_CC:
			v35arm_prefix_cond(op, COND_CC);
			break;
		case ARM64_B_CS:
			v35arm_prefix_cond(op, COND_CS);
			break;
		case ARM64_B_EQ:
			v35arm_prefix_cond(op, COND_EQ);
			break;
		case ARM64_B_GE:
			v35arm_prefix_cond(op, COND_GE);
			break;
		case ARM64_B_GT:
			v35arm_prefix_cond(op, COND_GT);
			break;
		case ARM64_B_HI:
			v35arm_prefix_cond(op, COND_HI);
			break;
		case ARM64_B_LE:
			v35arm_prefix_cond(op, COND_LE);
			break;
		case ARM64_B_LS:
			v35arm_prefix_cond(op, COND_LS);
			break;
		case ARM64_B_LT:
			v35arm_prefix_cond(op, COND_LT);
			break;
		case ARM64_B_MI:
			v35arm_prefix_cond(op, COND_MI);
			break;
		case ARM64_B_NE:
			v35arm_prefix_cond(op, COND_NE);
			break;
		case ARM64_B_PL:
			v35arm_prefix_cond(op, COND_PL);
			break;
		case ARM64_B_VC:
			v35arm_prefix_cond(op, COND_VC);
			break;
		case ARM64_B_VS:
			v35arm_prefix_cond(op, COND_VS);
			break;
		default:
			// unhandled
			break;
		}

		r_strbuf_appendf (&op->esil, "%"PFMT64u",pc,=,}", GETIMM64 (0));
		break;
	case ARM64_B_AL:
	case ARM64_B:
		/* capstone precompute resulting address, using PC + IMM */
		r_strbuf_appendf (&op->esil, "%"PFMT64u",pc,=", GETIMM64 (0));
		break;
	case ARM64_CLZ:
	{
		/*
		from https://en.wikipedia.org/wiki/Find_first_set modified for up to size 64
		function clz3 (x)
			if x = 0 return 32
			n ← 0
			if (x & 0xFFFF0000) = 0: n ← n + 16, x ← x << 16
			if (x & 0xFF000000) = 0: n ← n +  8, x ← x <<  8
			if (x & 0xF0000000) = 0: n ← n +  4, x ← x <<  4
			if (x & 0xC0000000) = 0: n ← n +  2, x ← x <<  2
			if (x & 0x80000000) = 0: n ← n +  1
			return n
		*/

		int size = 8*REGSIZE64 (0);
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);

		if (size == 32) {
			r_strbuf_setf (&op->esil,
			"%s,tmp,=,0,"
			"tmp,0xffff0000,&,!,?{,16,tmp,<<=,16,+,},"
			"tmp,0xff000000,&,!,?{,8,tmp,<<=,8,+,},"
			"tmp,0xf0000000,&,!,?{,4,tmp,<<=,4,+,},"
			"tmp,0xc0000000,&,!,?{,2,tmp,<<=,2,+,},"
			"tmp,0x80000000,&,!,?{,1,+,},"
			"%s,!,?{,32,%s,=,}{,%s,=,}",
			r1, r1, r0, r0);
		}
		else {
			r_strbuf_setf (&op->esil,
			"%s,tmp,=,0,"
			"tmp,0xffffffff00000000,&,!,?{,32,tmp,<<=,32,+,},"
			"tmp,0xffff000000000000,&,!,?{,16,tmp,<<=,16,+,},"
			"tmp,0xff00000000000000,&,!,?{,8,tmp,<<=,8,+,},"
			"tmp,0xf000000000000000,&,!,?{,4,tmp,<<=,4,+,},"
			"tmp,0xc000000000000000,&,!,?{,2,tmp,<<=,2,+,},"
			"tmp,0x8000000000000000,&,!,?{,1,+,},"
			"%s,!,?{,64,%s,=,}{,%s,=,}",
			r1, r1, r0, r0);
		}

		break;
	}
	case ARM64_LDRH:
	case ARM64_LDUR:
	case ARM64_LDURB:
	case ARM64_LDURH:
	case ARM64_LDTR:
	case ARM64_LDTRB:
	case ARM64_LDTRH:
	case ARM64_LDTRSB:
	case ARM64_LDTRSH:
	case ARM64_LDR:
	case ARM64_LDRB:
	case ARM64_LDXR:
	case ARM64_LDXRB:
	case ARM64_LDXRH:
	case ARM64_LDAXR:
	case ARM64_LDAXRB:
	case ARM64_LDAXRH:
	case ARM64_LDAR:
	case ARM64_LDARB:
	case ARM64_LDARH:
		{
			int size = REGSIZE64 (0);
			switch (insn->operation) {
			case ARM64_LDRB:
			case ARM64_LDARB:
			case ARM64_LDAXRB:
			case ARM64_LDXRB:
			case ARM64_LDURB:
			case ARM64_LDTRB:
			case ARM64_LDTRSB:
				size = 1;
				break;
			case ARM64_LDRH:
			case ARM64_LDARH:
			case ARM64_LDXRH:
			case ARM64_LDAXRH:
			case ARM64_LDURH:
			case ARM64_LDTRH:
			case ARM64_LDTRSH:
				size = 2;
				break;
			case ARM64_LDRSW:
			case ARM64_LDTRSW:
			case ARM64_LDURSW:
				size = 4;
				break;
			default:
				break;
			}

		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				ARG64_APPEND (&op->esil, 1);
				r_strbuf_appendf (&op->esil, ",%s,+,[%d],%s,=",
					MEMBASE64 (1), size, REG64 (0));
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%"PFMT64u",%s,+",
							MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%"PFMT64u",%s,-",
							-(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%"PFMT64u",%s,+",
							MEMDISP64 (1), MEMBASE64 (1));
				}
				

				if (ISPREINDEX32 () || ISPOSTINDEX32 ()) {
					r_strbuf_appendf (&op->esil, ",DUP,tmp,=");
				}

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX32 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],%s,=", size, REG64 (0));

				if (ISPOSTINDEX32 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64u",+,%s,=", GETIMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,[%d],%s,=",
						REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					
						/*This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.*/
					
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,=",
							REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%"PFMT64u",[%d],%s,=",
					GETIMM64 (1), size, REG64 (0));
			}
		}
		break;
		}
	case ARM64_LDRSB:
	case ARM64_LDRSH:
	case ARM64_LDRSW:
	case ARM64_LDURSB:
	case ARM64_LDURSH:
	case ARM64_LDURSW:
	{
		// handle the sign extended instrs here
		int size = REGSIZE64 (0);
		switch (insn->operation) {
		case ARM64_LDRSB:
		case ARM64_LDURSB:
			size = 1;
			break;
		case ARM64_LDRSH:
		case ARM64_LDURSH:
			size = 2;
			break;
		case ARM64_LDRSW:
		case ARM64_LDURSW:
			size = 4;
			break;
		default:
			break;
		}

		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				r_strbuf_appendf (&op->esil, "%d,%s,", size*8, MEMBASE64 (1));
				ARG64_APPEND(&op->esil, 1);
				r_strbuf_appendf (&op->esil, ",+,[%d],~,%s,=", size, REG64 (0));
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64u",%s",
							size*8, MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64u",%s,-",
							size*8, -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64u",%s,+",
							size*8, MEMDISP64 (1), MEMBASE64 (1));
				}

				if (ISPREINDEX32() || ISPOSTINDEX32()) {
					r_strbuf_append (&op->esil, ",DUP,tmp,=");
				}

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX32()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],~,%s,=", size, REG64 (0));
				
				if (ISPOSTINDEX32()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64u",+,%s,=", GETIMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%d,%s,[%d],~,%s,=",
						size*8, REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					
						/*This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.*/
					
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size*8, REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%d,%"PFMT64u",[%d],~,%s,=",
					size*8, GETIMM64 (1), size, REG64 (0));
			}
		}
		break;
	}
	case ARM64_CCMP:
	case ARM64_TST: // cmp w8, 0xd
	case ARM64_CMP: // cmp w8, 0xd
		ARG64_APPEND(&op->esil, 1);
		COMMA(&op->esil);
		ARG64_APPEND(&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) -1);
	
		if (insn->operation == ARM64_CCMP || insn->operation == ARM64_CCMN) {
			r_strbuf_appendf (&op->esil, ",");
			v35arm_prefix_cond(op, insn->operands[3].cond);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,28,%"PFMT64u",<<,|,pstate,:=", GETIMM64 (2));
		}
		break;
	case ARM64_CCMN:
	case ARM64_CMN:
		ARG64_APPEND(&op->esil, 1);
		COMMA(&op->esil);
		ARG64_APPEND(&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",-1,*,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) -1);
	
		if (insn->operation == ARM64_CCMN) {
			r_strbuf_appendf (&op->esil, ",");
			v35arm_prefix_cond(op, insn->operands[3].cond);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,28,%"PFMT64u",<<,|,pstate,:=", GETIMM64 (2));
		}
		break;
	case ARM64_FCSEL:
	case ARM64_CSEL: // csel Wd, Wn, Wm --> Wd := (cond) ? Wn : Wm
		if ISCOND64(3) {
			v35arm_prefix_cond (op, insn->operands[3].cond);
		}
		r_strbuf_appendf (&op->esil, "%s,}{,%s,},%s,=", REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_CSET: // cset Wd --> Wd := (cond) ? 1 : 0
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "1,}{,0,},%s,=", REG64 (0));
		postfix = "";
		break;
	case ARM64_CSETM: // cset Wd --> Wd := (cond) ? 1 : 0
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "-1,}{,0,},%s,=", REG64 (0));
		postfix = "";
		break;
	case ARM64_CINC: // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "1,%s,+,}{,%s,},%s,=", REG64 (1), REG64 (1), REG64 (0));
		postfix = "";
		break;
	case ARM64_CSINC: // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "%s,}{,1,%s,+,},%s,=", REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_CINV:
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "-1,%s,^,}{,%s,},%s,=", REG64 (1), REG64 (1), REG64 (0));
		postfix = "";
		break;
	case ARM64_CSINV: // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "%s,}{,-1,%s,^,},%s,=", REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_CNEG:
		if ISCOND64(1) {
			v35arm_prefix_cond (op, insn->operands[1].cond);
		}
		r_strbuf_appendf (&op->esil, "-1,%s,*,}{,%s,},%s,=", REG64 (1), REG64 (1), REG64 (0));
		postfix = "";
		break;
	case ARM64_STXRB:
	case ARM64_STXRH:
	case ARM64_STXR:
	{
		int size = REGSIZE64 (1);
		if (insn->operation == ARM64_STXRB) {
		    size = 1;
		} else if (insn->operation == ARM64_STXRH) {
		    size = 2;
		}
		r_strbuf_setf (&op->esil, "0,%s,=,%s,%s,%"PFMT64u",+,=[%d]",
			REG64 (0), REG64 (1), MEMBASE64 (1), MEMDISP64 (1), size);
		break;
	}
	case ARM64_STRB:
	case ARM64_STRH:
	case ARM64_STUR:
	case ARM64_STURB:
	case ARM64_STURH:
	case ARM64_STTR:
	case ARM64_STTRH:
	case ARM64_STTRB:
	case ARM64_STR: // str x6, [x6,0xf90]
	{
		int size = REGSIZE64 (0);
		switch (insn->operation) {
		case ARM64_STRB:
		case ARM64_STURB:
		case ARM64_STTRB:
			{
				size = 1;
				break;
			}
		case ARM64_STRH:
		case ARM64_STURH:
		case ARM64_STTRH:
			{
				size = 2;
				break;
			}
		default:
			break;
		}
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				r_strbuf_appendf (&op->esil, "%s,%s,", REG64 (0), MEMBASE64 (1));
				ARG64_APPEND(&op->esil, 1);
				r_strbuf_appendf (&op->esil, ",+,=[%d]", size);
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%s,%d,%"PFMT64u",%s,+",
							REG64 (0), MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64u",%s,-",
							REG64 (0), -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64u",%s,+",
							REG64 (0), MEMDISP64 (1), MEMBASE64 (1));
				}

				if (ISPREINDEX32() || ISPOSTINDEX32()) {
					r_strbuf_append (&op->esil, ",DUP,tmp,=");
				}

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX32()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",=[%d]", size);

				if (ISPOSTINDEX32()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64u",+,%s,=", GETIMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,%s,=[%d]",
						REG64 (0), REG64 (1), size);
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.*/
					
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[%d]",
							REG64 (0), REG64 (1), REG64 (2), size);
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%s,%"PFMT64u",=[%d]",
					REG64 (0), GETIMM64 (1), size);
			}
		}
		break;
	}
	case ARM64_BIC:
	if (OPCOUNT64 () == 2) {
		if (REGSIZE64 (0) == 4) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&=",
					REG64 (1), REG64 (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffffffffffff,^,%s,&=",
					REG64 (1), REG64 (0));
		}
	} else {
		if (REGSIZE64 (0) == 4) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&,%s,=",
					REG64 (2), REG64 (1), REG64 (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffffffffffff,^,%s,&,%s,=",
					REG64 (2), REG64 (1), REG64 (0));
		}
	}
	break;
	case ARM64_CBZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%"PFMT64u",pc,=,}",
				REG64 (0), GETIMM64 (1));
		break;
	case ARM64_CBNZ:
		r_strbuf_setf (&op->esil, "%s,?{,%"PFMT64u",pc,=,}",
				REG64 (0), GETIMM64 (1));
		break;
	case ARM64_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64u ",1,<<,%s,&,!,?{,%"PFMT64u",pc,=,}",
				GETIMM64 (1), REG64 (0), GETIMM64 (2));
		break;
	case ARM64_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64u ",1,<<,%s,&,?{,%"PFMT64u",pc,=,}",
				GETIMM64 (1), REG64 (0), GETIMM64 (2));
		break;
	case ARM64_STNP:
	case ARM64_STP: // stp x6, x7, [x6,0xf90]
	{
		int disp = (int)MEMDISP64 (2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64 (2): -MEMDISP64 (2);
		int size = REGSIZE64 (0);
		// Pre-index case
		if (ISPREINDEX64 ()) {
			// "stp x2, x3, [x8, 0x20]!
			// "32,x8,+=,x2,x8,=[8],x3,x8,8,+,=[8]",
			r_strbuf_setf(&op->esil,
					"%" PFMT64u ",%s,%c=,%s,%s,=[%d],%s,%s,%d,+,=[%d]",
					abs, MEMBASE64 (2), sign,
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size);
		// Post-index case
		} else if (ISPOSTINDEX64 ()) {
			int val = GETIMM64 (3);
			sign = val>=0?'+':'-';
			abs = val>=0? val: -val;
			// "stp x4, x5, [x8], 0x10"
			// "x4,x8,=[],x5,x8,8,+,=[],16,x8,+="
			r_strbuf_setf(&op->esil,
					"%s,%s,=[%d],%s,%s,%d,+,=[%d],%" PFMT64u ",%s,%c=",
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size,
					abs, MEMBASE64 (2), sign);
		// Everything else
		} else {
			r_strbuf_setf (&op->esil,
					"%s,%s,%"PFMT64u",%c,=[%d],"
					"%s,%s,%"PFMT64u",%c,%d,+,=[%d]",
					REG64 (0), MEMBASE64 (2), abs, sign, size,
					REG64 (1), MEMBASE64 (2), abs, sign, size, size);
		}
		break;
	}
	case ARM64_LDNP:
	case ARM64_LDP: // ldp x29, x30, [sp], 0x10
	{
		int disp = (int)MEMDISP64 (2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64 (2): -MEMDISP64 (2);
		int size = REGSIZE64 (0);
		// Pre-index case
		// x2,x8,32,+,=[8],x3,x8,32,+,8,+,=[8]
		if (ISPREINDEX64 ()) {
			// "ldp x0, x1, [x8, -0x10]!"
			// 16,x8,-=,x8,[8],x0,=,x8,8,+,[8],x1,=
			r_strbuf_setf (&op->esil,
					"%"PFMT64u",%s,%c=,"
					"%s,[%d],%s,=,"
					"%s,%d,+,[%d],%s,=",
					abs, MEMBASE64 (2), sign,
					MEMBASE64 (2), size, REG64 (0),
					MEMBASE64 (2), size, size, REG64 (1));
		// Post-index case
		} else if (ISPOSTINDEX64 ()) {
			int val = GETIMM64 (3);
			sign = val>=0?'+':'-';
			abs = val>=0? val: -val;
			// ldp x4, x5, [x8], -0x10
			// x8,[8],x4,=,x8,8,+,[8],x5,=,16,x8,+=
			r_strbuf_setf (&op->esil,
					"%s,[%d],%s,=,"
					"%s,%d,+,[%d],%s,=,"
					"%" PFMT64u ",%s,%c=",
					MEMBASE64 (2), size, REG64 (0),
					MEMBASE64 (2), size, size, REG64 (1),
					abs, MEMBASE64 (2), sign);
		} else {
			r_strbuf_setf (&op->esil,
					"%"PFMT64d",%s,%c,[%d],%s,=,"
					"%d,%"PFMT64d",%s,%c,+,[%d],%s,=",
					abs, MEMBASE64 (2), sign, size, REG64 (0),
					size, abs, MEMBASE64 (2), sign, size, REG64 (1));
		}
		break;
	}
	case ARM64_ADRP:
		r_strbuf_setf (&op->esil, "%"PFMT64u",%s,=",
				GETIMM64 (1), REG64 (0));
		break;
	case ARM64_EXTR:
		// from VEX
		/*
			01 | t0 = GET:I64(x4)
			02 | t1 = GET:I64(x0)
			03 | t4 = Shr64(t1,0x20)
			04 | t5 = Shl64(t0,0x20)
			05 | t3 = Or64(t5,t4)
			06 | PUT(x4) = t3
		*/
		r_strbuf_setf (&op->esil, "%" PFMT64u ",%s,>>,%" PFMT64u ",%s,<<,|,%s,=",
			GETIMM64 (3), REG64 (2), GETIMM64 (3), REG64 (1), REG64 (0));
		break;
	case ARM64_RBIT:
		// slightly shorter expression to reverse bits
		r_strbuf_setf (&op->esil, "0,tmp,=,0,DUP,DUP,DUP,%d,-,%s,>>,1,&,<<,tmp,+=,%d,-,?{,++,4,GOTO,},tmp,%s,=",
			REGBITS64 (1)-1, REG64 (1), REGBITS64 (1)-1, REG64 (0));
		break;
	case ARM64_MVN:
	case ARM64_MOVN:
	{
		if (0) {
			r_strbuf_setf (&op->esil, "%sh,-1,^,%sh,=,%sl,-1,^,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_appendf (&op->esil, ",-1,^,");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_appendf (&op->esil, ",=");
		}
		break;
	}
	case ARM64_MOVK: // movk w8, 0x1290
	{
		ut64 shift = LSHIFT2_64 (1);
		if (shift < 0) {
			shift = 0;
		} else if (shift > 48) {
			shift = 48;
		}
		ut64 shifted_imm = GETIMM64 (1) << shift;
		ut64 mask = ~(0xffffULL << shift);

		r_strbuf_setf (&op->esil, "0x%"PFMT64x",%s,&,%"PFMT64u",|,%s,=",
			mask,
			REG64 (0),
			shifted_imm,
			REG64 (0));

		break;
	}
	case ARM64_MOVZ:
		r_strbuf_setf (&op->esil, "%"PFMT64u",%s,=",
			SHIFTED_IMM64 (1, REGSIZE64 (0)*8),
			REG64 (0));
		break;
	/* ASR, SXTB, SXTH and SXTW are alias for SBFM */
	case ARM64_ASR:
	{
		//OPCALL(">>>>");
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2)) {
				ARG64_APPEND(&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,>>>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,>>>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = GETIMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,>>>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case ARM64_SXTB:
		if (REGBITS64 (0) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,8,0xff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "8,0xff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_SXTH: /* halfword */
		if (REGBITS64 (0) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,16,0xffff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "16,0xffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_SXTW: /* word */
		r_strbuf_setf (&op->esil, "32,0xffffffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		break;
	case ARM64_UXTB:
		r_strbuf_setf (&op->esil, "%s,0xff,&,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_UXTH:
		r_strbuf_setf (&op->esil, "%s,0xffff,&,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_RETAA:
	case ARM64_RETAB:
	case ARM64_RET:
		r_strbuf_setf (&op->esil, "lr,pc,=");
		break;
	case ARM64_ERETAA:
	case ARM64_ERETAB:
	case ARM64_ERET:
		r_strbuf_setf (&op->esil, "lr,pc,=");
		break;
	case ARM64_BFI: // bfi w8, w8, 2, 1
	case ARM64_BFXIL:
	{
		if (OPCOUNT64 () >= 3 && ISIMM64 (3) && GETIMM64 (3) > 0) {
			size_t index = GETIMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[index];
			ut64 shift = GETIMM64 (2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,%"PFMT64u",%"PFMT64u",%s,&,<<,|,%s,=",
				notmask, REG64 (0), shift, mask, REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_SBFIZ:
		if (GETIMM64 (3) > 0 && GETIMM64 (3) <= 64 - GETIMM64 (2)) {
			size_t index = GETIMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64u ",%" PFMT64u ",%s,%"PFMT64u",&,~,<<,%s,=",
					GETIMM64 (2), GETIMM64 (3), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_UBFIZ:
		if (GETIMM64 (3) > 0 && GETIMM64 (3) <= 64 - GETIMM64 (2)) {
			size_t index = GETIMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64u ",%s,%"PFMT64u",&,<<,%s,=",
					GETIMM64 (2), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_SBFX:
		if (GETIMM64 (3) > 0 && GETIMM64 (3) <= 64 - GETIMM64 (2)) {
			size_t index = GETIMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64u ",%" PFMT64u ",%s,%" PFMT64u ",%"PFMT64u",<<,&,>>,~,%s,=",
				GETIMM64 (3), GETIMM64 (2), REG64 (1), GETIMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_UBFX:
		if (GETIMM64 (3) > 0 && GETIMM64 (3) <= 64 - GETIMM64 (2)) {
			size_t index = GETIMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64u ",%s,%" PFMT64u ",%"PFMT64u",<<,&,>>,%s,=",
				GETIMM64 (2), REG64 (1), GETIMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_NGC:
	case ARM64_NEG:
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",0,-,%s,=", REG64 (0));
		break;
	case ARM64_NGCS:
	case ARM64_NEGS:
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",0,-,%s,=", REG64 (0));
		SET_FLAGS();
		break;
	case ARM64_SVC:
		r_strbuf_setf (&op->esil, "%" PFMT64u ",$", GETIMM64 (0));
		break;
	default:
		break;
	}

	r_strbuf_append (&op->esil, postfix);

	return 0;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	Instruction insn = {0};
	char output[256];
	op->addr = addr;
	op->size = 4;
	if (len < 4) {
		return -1;
	}
	ut32 n = r_read_le32 (buf);
	// FailureCodes fc = aarch64_decompose (n, &insn, addr);
	int fc = aarch64_decompose (n, &insn, addr);
	if (fc != DISASM_SUCCESS) {
		return -1;
	}
	output[0] = 0;
	fc = aarch64_disassemble (&insn, output, sizeof (output));
	if (fc == DISASM_SUCCESS) {
		if (*output) {
			// XXX trim tailing newline on UNDEFINED string
			/// output[strlen (output) - 2] = 0;
		}
		r_str_trim_tail (output);
		r_str_replace_char (output, '\t', ' ');
		r_str_replace_char (output, '#', ' ');
		if (r_str_startswith (output, "UNDEF")) {
			//r_strbuf_set (&op->buf_asm, "undefined");
			return 4;
		}
		//r_strbuf_set (&op->buf_asm, output);
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		anop64 (a, op, &insn);
		if (mask & R_ANAL_OP_MASK_OPEX) {
			opex64 (&op->opex, &insn);
		}
		if (mask & R_ANAL_OP_MASK_ESIL) {
			analop_esil (a, op, addr, buf, len, &insn);
		}
		return op->size;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = strdup ("invalid");
	}
	//r_strbuf_set (&op->buf_asm, "invalid");
	// this can be moved into op.c
	set_opdir (op);
	return 4;
}

#include "anal_arm_regprofile.inc"

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		if (anal && anal->bits == 16) {
			return 2;
		}
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		if (anal && anal->bits == 16) {
			return 2;
		}
		return 4;
	}
	return 4; // XXX
}

static RList *anal_preludes(RAnal *anal) {
	RList *l = r_list_newf ((RListFree)r_search_keyword_free);
#define KW(d,ds,m,ms) r_list_append (l, r_search_keyword_new((const ut8*)d,ds,(const ut8*)m, ms, NULL))
	KW ("\xf0\x00\x00\xd1", 4, "\xf0\x00\x00\xff", 4);
	KW ("\xf0\x00\x00\xa9", 4, "\xf0\x00\x00\xff", 4);
	KW ("\x7f\x23\x03\xd5\xff", 5, NULL, 0);
	return l;
}

RAnalPlugin r_anal_plugin_arm_v35 = {
	.name = "arm.v35",
	.desc = "Vector35 ARM analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "arm",
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.preludes = anal_preludes,
	.bits = 64,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm_v35,
	.version = R2_VERSION
};
#endif
