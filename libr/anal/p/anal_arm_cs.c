/* radare2 - LGPL - Copyright 2013-2016 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/arm.h>
#include "esil.h"
/* arm64 */
#define IMM64(x) insn->detail->arm64.operands[x].imm

/* arm32 */
#define REG(x) cs_reg_name (*handle, insn->detail->arm.operands[x].reg)
#define REG64(x) cs_reg_name (*handle, insn->detail->arm64.operands[x].reg)
#define REGID64(x) insn->detail->arm64.operands[x].reg
#define REGID(x) insn->detail->arm.operands[x].reg
#define IMM(x) (ut32)(insn->detail->arm.operands[x].imm)
#define IMM64(x) insn->detail->arm64.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->arm.operands[x].mem.base)
#define MEMBASE64(x) cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.base)
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
#define REGBASE64(x) insn->detail->arm64.operands[x].mem.base
// s/index/base|reg/
#define MEMINDEX(x) cs_reg_name(*handle, insn->detail->arm.operands[x].mem.index)
#define MEMINDEX64(x) cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.index)
#define HASMEMINDEX64(x) insn->detail->arm64.operands[x].mem.index != ARM64_REG_INVALID
#define MEMDISP(x) insn->detail->arm.operands[x].mem.disp
#define MEMDISP64(x) insn->detail->arm64.operands[x].mem.disp
#define ISIMM(x) insn->detail->arm.operands[x].type == ARM_OP_IMM
#define ISIMM64(x) insn->detail->arm64.operands[x].type == ARM64_OP_IMM
#define ISREG(x) insn->detail->arm.operands[x].type == ARM_OP_REG
#define ISREG64(x) insn->detail->arm64.operands[x].type == ARM64_OP_REG
#define ISMEM(x) insn->detail->arm.operands[x].type == ARM_OP_MEM
#define ISMEM64(x) insn->detail->arm64.operands[x].type == ARM64_OP_MEM

#if CS_API_MAJOR > 3
#define LSHIFT(x) insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x) insn->detail->arm.operands[x].shift.value
#define LSHIFT2_64(x) insn->detail->arm64.operands[x].shift.value
#else
#define LSHIFT(x) 0
#define LSHIFT2(x) 0
#define LSHIFT2_64(x) 0
#endif
#define OPCOUNT() insn->detail->arm.op_count
#define OPCOUNT64() insn->detail->arm64.op_count
#define ISSHIFTED(x) (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)

static const ut64 bitmask_by_width[] = {
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

static const char *decode_shift(arm_shifter shift) {
	static const char *E_OP_SR = ">>";
	static const char *E_OP_SL = "<<";
	static const char *E_OP_RR = ">>>";
	static const char *E_OP_VOID = "";

	switch (shift) {
	case ARM_SFT_ASR:
	case ARM_SFT_ASR_REG:
	case ARM_SFT_LSR:
	case ARM_SFT_LSR_REG:
		return E_OP_SR;

	case ARM_SFT_LSL:
	case ARM_SFT_LSL_REG:
		return E_OP_SL;

	case ARM_SFT_ROR:
	case ARM_SFT_RRX:
	case ARM_SFT_ROR_REG:
	case ARM_SFT_RRX_REG:
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}

static const char *decode_shift_64(arm64_shifter shift) {
	static const char *E_OP_SR = ">>";
	static const char *E_OP_SL = "<<";
	static const char *E_OP_RR = ">>>";
	static const char *E_OP_VOID = "";

	switch (shift) {
	case ARM64_SFT_ASR:
	case ARM64_SFT_LSR:
		return E_OP_SR;

	case ARM64_SFT_LSL:
	case ARM64_SFT_MSL:
		return E_OP_SL;

	case ARM64_SFT_ROR:
		return E_OP_RR;

	default:
		break;
	}
	return E_OP_VOID;
}


#define DECODE_SHIFT(x) decode_shift(insn->detail->arm.operands[x].shift.type)
#define DECODE_SHIFT64(x) decode_shift_64(insn->detail->arm64.operands[x].shift.type)

static int regsize64(cs_insn *insn, int n) {
	unsigned int reg = insn->detail->arm64.operands[n].reg;
	if ( (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
		(reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)) {
		return 4;
	}
	if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
		return 1;
	}
	if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
		return 2;
	}
	if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
		return 16;
	}
	return 8;
}

#define REGSIZE64(x) regsize64 (insn, x)

/* arm64 */

static const char *arg(RAnal *a, csh *handle, cs_insn *insn, char *buf, int n) {
	buf[0] = 0;
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		if (ISSHIFTED (n)) {
			sprintf (buf, "%u,%s,%s",
			LSHIFT2 (n),
			cs_reg_name (*handle,
				insn->detail->arm.operands[n].reg),
			DECODE_SHIFT (n));
		} else {
			sprintf (buf, "%s",
			cs_reg_name (*handle,
				insn->detail->arm.operands[n].reg));
		}
		break;
	case ARM_OP_IMM:
		if (a->bits == 64) {
			// 64bit only
			sprintf (buf, "%"PFMT64d, (ut64)
					insn->detail->arm.operands[n].imm);
		} else {
			// 32bit only
			sprintf (buf, "%"PFMT64d, (ut64)(ut32)
					insn->detail->arm.operands[n].imm);
		}
		break;
	case ARM_OP_MEM:
		break;
	case ARM_OP_FP:
		sprintf (buf, "%lf", insn->detail->arm.operands[n].fp);
		break;
	default:
		break;
	}
	return buf;
}

#define ARG(x) arg(a, handle, insn, str[x], x)

#define SHIFTED_REG64_APPEND(sb, n) shifted_reg64_append(sb, handle, insn, n)


static void shifted_reg64_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n) {
	if (insn->detail->arm64.operands[n].shift.type != ARM64_SFT_ASR) {
		r_strbuf_appendf (sb, "%d,%s,%s", LSHIFT2_64(n), REG64(n), DECODE_SHIFT64(n));
	} else {
		/* ASR: add the missing ones if negative */
		ut64 missing_ones = bitmask_by_width[LSHIFT2_64(n)-1] << (REGSIZE64(n)*8 - LSHIFT2_64(n));
		r_strbuf_appendf (sb, "%d,%s,%s,1,%s,<<<,1,&,?{,%"PFMT64u",}{,0,},|", 
			LSHIFT2_64(n), REG64(n), DECODE_SHIFT64(n), REG64(n), missing_ones);
	}
}

#define OPCALL(opchar) arm64math(a, op, addr, buf, len, handle, insn, opchar, 0)
#define OPCALL_NEG(opchar) arm64math(a, op, addr, buf, len, handle, insn, opchar, 1)

static void arm64math(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate) {
	const char *r0 = REG64(0);
	const char *r1 = REG64(1);
	if (ISREG64(2)) {
		if (LSHIFT2_64 (2)) {
			SHIFTED_REG64_APPEND(&op->esil, 2);
			if (negate) {
				r_strbuf_appendf (&op->esil, ",-1,^");
			}
			if (REGID64(0) == REGID64(1)) {
				r_strbuf_appendf (&op->esil, ",%s,%s=", r0, opchar);
			} else {
				r_strbuf_appendf (&op->esil, ",%s,%s,%s,=", r1, opchar, r0);
			}
		} else {
			const char *r2 = REG64(2);
			if (negate) {
				if (REGID64(0) == REGID64(1)) {
					r_strbuf_setf (&op->esil, "%s,-1,^,%s,%s=", r2, r0, opchar);
				} else {
					r_strbuf_setf (&op->esil, "%s,-1,^,%s,%s,%s,=", r2, r1, opchar, r0);
				}
			} else {
				if (REGID64(0) == REGID64(1)) {
					r_strbuf_setf (&op->esil, "%s,%s,%s=", r2, r0, opchar);
				} else {
					r_strbuf_setf (&op->esil, "%s,%s,%s,%s,=", r2, r1, opchar, r0);
				}
			}
		}
		
	} else {
		ut64 i2 = IMM64(2);
		if (negate) {
			if (REGID64(0) == REGID64(1)) {
				r_strbuf_setf (&op->esil, "%"PFMT64d",-1,^,%s,%s=", i2, r0, opchar);
			} else {
				r_strbuf_setf (&op->esil, "%"PFMT64d",-1,^,%s,%s,%s,=", i2, r1, opchar, r0);
			}
		} else {
			if (REGID64(0) == REGID64(1)) {
				r_strbuf_setf (&op->esil, "%"PFMT64d",%s,%s=", i2, r0, opchar);
			} else {
				r_strbuf_setf (&op->esil, "%"PFMT64d",%s,%s,%s,=", i2, r1, opchar, r0);
			}
		}
	}
}

static int analop64_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	switch (insn->id) {
	case ARM64_INS_REV: {
		const char *r0 = REG64(0);
		const char *r1 = REG64(1);
		r_strbuf_setf (&op->esil,
			"24,0xff,%s,&,<<,%s,=,"
			"16,0xff,8,%s,>>,&,<<,%s,|=,"
			"8,0xff,16,%s,>>,&,<<,%s,|=,"
			"0xff,24,%s,>>,&,%s,|=,",
			r1, r0, r1, r0, r1, r0, r1, r0);
		} break;
	case ARM64_INS_ADR:
		// TODO: must be 21bit signed
		r_strbuf_setf (&op->esil,
			"%"PFMT64d",%s,=",IMM64(1), REG64(0));
		break;
	case ARM64_INS_MADD:
		r_strbuf_setf (&op->esil,
			"%s,%s,*,%s,+,%s,=",REG64(2),REG64(1),REG64(3), REG64(0));
		break;
	case ARM64_INS_ADD: OPCALL("+"); break;
	case ARM64_INS_SUB: OPCALL("-"); break;
	case ARM64_INS_MUL: OPCALL("*"); break;
	case ARM64_INS_AND: OPCALL("&"); break;
	case ARM64_INS_ORR: OPCALL("|"); break;
	case ARM64_INS_EOR: OPCALL("^"); break;
	case ARM64_INS_ORN: OPCALL_NEG("|"); break;
	case ARM64_INS_EON: OPCALL_NEG("^"); break;
	case ARM64_INS_LSR: OPCALL(">>"); break;
	case ARM64_INS_LSL: OPCALL("<<"); break;


	case ARM64_INS_STURB: // sturb wzr, [x9, 0xffffffffffffffff]
		// TODO
		break;
	case ARM64_INS_NOP:
		r_strbuf_setf (&op->esil, ",");
		break;
	case ARM64_INS_FDIV:
	case ARM64_INS_SDIV:
	case ARM64_INS_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		r_strbuf_setf (&op->esil, "%s,%s,/=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_B:
		switch (insn->detail->arm.cc) {
		case 0:
			r_strbuf_setf (&op->esil, "%"PFMT64d",pc,=", (ut64)addr + IMM64 (0));
			break;
		case ARM_CC_EQ:
			r_strbuf_setf (&op->esil, "zf,{,%"PFMT64d",pc,=,}", (ut64)addr + IMM64 (0));
			break;
		case ARM_CC_NE:
			r_strbuf_setf (&op->esil, "zf,!,{,%"PFMT64d",pc,=,}", (ut64)addr + IMM64 (0));
			break;
		default:
			//TODO
			break;
		}
		break;
	case ARM64_INS_BL:
		r_strbuf_setf (&op->esil, "pc,lr,=,%"PFMT64d",pc,=", addr + IMM64 (0));
		break;
	case ARM64_INS_BLR:
		// XXX
		r_strbuf_setf (&op->esil, "pc,lr,=,%d,pc,=", IMM64 (0));
		break;
	case ARM64_INS_LDUR:
	case ARM64_INS_LDR:
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRB:
	case ARM64_INS_LDRSW:
		if ((int)MEMDISP64(1) < 0) {
			r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",-,=[]",
				REG64(0), MEMBASE64(1), -(int)MEMDISP64(1));
		} else {
			int size = REGSIZE64(0);
			switch (insn->id) {
			case ARM64_INS_LDRSB:
			case ARM64_INS_LDRB:
				size = 1;
				break;
			case ARM64_INS_LDRSW:
				size = 4;
				break;
			default:
				break;

			}
			if (ISMEM64(1)) {
				if (HASMEMINDEX64(1)) {
					if (LSHIFT2_64(1)) {
						r_strbuf_appendf (&op->esil, "%s,%d,%s,%s,+,[%d],%s,=",
								MEMBASE64(1), LSHIFT2_64(1), MEMINDEX64(1), DECODE_SHIFT64(1), size, REG64(0));
					} else {
						r_strbuf_appendf (&op->esil, "%s,%s,+,[%d],%s,=",
								MEMBASE64(1), MEMINDEX64(1), size, REG64(0));
					}
				} else {
					if (LSHIFT2_64(1)) {
						r_strbuf_appendf (&op->esil, "%s,%d,%d,%s,+,[%d],%s,=",
								MEMBASE64(1), LSHIFT2_64(1), MEMDISP64(1), DECODE_SHIFT64(1), size, REG64(0));
					} else {
						r_strbuf_appendf (&op->esil, "%s,%d,+,[%d],%s,=",
								MEMBASE64(1), MEMDISP64(1), size, REG64(0));
					}
				}
			} else {
				if (ISREG64(1)) {
					if (OPCOUNT64() == 2) {
						r_strbuf_setf (&op->esil, "%s,[%d],%s,=",
							REG64(1), size, REG64(0));
					} else if (OPCOUNT64() == 3) {
						/* 
							This seems like a capstone bug:
							instructions like
								ldr x16, [x13, x9]
								ldrb w2, [x19, x23]
							are not detected as ARM64_OP_MEM type and 
							fall in this case instead.
						*/
						if (ISREG64(2)) {
							r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,=",
								REG64(1), REG64(2), size, REG64(0));
						}
					}
				} else {
					r_strbuf_setf (&op->esil, "%"PFMT64d",[%d],%s,=",
						IMM64(1), size, REG64(0));
				}
			}
		}
		break;
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_TST: // cmp w8, 0xd
	case ARM64_INS_CMP: // cmp w8, 0xd
	case ARM64_INS_CMN: // cmp w8, 0xd
		// update esil, cpu flags
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,==,$z,zf,=",
			IMM64(1), REG64(0));
		break;
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSEL: // CSEL w8, w13, w14, eq
		// TODO: w8 = eq? w13: w14
		// COND64(4) { ARM64_CC_EQ, NE, HS, ...
		r_strbuf_setf (&op->esil, "$z,?{,%s,}{,%s,},%s,=",
			REG64(1), REG64(2), REG64(0));
		break;
	case ARM64_INS_STRB:
		r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",+,=[1]",
			REG64(0), MEMBASE64(1), MEMDISP64(1));
	case ARM64_INS_STUR:
	case ARM64_INS_STR: // str x6, [x6,0xf90]
	case ARM64_INS_STRH:
		if ((int)MEMDISP64(1) < 0) {
			r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",-,=[]",
				REG64(0), MEMBASE64(1), -(int)MEMDISP64(1));
		} else {
			r_strbuf_setf (&op->esil, "%s,%s,%"PFMT64d",+,=[]",
				REG64(0), MEMBASE64(1), MEMDISP64(1));
		}
		break;
	case ARM64_INS_CBZ:
		r_strbuf_setf (&op->esil, "%s,?{,%"PFMT64d",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_CBNZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%"PFMT64d",pc,=,}",
			REG64(0), IMM64(1));
		break;
	case ARM64_INS_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%d,1,<<=,%s,&,!,?{,%"PFMT64d",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%d,1,<<=,%s,&,?{,%"PFMT64d",pc,=,}",
			IMM64(1), REG64(0), IMM64(2));
		break;
	case ARM64_INS_STP: // str x6, x7, [x6,0xf90]
		{
		int disp = (int)MEMDISP64(2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64(2): -MEMDISP64(2);
		r_strbuf_setf (&op->esil, 
			"%s,%s,%"PFMT64d",%c,=[],"
			"%s,%s,%"PFMT64d",%c,%d,+,=[]",
			REG64(0), MEMBASE64(2), abs, sign, 
			REG64(1), MEMBASE64(2), abs, sign, 8);
		}
		if (!strcmp ("sp", MEMBASE64(2))) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP64(2);
		}
		break;
	case ARM64_INS_LDP: // ldp x29, x30, [sp], 0x10
		{
		int disp = (int)MEMDISP64(2);
		char sign = disp>=0?'+':'-';
		ut64 abs = disp>=0? MEMDISP64(2): -MEMDISP64(2);
		r_strbuf_setf (&op->esil, 
			"%s,%s,%"PFMT64d",%c,=[],"
			"%s,%s,%"PFMT64d",%c,%d,+,=[]",
			REG64(0), MEMBASE64(2), abs, sign, 
			REG64(1), MEMBASE64(2), abs, sign, 8);
		}
		if (!strcmp ("sp", MEMBASE64(2))) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP64(2);
		}
		break;
	case ARM64_INS_ADRP:
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=",
				IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_MOV:
		if (ISREG64(1)) {
			r_strbuf_setf (&op->esil, "%s,%s,=", REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_MOVN:
		if (ISREG64(1)) {
			r_strbuf_setf (&op->esil, "%s,-1,^,%s,=", REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "%"PFMT64d",-1,^,%s,=", IMM64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_MOVK: // movk w8, 0x1290
		// XXX: wrongly implemented
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_MOVZ:
		// XXX: wrongly implemented
		r_strbuf_setf (&op->esil, "%d,%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_RET:
		r_strbuf_setf (&op->esil, "lr,pc,=");
		break;
	}
	return 0;
}

static int analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb) {
	bool hascond = false;
	int i;
	char str[32][32];
	int msr_flags;
	int pcdelta = (thumb ? 4 : 8 ) - op->size;
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");
	switch (insn->detail->arm.cc) {
	case ARM_CC_AL:
		// no condition
		break;
	case ARM_CC_EQ:
		hascond = true;
		r_strbuf_setf (&op->esil, "zf,?{,");
		break;
	case ARM_CC_NE:
		r_strbuf_setf (&op->esil, "zf,!,?{,");
		hascond = true;
		break;
	case ARM_CC_GT:
	case ARM_CC_LE:
		break;
	default:
		break;
	}
	// TODO: PREFIX CONDITIONAL

	switch (insn->id) {
	case ARM_INS_IT:
		// TODO: See #3486
		break;
	case ARM_INS_NOP:
		r_strbuf_setf (&op->esil, ",");
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		r_strbuf_setf (&op->esil, "%s,pc,=", ARG(0));
		break;
	case ARM_INS_UDF:
		r_strbuf_setf (&op->esil, "%s,TRAP", ARG(0));
		break;
	case ARM_INS_EOR:
		if (OPCOUNT() == 2) {
			r_strbuf_setf (&op->esil, "%s,%s,^=", ARG(1), ARG(0));
		} else if (OPCOUNT() == 3) {
			r_strbuf_setf (&op->esil, "%s,%s,^,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_ORR:
		r_strbuf_setf (&op->esil, "%s,%s,|=", ARG(1), ARG(0));
		break;
	case ARM_INS_AND:
		r_strbuf_setf (&op->esil, "%s,%s,&=", ARG(1), ARG(0));
		break;
	case ARM_INS_SVC:
		r_strbuf_setf (&op->esil, "%s,$", ARG(0));
		break;
	case ARM_INS_PUSH:
#if 0
PUSH { r4, r5, r6, r7, lr }
4,sp,-=,lr,sp,=[4],
4,sp,-=,r7,sp,=[4],
4,sp,-=,r6,sp,=[4],
4,sp,-=,r5,sp,=[4],
4,sp,-=,r4,sp,=[4]

20,sp,-=,r4,r5,r6,r7,lr,5,sp,=[*]
#endif
		r_strbuf_setf (&op->esil, "%d,sp,-=,",
			4 * insn->detail->arm.op_count);
		for (i=0; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,=[*]",
			insn->detail->arm.op_count);
		break;
	case ARM_INS_STM:
		r_strbuf_setf (&op->esil, "");
		for (i=1; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4],",
				REG (i), ARG (0), i*4);
		}
		break;
	case ARM_INS_ASR:
		r_strbuf_setf (&op->esil, "%s,%s,=", ARG(1), ARG(0));
		break;
	case ARM_INS_POP:
#if 0
POP { r4,r5, r6}
r4,r5,r6,3,sp,[*],12,sp,+=
#endif
		r_strbuf_setf (&op->esil, "");
		for (i=0; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,[*],",
			insn->detail->arm.op_count);
		r_strbuf_appendf (&op->esil, "%d,sp,+=",
			4 * insn->detail->arm.op_count);
		break;
	case ARM_INS_LDM:
		{
		const char *comma = "";
		for (i=1; i<insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s%s,%d,+,[4],%s,=",
				comma, ARG (0), i*4, REG (i));
			comma = ",";
		}
		}
		break;
	case ARM_INS_CMP:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG(1), ARG(0));
		break;
	case ARM_INS_CMN:
		r_strbuf_appendf (&op->esil, "%s,%s,!=", ARG(1), ARG(0));
		break;
	case ARM_INS_LSL:
		// suffix 'S' forces conditional flag to be updated
		if (OPCOUNT() == 2) {
			r_strbuf_appendf (&op->esil, "%s,%s,<<=", ARG(1), ARG(0));
		} else if (OPCOUNT() == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_LSR:
		// suffix 'S' forces conditional flag to be updated
		if (OPCOUNT() == 2) {
			r_strbuf_appendf (&op->esil, "%s,%s,>>=", ARG(1), ARG(0));
		} else if (OPCOUNT() == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_B:
		r_strbuf_appendf (&op->esil, "%s,pc,=%s", ARG(0), hascond? ",}":"");
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		r_strbuf_appendf (&op->esil, "4,pc,+,lr,=,%s,pc,=", ARG(0));
		break;
	case ARM_INS_MOVT:
		r_strbuf_appendf (&op->esil, "16,%s,<<,%s,|=", ARG(1), REG(0));
		break;
	case ARM_INS_ADR:
	case ARM_INS_MOV:
	case ARM_INS_VMOV:
	case ARM_INS_MOVW:
		r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_CBZ:
		r_strbuf_appendf (&op->esil, "zf,?{,%s,pc,=", ARG(0));
		break;
	case ARM_INS_CBNZ:
		r_strbuf_appendf (&op->esil, "zf,!,?{,%s,pc,=", ARG(0));
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
	case ARM_INS_SUBW:
	case ARM_INS_SUB:
		if (!strcmp (ARG(2), "")) {
			if (!strcmp (ARG(0), ARG(1))) {
				r_strbuf_appendf (&op->esil, "0,%s,=", ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,-=",
					ARG(1), ARG(0));
			}
		} else {
			if (!strcmp (ARG(0), ARG(1))) {
				r_strbuf_appendf (&op->esil, "%s,%s,-=", ARG(2), ARG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
					ARG(2), ARG(1), ARG(0));
			}
		}
		break;
	case ARM_INS_MUL:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,=", ARG(2), ARG(1), ARG(0));
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
	case ARM_INS_ADD:
		if (!strcmp (ARG(2), "")) {
			if (!strcmp (ARG(1), "pc")) {
				int delta = thumb ? 4 : 8;
				if (thumb) {
					delta -= op->size;
					if (!(addr & 2))
						delta += 2;
				}
				r_strbuf_appendf (&op->esil,
					"%d,2,2,%s,>>,<<,+,%s,+=",
					delta, ARG(1), ARG(0));
			} else {
				if (!strcmp (ARG(0), ARG(1))) {
					r_strbuf_appendf (&op->esil, "2,%s,*=", ARG(0));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,+=", ARG(1), ARG(0));
				}
			}
		} else {
			if (!strcmp (ARG(1), "pc")) {
				int delta = 4; //thumb ? 4 : 8;
				r_strbuf_appendf (&op->esil, "%d,%s,+,%s,+,%s,=", delta, ARG(2), ARG(1), ARG(0));
			} else {
				if (!strcmp (ARG(0), ARG(1))) {
					r_strbuf_appendf (&op->esil, "%s,%s,+=", ARG(2), ARG(0));
				} else if (!strcmp (ARG(2),"0")) {
					r_strbuf_appendf (&op->esil, "%s,%s,=", ARG(1), ARG(0));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
				}
			}
		}
		break;
	case ARM_INS_STRH:
		r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[2]",
			REG(0), MEMBASE(1), MEMDISP(1));
		break;
	case ARM_INS_STR:
		r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4]",
			REG(0), MEMBASE(1), MEMDISP(1));
		break;
	case ARM_INS_STRB:
		r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[1]",
			REG(0), MEMBASE(1), MEMDISP(1));
		break;
	case ARM_INS_TST:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG(1), ARG(0));
		break;
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
		r_strbuf_appendf (&op->esil, "%s,%d,+,[1],%s,=",
			MEMBASE(1), MEMDISP(1), REG(0));
		break;
	case ARM_INS_LDRHT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRT:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
	case ARM_INS_LDR:
		addr &= ~3LL;
		if (MEMDISP(1) < 0) {
			if (REGBASE(1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta - MEMDISP(1);
				r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=",
					"$$", MEMDISP(1), REG(0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=",
					MEMBASE(1), MEMDISP(1), REG(0));
			}
		} else {
			if (REGBASE(1) == ARM_REG_PC) {
				const char *pc = "$$"; //MEMBASE(1);
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				if (ISMEM(1) && LSHIFT2(1)) {
					r_strbuf_appendf (&op->esil, "2,2,%d,%s,+,>>,<<,%d,%s,<<,+,[4],%s,=",
						pcdelta, pc, LSHIFT2(1), MEMINDEX(1), REG(0));
				} else {
					if (ISREG(1)) {
						r_strbuf_appendf (&op->esil, "2,2,%d,%s,+,>>,<<,%s,+,[4],%s,=",
							pcdelta, pc, MEMINDEX(1), REG(0));
					} else {
						r_strbuf_appendf (&op->esil, "2,2,%d,%s,+,>>,<<,%d,+,[4],%s,=",
							pcdelta, pc, MEMDISP(1), REG(0));
					}
				}
			} else {
				if (ISMEM(1) && LSHIFT(1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,[4],%s,=",
						MEMBASE(1), LSHIFT(1), MEMINDEX(1), REG(0));
				} else {
					if (ISREG(1)) {
						r_strbuf_appendf (&op->esil, "%s,%s,+,[4],%s,=",
							MEMBASE(1), MEMINDEX(1), REG(0));
					} else {
						r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=",
							MEMBASE(1), MEMDISP(1), REG(0));
					}
				}
			}
		}
		break;
	case ARM_INS_MSR:
		msr_flags = insn->detail->arm.operands[0].reg >> 4;
		r_strbuf_appendf (&op->esil, "0,",REG(1));
		if (msr_flags & 1) {
			r_strbuf_appendf (&op->esil, "0xFF,|,");
		}
		if (msr_flags & 2) {
			r_strbuf_appendf (&op->esil, "0xFF00,|,");
		}
		if (msr_flags & 4) {
			r_strbuf_appendf (&op->esil, "0xFF0000,|,");
		}
		if (msr_flags & 8) {
			r_strbuf_appendf (&op->esil, "0xFF000000,|,");
		}
		r_strbuf_appendf (&op->esil, "DUP,!,SWAP,&,%s,SWAP,cpsr,&,|,cpsr,=",REG(1));
		break;
	case ARM_INS_UBFX:
		if (IMM (3)>0 && IMM (3)<=32-IMM (2)) {
			r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64u",<<,&,>>,%s,=",
				IMM (2),REG (1),IMM (2),bitmask_by_width[IMM (3)-1],REG (0));
		}
		break;
	case ARM_INS_UXTB:
		r_strbuf_appendf (&op->esil, "%s,0xff,&,%s,=",ARG (1),REG (0));
		break;
	case ARM_INS_RSB:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,%s,-=",ARG (0),ARG (1));
		} else if (OPCOUNT () == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",ARG (1),ARG (2),ARG (0));
		}
		break;
	case ARM_INS_BIC:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&=",ARG (1),ARG (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&,%s,=",ARG (2),ARG (1),ARG (0));
		}
		break;
	default:
		break;
	}
	return 0;
}

static void anop64 (RAnalOp *op, cs_insn *insn) {
	ut64 addr = op->addr;
	switch (insn->id) {
	case ARM64_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case ARM64_INS_ADRP:
	case ARM64_INS_ADR:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case ARM64_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ARM64_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (REGID64(0) == ARM64_REG_SP) {
			if (REGID64(1) == ARM64_REG_SP) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = IMM64(2);
			} else {
				op->stackop = R_ANAL_STACK_RESET;
				op->stackptr = 0;
			}
		}
		break;
	case ARM64_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_CSEL:
	case ARM64_INS_FCSEL:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case ARM64_INS_MOV:
		if (REGID64(0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		/* fallthru */
	case ARM64_INS_MOVI:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		break;
	case ARM64_INS_UXTB:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_INS_UXTH:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_INS_BRK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_CMP:
	case ARM64_INS_CMN:
	case ARM64_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM64_INS_ORR:
	case ARM64_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM64_INS_EOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_INS_LSL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_INS_ASR:
	case ARM64_INS_LSR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_INS_STRB:
	case ARM64_INS_STURB:
	case ARM64_INS_STUR:
	case ARM64_INS_STR:
	case ARM64_INS_STP:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP64(1);
		}
		break;
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDR:
	case ARM64_INS_LDP:
	case ARM64_INS_LDRH:
	case ARM64_INS_LDRB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		}
		break;
	case ARM64_INS_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_BL: // bl 0x89480
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM64(0);
		op->fail = addr + 4;
		break;
	case ARM64_INS_BLR: // blr x0
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->fail = addr + 4;
		//op->jump = IMM64(0);
		break;
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(1);
		op->fail = addr+op->size;
		break;
	case ARM64_INS_TBZ:
	case ARM64_INS_TBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(2);
		op->fail = addr+op->size;
		break;
	case ARM64_INS_BR:
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->eob = 1;
		break;
	case ARM64_INS_B:
		// BX LR == RET
		if (insn->detail->arm64.operands[0].reg == ARM64_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm64.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr+op->size;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM64(0);
		}
		break;
	default:
		break;
	}
}

static int cond_cs2r2(int cc) {
	if (cc == ARM_CC_AL || cc < 0) {
		cc = R_ANAL_COND_AL;
	} else {
		switch (cc) {
		case ARM_CC_EQ: cc = R_ANAL_COND_EQ; break;
		case ARM_CC_NE: cc = R_ANAL_COND_NE; break;
		case ARM_CC_HS: cc = R_ANAL_COND_HS; break;
		case ARM_CC_LO: cc = R_ANAL_COND_LO; break;
		case ARM_CC_MI: cc = R_ANAL_COND_MI; break;
		case ARM_CC_PL: cc = R_ANAL_COND_PL; break;
		case ARM_CC_VS: cc = R_ANAL_COND_VS; break;
		case ARM_CC_VC: cc = R_ANAL_COND_VC; break;

		case ARM_CC_HI: cc = R_ANAL_COND_HI; break;
		case ARM_CC_LS: cc = R_ANAL_COND_LS; break;
		case ARM_CC_GE: cc = R_ANAL_COND_GE; break;
		case ARM_CC_LT: cc = R_ANAL_COND_LT; break;
		case ARM_CC_GT: cc = R_ANAL_COND_GT; break;
		case ARM_CC_LE: cc = R_ANAL_COND_LE; break;
		}
	}
	return cc;
}

static void anop32 (RAnalOp *op, cs_insn *insn, bool thumb) {
	const ut64 addr = op->addr;
	int i;
	op->cond = cond_cs2r2 (insn->detail->arm.cc);
	if (op->cond == R_ANAL_COND_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}
	switch (insn->id) {
#if 0

If PC is specified for Rn, the value used is the address of the instruction plus 4.

These instructions cause a PC-relative forward branch using a table of single byte offsets (TBB) or halfword offsets (TBH). Rn provides a pointer to the table, and Rm supplies an index into the table. The branch length is twice the value of the byte (TBB) or the halfword (TBH) returned from the table. The target of the branch table must be in the same execution state.

jmp $$ + 4 + ( [delta] * 2 )

#endif
	case ARM_INS_TBH: // half word table
	case ARM_INS_TBB: // byte table
		op->type = R_ANAL_OP_TYPE_UJMP;
		// TABLE JUMP  used for switch statements
		break;
	case ARM_INS_IT:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + insn->size;
		op->fail = addr + insn->size + 4; // XXX must be next_insn->size;
			// XXX what if instruction is 4
		break;
	case ARM_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ARM_INS_POP:
	case ARM_INS_FLDMDBX:
	case ARM_INS_FLDMIAX:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
	case ARM_INS_LDM:
		op->type = R_ANAL_OP_TYPE_POP;
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG &&
					insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				if (insn->detail->arm.cc == ARM_CC_AL)
					op->type = R_ANAL_OP_TYPE_RET;
				else
					op->type = R_ANAL_OP_TYPE_CRET;
				break;
			}
		}
		break;
	case ARM_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (ISREG(0)) {
			if (REGID(0) == ARM_REG_SP) {
// 0x00008254    10d04de2     sub sp, sp, 0x10
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = IMM (2);
			}
		}
		break;
	case ARM_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID(1) == ARM_REG_PC) {
			op->ptr = (addr & ~3) + (thumb ? 4 : 8) + IMM(2);
//if (addr & 2) { op->ptr += 2; }
			op->refptr = 4;
		}
		break;
	case ARM_INS_VMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case ARM_INS_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case ARM_INS_MOV:
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (REGID(0) == ARM_REG_PC) {
			if (REGID(1) == ARM_REG_LR) {
				op->type = R_ANAL_OP_TYPE_RET;
			} else {
				op->type = R_ANAL_OP_TYPE_UJMP;
			}
		}
		if (ISIMM(1)) {
			op->ptr = IMM(1);
		}
		break;
	case ARM_INS_UDF:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case ARM_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case ARM_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM_INS_CMP:
	case ARM_INS_CMN:
	case ARM_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		if (ISIMM(1)) {
			op->ptr = IMM(1);
		}
		break;
	case ARM_INS_ROR:
	case ARM_INS_ORN:
	case ARM_INS_LSL:
	case ARM_INS_LSR:
		break;
		//case ARM_INS_POP:
	case ARM_INS_PUSH:
	case ARM_INS_STM:
	case ARM_INS_STMDB:
		op->type = R_ANAL_OP_TYPE_PUSH;
// 0x00008160    04202de5     str r2, [sp, -4]!
// 0x000082a0    28000be5     str r0, [fp, -0x28]
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	case ARM_INS_STRBT:
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STRT:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = -MEMDISP(1);
		}
		break;
	case ARM_INS_LDR:
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDRT:
// 0x000082a8    28301be5     ldr r3, [fp, -0x28]
		if (REGID(0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_UJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = -MEMDISP(1);
		}
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0) & UT32_MAX;
		op->fail = addr + op->size;
		break;
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM(1) & UT32_MAX;
		op->fail = addr + op->size;
		if (op->jump == op->fail) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		}
		break;
	case ARM_INS_B:
		if (insn->detail->arm.cc == ARM_CC_INVALID) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->fail = addr+op->size;
		} else if (insn->detail->arm.cc == ARM_CC_AL) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr+op->size;
		}
		op->jump = IMM(0) & UT32_MAX;
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		// BX LR == RET
		if (ISREG(0)) {
			switch (REGID(0)) {
			case ARM_REG_LR:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case ARM_REG_IP:
				op->type = R_ANAL_OP_TYPE_UJMP;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_UJMP;
				op->eob = true;
				break;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
		}
		break;
	default:
		break;
	}
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	static csh handle = 0;
	static int omode = -1;
	static int obits = 32;
	cs_insn *insn = NULL;
	int mode = (a->bits==16)? CS_MODE_THUMB: CS_MODE_ARM;
	int n, ret;
	mode |= (a->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	if (mode != omode || a->bits != obits) {
		cs_close (&handle);
		handle = 0; // unnecessary
		omode = mode;
		obits = a->bits;
	}
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = (a->bits==16)? 2: 4;
	op->stackop = R_ANAL_STACK_NULL;
	op->delay = 0;
	op->jump = op->fail = -1;
	op->addr = addr;
	op->ptr = op->val = -1;
	op->refptr = 0;
	r_strbuf_init (&op->esil);
	if (handle == 0) {
		ret = (a->bits==64)?
			cs_open (CS_ARCH_ARM64, mode, &handle):
			cs_open (CS_ARCH_ARM, mode, &handle);
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		if (ret != CS_ERR_OK) {
			return -1;
		}
	}

	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n<1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		bool thumb = cs_insn_group (handle, insn, ARM_GRP_THUMB);
		op->size = insn->size;
		if (a->bits == 64) {
			anop64 (op, insn);
			if (a->decode) {
				analop64_esil (a, op, addr, buf, len, &handle, insn);
			}
		} else {
			anop32 (op, insn, thumb);
			if (a->decode) {
				analop_esil (a, op, addr, buf, len, &handle, insn, thumb);
			}
		}
		cs_free (insn, n);
	}
//		cs_close (&handle);
	return op->size;
}

static char *get_reg_profile(RAnal *anal) {
	const char *p;
	if (anal->bits == 64) {
		p = \
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	x29\n"
		"=A0	x0\n"
		"=A1	x1\n"
		"=A2	x2\n"
		"=A3	x3\n"
		"=ZF	zf\n"
		"=SF	nf\n"
		"=OF	vf\n"
		"=CF	cf\n"
		"=SN	x0\n"

		/* 32bit sub-registers */
		"gpr	w0	.32	0	0\n"
		"gpr	w1	.32	8	0\n"
		"gpr	w2	.32	16	0\n"
		"gpr	w3	.32	24	0\n"
		"gpr	w4	.32	32	0\n"
		"gpr	w5	.32	40	0\n"
		"gpr	w6	.32	48	0\n"
		"gpr	w7	.32	56	0\n"
		"gpr	w8	.32	64	0\n"
		"gpr	w9	.32	72	0\n"
		"gpr	w10	.32	80	0\n"
		"gpr	w11	.32	88	0\n"
		"gpr	w12	.32	96	0\n"
		"gpr	w13	.32	104	0\n"
		"gpr	w14	.32	112	0\n"
		"gpr	w15	.32	120	0\n"
		"gpr	w16	.32	128	0\n"
		"gpr	w17	.32	136	0\n"
		"gpr	w18	.32	144	0\n"
		"gpr	w19	.32	152	0\n"
		"gpr	w20	.32	160	0\n"
		"gpr	w21	.32	168	0\n"
		"gpr	w22	.32	176	0\n"
		"gpr	w23	.32	184	0\n"
		"gpr	w24	.32	192	0\n"
		"gpr	w25	.32	200	0\n"
		"gpr	w26	.32	208	0\n"
		"gpr	w27	.32	216	0\n"
		"gpr	w28	.32	224	0\n"
		"gpr	w29	.32	232	0\n"
		"gpr	w30	.32	240	0\n"
		"gpr	wzr	.32	272	0\n"

		/* 64bit */
		"gpr	x0	.64	0	0\n" // x0
		"gpr	x1	.64	8	0\n" // x0
		"gpr	x2	.64	16	0\n" // x0
		"gpr	x3	.64	24	0\n" // x0
		"gpr	x4	.64	32	0\n" // x0
		"gpr	x5	.64	40	0\n" // x0
		"gpr	x6	.64	48	0\n" // x0
		"gpr	x7	.64	56	0\n" // x0
		"gpr	x8	.64	64	0\n" // x0
		"gpr	x9	.64	72	0\n" // x0
		"gpr	x10	.64	80	0\n" // x0
		"gpr	x11	.64	88	0\n" // x0
		"gpr	x12	.64	96	0\n" // x0
		"gpr	x13	.64	104	0\n" // x0
		"gpr	x14	.64	112	0\n" // x0
		"gpr	x15	.64	120	0\n" // x0
		"gpr	x16	.64	128	0\n" // x0
		"gpr	x17	.64	136	0\n" // x0
		"gpr	x18	.64	144	0\n" // x0
		"gpr	x19	.64	152	0\n" // x0
		"gpr	x20	.64	160	0\n" // x0
		"gpr	x21	.64	168	0\n" // x0
		"gpr	x22	.64	176	0\n" // x0
		"gpr	x23	.64	184	0\n" // x0
		"gpr	x24	.64	192	0\n" // x0
		"gpr	x25	.64	200	0\n" // x0
		"gpr	x26	.64	208	0\n" // x0
		"gpr	x27	.64	216	0\n"
		"gpr	x28	.64	224	0\n"
		"gpr	x29	.64	232	0\n"
		"gpr	fp	.64	232	0\n" // fp = x29
		"gpr	x30	.64	240	0\n"
		"gpr	lr	.64	240	0\n" // lr = x30
		"gpr	sp	.64	248	0\n"
		"gpr	pc	.64	256	0\n"
		"gpr	zr	.64	272	0\n"
		"gpr	xzr	.64	272	0\n"
		"gpr	cpsr	.64	264	0	_____tfiae_____________j__qvczn\n"
		"gpr	pstate	.64	264	0\n" // x0
		// probably wrong
		"gpr	nf	.1	.264	0	sign\n" // msb bit of last op
		"gpr	zf	.1	.265	0	zero\n" // set if last op is 0
		"gpr	cf	.1	.268	0	carry\n" // set if last op carries
		"gpr	vf	.1	.269	0	overflow\n"; // set if overflows
	} else {
		p = \
		"=PC	r15\n"
		"=LR	r14\n"
		"=SP	r13\n"
		"=BP	fp\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"gpr	sb	.32	36	0\n" // r9
		"gpr	sl	.32	40	0\n" // rl0
		"gpr	fp	.32	44	0\n" // r11
		"gpr	ip	.32	48	0\n" // r12
		"gpr	sp	.32	52	0\n" // r13
		"gpr	lr	.32	56	0\n" // r14
		"gpr	pc	.32	60	0\n" // r15

		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
		"gpr	r16	.32	64	0\n"
		"gpr	r17	.32	68	0\n"
		"gpr	cpsr	.32	72	0\n"
		"gpr	tf	.1	72.5	0	thumb\n" // +5
		"gpr	ef	.1	72.9	0	endian\n" // +9
		// ...
		"gpr	jf	.1	72.24	0	java\n" // +24
		// ...
		"gpr	qf	.1	72.27	0	sticky_overflow\n" // +27
		"gpr	vf	.1	72.28	0	overflow\n" // +28
		"gpr	cf	.1	72.29	0	carry\n" // +29
		"gpr	zf	.1	72.30	0	zero\n" // +30
		"gpr	nf	.1	72.31	0	negative\n" // +31
		// if-then-counter
		"gpr	itc	.4	72.10	0	if_then_count\n" // +10
		"gpr	gef	.4	72.16	0	great_or_equal\n" // +16
		;
	}
	return strdup (p);
}

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		if (anal && anal->bits == 16)
			return 2;
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		if (anal && anal->bits == 16)
			return 2;
		return 4;
	}
	return 4; // XXX
}

RAnalPlugin r_anal_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "arm",
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.bits = 16 | 32 | 64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm_cs,
	.version = R2_VERSION
};
#endif
