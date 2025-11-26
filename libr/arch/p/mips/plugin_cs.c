/* radare2 - LGPL - Copyright 2013-2024 - pancake */

#include <r_asm.h>
#include <r_endian.h>
#include "mips_utils.h"
#include <capstone/capstone.h>
#include <capstone/mips.h>

R_IPI int mips_assemble(const char *str, ut64 pc, ut8 *out);

// https://www.mrc.uidaho.edu/mrc/people/jff/digital/MIPSir.html

#define OPERAND(x) insn->detail->mips.operands[x]
#define REGID(x) insn->detail->mips.operands[x].reg
#define REG(x) cs_reg_name (*handle, insn->detail->mips.operands[x].reg)
#define IMM(x) insn->detail->mips.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->mips.operands[x].mem.index
#define MEMDISP(x) insn->detail->mips.operands[x].mem.disp
#define OPCOUNT() insn->detail->mips.op_count
// TODO scale and disp

#define SET_VAL(op,i) \
	if ((i)<OPCOUNT() && OPERAND(i).type == MIPS_OP_IMM) {\
		(op)->val = OPERAND(i).imm;\
	}

#define CREATE_SRC_DST_3(op) \
	src0 = r_vector_push (&(op)->srcs, NULL);\
	src1 = r_vector_push (&(op)->srcs, NULL);\
	dst = r_vector_push (&(op)->dsts, NULL);

#define CREATE_SRC_DST_2(op) \
	src0 = r_vector_push (&(op)->srcs, NULL);\
	dst = r_vector_push (&(op)->dsts, NULL);

#define SET_SRC_DST_3_REGS(op) \
	CREATE_SRC_DST_3 (op); \
	dst->reg = REG (0); \
	src0->reg = REG (1); \
	src1->reg = REG (2);

#define SET_SRC_DST_3_IMM(op) \
	CREATE_SRC_DST_3 (op);\
	dst->reg = REG (0);\
	src0->reg = REG (1);\
	src1->imm = IMM (2);

#define SET_SRC_DST_2_REGS(op) \
	CREATE_SRC_DST_2 (op);\
	dst->reg = REG (0);\
	src0->reg = REG (1);

#define SET_SRC_DST_3_REG_OR_IMM(op) \
	if (OPERAND(2).type == MIPS_OP_IMM) {\
		SET_SRC_DST_3_IMM (op);\
	} else if (OPERAND(2).type == MIPS_OP_REG) {\
		SET_SRC_DST_3_REGS (op);\
	}

// ESIL macros:

// put the sign bit on the stack
#define ES_IS_NEGATIVE(arg) "1,"arg",<<<,1,&"


// Call with delay slot.
#define ES_CALL_DR(ra, addr) "pc,4,+,"ra",=,"ES_J_D(addr)
#define ES_CALL_D(addr) ES_CALL_DR("ra", addr)

// Call without delay slot.
#define ES_CALL_NDR(ra, addr) "pc,"ra",=,"ES_J_ND(addr)
#define ES_CALL_ND(addr) ES_CALL_NDR("ra", addr)

// Delay-slot helper macros.
// Trap if executed in a delay slot.
#define ES_TRAP_DS(addr) "$ds,!,!,?{," addr ",1,TRAP,BREAK,},"
// Jump with delay slot: record target and mark delay.
#define ES_J_D(addr) addr",SETJT,1,SETD"
// Jump without delay slot: update PC immediately.
#define ES_J_ND(addr) addr",pc,:="
// For likely branches: skip delay slot by advancing PC over it.
#define ES_SKIP_NXT() "pc,4,+,pc,:="

#define ES_B(x) "0xff,"x",&"
#define ES_H(x) "0xffff,"x",&"
#define ES_W(x) "0xffffffff,"x",&"

// sign extend 32 -> 64
#define ES_SIGN32_64(arg)	es_sign_n_64 (as, op, arg, 32)
#define ES_SIGN16_64(arg)	es_sign_n_64 (as, op, arg, 16)

#define ES_ADD_CK32_OVERF(x, y, z) es_add_ck (op, x, y, z, 32)
#define ES_ADD_CK64_OVERF(x, y, z) es_add_ck (op, x, y, z, 64)

// * cs6 compatibility *
#if CS_API_MAJOR == 6
// XXX - There are more options than EQ or QB, need to be tested:
#define MIPS_INS_CMPU MIPS_INS_CMPU_EQ_QB
#define MIPS_INS_CMPGU MIPS_INS_CMPGU_EQ_QB
#define MIPS_INS_CMPGDU MIPS_INS_CMPGDU_EQ_QB
#define MIPS_INS_SHRAV MIPS_INS_SHRAV_QB
#define MIPS_INS_SHRAV_R MIPS_INS_SHRAV_R_QB
#define MIPS_INS_SHRA MIPS_INS_SHRA_QB
#define MIPS_INS_SHRA_R MIPS_INS_SHRA_R_QB
#define MIPS_INS_SHRL MIPS_INS_SHRL_QB

// XXX - don't know if there should be _D or _W, went for _D:
#define MIPS_INS_BZ MIPS_INS_BZ_D
#define MIPS_INS_MOV MIPS_INS_MOV_D
#define MIPS_INS_FSUB MIPS_INS_FSUB_D
#define MIPS_INS_NEGU MIPS_INS_NEG_D
#define MIPS_INS_LDI MIPS_INS_LDI_D
#define MIPS_INS_SUBV MIPS_INS_SUBV_D
#define MIPS_INS_SUBVI MIPS_INS_SUBVI_D
#define MIPS_INS_FMSUB MIPS_INS_FMSUB_D
#define MIPS_INS_SUBS_S MIPS_INS_SUBS_S_D
#define MIPS_INS_SUBS_U MIPS_INS_SUBS_U_D
#define MIPS_INS_SUBUH MIPS_INS_SUBUH_QB
#define MIPS_INS_SUBUH_R MIPS_INS_SUBUH_R_QB
#define MIPS_INS_MULV MIPS_INS_MULV_D
#define MIPS_INS_MULSA MIPS_INS_MULSA_W_PH
#define MIPS_INS_FMUL MIPS_INS_FMUL_D
#define MIPS_INS_FDIV MIPS_INS_FDIV_D
#define MIPS_INS_DIV_U MIPS_INS_DIV_U_D
#define MIPS_INS_BNZ MIPS_INS_BNZ_D
#define MIPS_INS_BNEG MIPS_INS_BNEG_D
#define MIPS_INS_BNEGI MIPS_INS_BNEGI_D

#define MIPS_REG_25 MIPS_REG_T9
#endif
// *********************

static inline void es_sign_n_64(RArchSession *as, RAnalOp *op, const char *arg, int bit) {
	if (as->config->bits == 64) {
		r_strbuf_appendf (&op->esil, ",%d,%s,~,%s,=,", bit, arg, arg);
	} else {
		r_strbuf_append (&op->esil, ",");
	}
}

static inline void es_add_ck(RAnalOp *op, const char *a1, const char *a2, const char *re, int bit) {
	ut64 mask = 1ULL << (bit-1);
	r_strbuf_appendf (&op->esil,
		"%d,0x%" PFMT64x ",%s,%s,^,&,>>,%d,0x%" PFMT64x ",%s,%s,+,&,>>,|,1,==,$z,?{,0x%"PFMT64x",1,TRAP,}{,%s,%s,+,%s,=,}",
		bit-2, mask, a1, a2, bit-1, mask, a1, a2, op->addr, a1, a2, re);
}

#define PROTECT_ZERO() \
	if (REG(0)[0] == 'z') {\
		r_strbuf_append (&op->esil, ",");\
	} else /**/

#define ESIL_LOAD(size) \
	PROTECT_ZERO () {\
		r_strbuf_appendf (&op->esil, "%s,["size"],%s,=",\
			ARG(1), REG(0));\
	}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_mips *x = &insn->detail->mips;
	for (i = 0; i < x->op_count; i++) {
		cs_mips_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case MIPS_OP_REG:
			{
				const char *rn = cs_reg_name (handle, op->reg);
				pj_ks (pj, "type", "reg");
				pj_ks (pj, "value", rn? rn: "");
			}
			break;
		case MIPS_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case MIPS_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != MIPS_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			pj_kN (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static const char *arg(csh *handle, cs_insn *insn, char *buf, size_t buf_sz, int n) {
	*buf = 0;
	switch (insn->detail->mips.operands[n].type) {
	case MIPS_OP_INVALID:
		break;
	case MIPS_OP_REG:
		snprintf (buf, buf_sz, "%s",
			cs_reg_name (*handle,
				insn->detail->mips.operands[n].reg));
		break;
	case MIPS_OP_IMM:
		{
			st64 x = (st64)insn->detail->mips.operands[n].imm;
			snprintf (buf, buf_sz, "%"PFMT64d, x);
		}
		break;
	case MIPS_OP_MEM:
		{
			int disp = insn->detail->mips.operands[n].mem.disp;
			if (disp < 0) {
				snprintf (buf, buf_sz, "%"PFMT64d",%s,-",
					(ut64)(-insn->detail->mips.operands[n].mem.disp),
					cs_reg_name (*handle, insn->detail->mips.operands[n].mem.base));
			} else {
				snprintf (buf, buf_sz, "0x%"PFMT64x",%s,+",
					(ut64)insn->detail->mips.operands[n].mem.disp,
					cs_reg_name (*handle, insn->detail->mips.operands[n].mem.base));
			}
		}
		break;
	}
	return buf;
}

#define ARG(x) (*str[x] != 0)?str[x]:arg(handle, insn, str[x], sizeof (str[x]), x)

static int analop_esil(RArchSession *as, RAnalOp *op, csh *handle, cs_insn *insn) {
	char str[8][32] = {{0}};
	int i;
	ut64 addr = op->addr;

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	if (insn) {
		addr = insn->address;
		// caching operands
		for (i = 0; i < insn->detail->mips.op_count && i < 8; i++) {
			*str[i] = 0;
			ARG (i);
		}
	}

	if (insn) {
		switch (insn->id) {
		case MIPS_INS_NOP:
			r_strbuf_set (&op->esil, ",");
			break;
		case MIPS_INS_BREAK:
			r_strbuf_setf (&op->esil, "%"PFMT64d",%" PFMT64d ",TRAP", (st64)IMM (0), (st64)IMM (0));
			break;
		case MIPS_INS_SD:
			r_strbuf_appendf (&op->esil, "%s,%s,=[8]",
				ARG (0), ARG (1));
			break;
		case MIPS_INS_SW:
		case MIPS_INS_SWL:
		case MIPS_INS_SWR:
			r_strbuf_appendf (&op->esil, "%s,%s,=[4]",
				ARG (0), ARG (1));
			break;
		case MIPS_INS_SH:
			r_strbuf_appendf (&op->esil, "%s,%s,=[2]",
				ARG (0), ARG (1));
			break;
		case MIPS_INS_SWC1:
		case MIPS_INS_SWC2:
			r_strbuf_setf (&op->esil, "%s,$", ARG (1));
			break;
		case MIPS_INS_SB:
			r_strbuf_appendf (&op->esil, "%s,%s,=[1]",
				ARG (0), ARG (1));
			break;
		case MIPS_INS_CMP:
		case MIPS_INS_CMPU:
		case MIPS_INS_CMPGU:
		case MIPS_INS_CMPGDU:
		case MIPS_INS_CMPI:
			r_strbuf_appendf (&op->esil, "%s,%s,==", ARG (1), ARG (0));
			break;
		case MIPS_INS_DSRA:
			r_strbuf_appendf (&op->esil,
				"%s,%s,>>,31,%s,>>,?{,32,%s,32,-,0xffffffff,<<,0xffffffff,&,<<,}{,0,},|,%s,=",
				ARG (2), ARG (1), ARG (1), ARG (2), ARG (0));
			break;
		case MIPS_INS_SHRAV:
		case MIPS_INS_SHRAV_R:
		case MIPS_INS_SHRA:
		case MIPS_INS_SHRA_R:
		case MIPS_INS_SRA:
			r_strbuf_appendf (&op->esil,
				"0xffffffff,%s,%s,>>,&,31,%s,>>,?{,%s,32,-,0xffffffff,<<,0xffffffff,&,}{,0,},|,%s,=",
				ARG (2), ARG (1), ARG (1), ARG (2), ARG (0));
			break;
		case MIPS_INS_SHRL:
			// suffix 'S' forces conditional flag to be updated
		case MIPS_INS_SRLV:
		case MIPS_INS_SRL:
			r_strbuf_appendf (&op->esil, "%s,%s,>>,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case MIPS_INS_SLLV:
		case MIPS_INS_SLL:
			r_strbuf_appendf (&op->esil, "%s,%s,<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case MIPS_INS_BALC:
			// BALC address
			// Branch And Link, Compact. Unconditional PC relative branch to address,
			// placing return address in register $31.
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_ND ("%s"), addr, ARG (0));
			break;
		case MIPS_INS_BAL:
		case MIPS_INS_JAL:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_D ("%s"), addr, ARG (0));
			break;
		case MIPS_INS_JALR:
		case MIPS_INS_JALRS:
			if (OPCOUNT () < 2) {
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_D ("%s"), addr, ARG (0));
			} else {
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_DR ("%s", "%s"), addr, ARG (0), ARG (1));
				}
			}
			break;
		case MIPS_INS_JALRC: // no delay
			if (OPCOUNT () < 2) {
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_ND ("%s"), addr, ARG (0));
			} else {
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_CALL_NDR ("%s", "%s"), addr, ARG (0), ARG (1));
				}
			}
			break;
		case MIPS_INS_JRADDIUSP:
			// increment stackpointer in X and jump to %ra
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,sp,+=," ES_J_D ("ra"), addr, ARG (0));
			break;
		case MIPS_INS_JRC:
		case MIPS_INS_BC:
			// JRC rt
			// Jump Register, Compact. Unconditional jump to address in register $rt.
			// BC address
			// Branch, Compact. Unconditional PC relative branch to address.
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_J_ND ("%s"), addr, ARG (0));
			break;
		case MIPS_INS_JR:
		case MIPS_INS_J:
		case MIPS_INS_B: // ???
			// jump to address with conditional
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "" ES_J_D ("%s"), addr, ARG (0));
			break;
		case MIPS_INS_BNEC:
				// BNEC rs, rt, address
				// Branch Not Equal, Compact. PC relative branch to address if register $rs is not equal to
				// register $rt.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BNE: // bne $s, $t, offset
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BNEL:
				// BNEL rs, rt, offset
				// To compare GPRs then do a PC-relative conditional branch; execute the delay slot only if
				// the branch is taken.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BEQC:
				// BEQC rs, rt, address
				// Branch if Equal, Compact. PC relative branch to address if registers $rs and $rt are are equal.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,!,?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BEQ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,!,?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BEQL:
				// BEQL rs, rt, offset
				// To compare GPRs then do a PC-relative conditional branch; execute the delay slot only if
				// the branch is taken.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,^,!,?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
					addr, ARG (0), ARG (1), ARG (2));
				break;
		case MIPS_INS_BEQZC:
				// BEQZC rt, address # when rt and address are in range
				// Branch if Equal to Zero, Compact. PC relative branch to address if register $rt equals zero.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,!,?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BZ:
		case MIPS_INS_BEQZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,!,?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BNEZC:
				// BNEZC rt, address
				// Branch if Not Equal to Zero, Compact. PC relative branch to address if register $rt is not equal to zero.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BNEZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BEQZALC:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,!,?{," ES_CALL_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BLEZC:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,<=,?{," ES_J_ND ("%s") ",},",
				addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BLEZ:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,<=,?{," ES_J_D ("%s") ",},",
				addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BLEZL:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,<=,?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
				addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BGEC:
				// BGEC rs, rt, address
				// Branch if Greater than or Equal, Compact. PC relative branch to address if register $rs
				// is greater than or equal to register $rt.
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "%s,%s,>=,?{," ES_J_ND ("%s") ",}",
					addr, ARG (1), ARG (0), ARG (2));
				break;
		case MIPS_INS_BGEZC:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",!,?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGEZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",!,?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGEZL:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",!,?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGEZAL:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",!,?{," ES_CALL_D ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGEZALC:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",!,?{," ES_CALL_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGTZALC:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,>,?{," ES_CALL_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BLTZAL:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",?{," ES_CALL_D ("%s") ",}",
						addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BLTZC:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",?{," ES_J_ND ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BLTZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",?{," ES_J_D ("%s") ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BLTZL:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) ES_IS_NEGATIVE ("%s") ",?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
					addr, ARG (0), ARG (1));
				break;
		case MIPS_INS_BGTZC:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,>,?{," ES_J_ND ("%s") ",},",
					addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BGTZ:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,>,?{," ES_J_D ("%s") ",},",
					addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BGTZL:
			r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "0,%s,>,?{," ES_J_D ("%s") ",}{," ES_SKIP_NXT () ",}",
					addr, ARG (0), ARG (1));
			break;
		case MIPS_INS_BTEQZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "t,!,?{," ES_J_D ("%s") ",}", addr, ARG (0));
				break;
		case MIPS_INS_BTNEZ:
				r_strbuf_appendf (&op->esil, ES_TRAP_DS ("0x%"PFMT64x) "t,?{," ES_J_D ("%s") ",}", addr, ARG (0));
				break;
			case MIPS_INS_MOV:
			case MIPS_INS_MOVE:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "%s,%s,=", ARG (1), REG (0));
				}
				break;
			case MIPS_INS_MOVZ:
			case MIPS_INS_MOVF:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "0,%s,==,$z,?{,%s,%s,=,}",
						ARG (2), ARG (1), REG (0));
				}
				break;
			case MIPS_INS_MOVN:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "0,%s,==,$z,!,?{,%s,%s,=,}",
						ARG (2), ARG (1), REG (0));
				}
				break;
			case MIPS_INS_MOVT:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "1,%s,==,$z,?{,%s,%s,=,}",
						ARG (2), ARG (1), REG (0));
				}
				break;
			case MIPS_INS_FSUB:
			case MIPS_INS_SUB:
			case MIPS_INS_SUBU:
			case MIPS_INS_DSUB:
			case MIPS_INS_DSUBU:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
						ARG (2), ARG (1), ARG (0));
				}
				break;
			case MIPS_INS_NEG:
			case MIPS_INS_NEGU:
				r_strbuf_appendf (&op->esil, "%s,0,-,%s,=,",
					ARG (1), ARG (0));
				break;

			/** signed -- sets overflow flag */
			case MIPS_INS_ADD:
				{
					PROTECT_ZERO () {
						ES_ADD_CK32_OVERF (ARG(1), ARG(2), ARG(0));
					}
				}
				break;
			case MIPS_INS_ADDI:
				PROTECT_ZERO () {
					ES_ADD_CK32_OVERF (ARG(1), ARG(2), ARG(0));
				}
				break;
			case MIPS_INS_DADD:
			case MIPS_INS_DADDI:
				ES_ADD_CK64_OVERF (ARG(1), ARG(2), ARG(0));
				break;
			/** unsigned */
			case MIPS_INS_DADDU:
			case MIPS_INS_ADDU:
			case MIPS_INS_ADDIU:
			case MIPS_INS_DADDIU:
				{
					const char *arg0 = ARG(0);
					const char *arg1 = ARG(1);
					const char *arg2 = ARG(2);
					PROTECT_ZERO () {
						if (*arg2 == '-') {
							r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
								arg2+1, arg1, arg0);
						} else {
							r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=",
								arg2, arg1, arg0);
						}
					}
				}
				break;
			case MIPS_INS_LI:
			case MIPS_INS_LDI:
				r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",%s,=", (ut64)IMM(1), ARG(0));
				break;
			case MIPS_INS_LUI:
				r_strbuf_appendf (&op->esil, "0x%" PFMT64x "0000,%s,=", (ut64)IMM(1), ARG(0));
				break;
			case MIPS_INS_LB:
				op->sign = true;
				ESIL_LOAD ("1");
				break;
			case MIPS_INS_LBU:
				//one of these is wrong
				ESIL_LOAD ("1");
				break;
			case MIPS_INS_LW:
			case MIPS_INS_LWC1:
			case MIPS_INS_LWC2:
			case MIPS_INS_LWL:
			case MIPS_INS_LWR:
			case MIPS_INS_LWU:
			case MIPS_INS_LL:
				ESIL_LOAD ("4");
				break;

			case MIPS_INS_LDL:
			case MIPS_INS_LDC1:
			case MIPS_INS_LDC2:
			case MIPS_INS_LLD:
			case MIPS_INS_LD:
				ESIL_LOAD ("8");
				break;

			case MIPS_INS_LWX:
			case MIPS_INS_LH:
			case MIPS_INS_LHU:
			case MIPS_INS_LHX:
				ESIL_LOAD ("2");
				break;

			case MIPS_INS_AND:
			case MIPS_INS_ANDI:
				{
					const char *arg0 = ARG(0);
					const char *arg1 = ARG(1);
					const char *arg2 = ARG(2);
					if (!strcmp (arg0, arg1)) {
						r_strbuf_appendf (&op->esil, "%s,%s,&=", arg2, arg1);
					} else {
						r_strbuf_appendf (&op->esil, "%s,%s,&,%s,=", arg2, arg1, arg0);
					}
				}
				break;
			case MIPS_INS_OR:
			case MIPS_INS_ORI:
				{
				const char *arg0 = ARG(0);
				const char *arg1 = ARG(1);
				const char *arg2 = ARG(2);
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "%s,%s,|,%s,=",
						arg2, arg1, arg0);
					}
				}
				break;
			case MIPS_INS_XOR:
			case MIPS_INS_XORI:
				{
					const char *arg0 = ARG(0);
					const char *arg1 = ARG(1);
					const char *arg2 = ARG(2);
					PROTECT_ZERO () {
						r_strbuf_appendf (&op->esil, "%s,%s,^,%s,=",
							arg2, arg1, arg0);
					}
				}
				break;
			case MIPS_INS_NOR:
				{
					const char *arg0 = ARG(0);
					const char *arg1 = ARG(1);
					const char *arg2 = ARG(2);
					PROTECT_ZERO () {
						r_strbuf_appendf (&op->esil, "%s,%s,|,0xffffffffffffffff,^,%s,=",
							arg2, arg1, arg0);
					}
				}
				break;
			case MIPS_INS_SLT:
			case MIPS_INS_SLTI:
				if (OPCOUNT () < 3) {
					r_strbuf_appendf (&op->esil, "%s,%s,<,t,=", ARG(1), ARG(0));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,<,%s,=", ARG(2), ARG(1), ARG(0));
				}
				break;
			case MIPS_INS_SLTU:
			case MIPS_INS_SLTIU:
				if (OPCOUNT () < 3) {
					r_strbuf_appendf (&op->esil, ES_W("%s")","ES_W("%s")",<,t,=",
						ARG (1), ARG (0));
				} else {
					r_strbuf_appendf (&op->esil, ES_W("%s")","ES_W("%s")",<,%s,=",
						ARG (2), ARG (1), ARG (0));
				}
				break;
			case MIPS_INS_MUL:
				r_strbuf_appendf (&op->esil, ES_W("%s,%s,*")",%s,=", ARG(1), ARG(2), ARG(0));
				ES_SIGN32_64 (ARG(0));
				break;
			case MIPS_INS_MULT:
			case MIPS_INS_MULTU:
				r_strbuf_appendf (&op->esil, ES_W("%s,%s,*")",lo,=", ARG (0), ARG (1));
				ES_SIGN32_64 ("lo");
				r_strbuf_appendf (&op->esil, ES_W("32,%s,%s,*,>>")",hi,=", ARG (0), ARG (1));
				ES_SIGN32_64 ("hi");
				break;
			case MIPS_INS_MFLO:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "lo,%s,=", REG (0));
				}
				break;
			case MIPS_INS_MFHI:
				PROTECT_ZERO () {
					r_strbuf_appendf (&op->esil, "hi,%s,=", REG (0));
				}
				break;
			case MIPS_INS_MTLO:
				r_strbuf_appendf (&op->esil, "%s,lo,=", REG (0));
				ES_SIGN32_64 ("lo");
				break;
			case MIPS_INS_MTHI:
				r_strbuf_appendf (&op->esil, "%s,hi,=", REG (0));
				ES_SIGN32_64 ("hi");
				break;
#if 0
	// could not test div
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
		PROTECT_ZERO () {
			// 32 bit needs sign extend
			r_strbuf_appendf (&op->esil, "%s,%s,/,lo,=,%s,%s,%%,hi,=", REG(1), REG(0), REG(1), REG(0));
		}
		break;
#endif
		default:
			return -1;
		}
	}
	return 0;
}

static const char *parse_reg_name(csh handle, cs_insn *insn, int reg_num) {
	switch (OPERAND (reg_num).type) {
	case MIPS_OP_REG:
		return cs_reg_name (handle, OPERAND (reg_num).reg);
	case MIPS_OP_MEM:
		if (OPERAND (reg_num).mem.base != MIPS_REG_INVALID) {
			return cs_reg_name (handle, OPERAND (reg_num).mem.base);
		}
	default:
		break;
	}
	return NULL;
}

static void op_fillval(RArchSession *as, RAnalOp *op, csh *handle, cs_insn *insn) {
	RAnalValue *dst, *src0, *src1;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			src0 = r_vector_push (&op->srcs, NULL);
			src0->reg = parse_reg_name (*handle, insn, 1);
			src0->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_STORE:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			dst = r_vector_push (&op->dsts, NULL);
			dst->reg = parse_reg_name (*handle, insn, 1);
			dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_OR:
		SET_SRC_DST_3_REG_OR_IMM (op);
		break;
	case R_ANAL_OP_TYPE_MOV:
		SET_SRC_DST_3_REG_OR_IMM (op);
		break;
	case R_ANAL_OP_TYPE_DIV: // UDIV
#if 0
capstone bug
------------
	$ r2 -a mips -e cfg.bigendian=1 -c "wx 0083001b" -
	// should be 3 regs, right?
	[0x00000000]> aoj~{}
	[
	  {
	    "opcode": "divu zero, a0, v1",
	    "disasm": "divu zero, a0, v1",
	    "mnemonic": "divu",
	    "sign": false,
	    "prefix": 0,
	    "id": 192,
	    "opex": {
	      "operands": [
		{
		  "type": "reg",
		  "value": "a0"
		},
		{
		  "type": "reg",
		  "value": "v1"
		}
	      ]
	    },
#endif
		if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG && OPERAND(2).type == MIPS_OP_REG) {
			SET_SRC_DST_3_REGS (op);
		} else if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG) {
			SET_SRC_DST_2_REGS (op);
		} else {
			R_LOG_ERROR ("Unknown div at 0x%08"PFMT64x, op->addr);
		}
		break;
	}
	if (insn && (insn->id == MIPS_INS_SLTI || insn->id == MIPS_INS_SLTIU)) {
		SET_SRC_DST_3_IMM (op);
	}
}

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

static int get_capstone_mode(RArchSession *as) {
	int mode = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	const char *cpu = as->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (!strcmp (cpu, "micro")) {
			mode |= CS_MODE_MICRO;
		} else if (!strcmp (cpu, "r6")) {
			mode |= CS_MODE_MIPS32R6;
		} else if (!strcmp (cpu, "v3")) {
			mode |= CS_MODE_MIPS3;
		} else if (!strcmp (cpu, "v2")) {
#if CS_API_MAJOR > 3
			mode |= CS_MODE_MIPS2;
#endif
		}
	}
	mode |= (as->config->bits == 64)? CS_MODE_MIPS64: CS_MODE_MIPS32;
	return mode;
}

#define CSINC MIPS
#define CSINC_MODE get_capstone_mode(as)
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	RRegItem reg;
	char *cpu;
	int bigendian;
	ut64 t9_pre;
} PluginData;


static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);

	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	PluginData *pd = R_NEW0 (PluginData);
	if (!pd) {
		return false;
	}

	pd->t9_pre = UT64_MAX;
	pd->bigendian = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	pd->cpu = as->config->cpu? strdup (as->config->cpu): NULL;
	if (!r_arch_cs_init (as, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}

	as->data = pd;
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	PluginData *pd = as->data;
	R_FREE (pd->cpu);
	cs_close (&pd->cpd.cs_handle);
	R_FREE (as->data);
	return true;
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static bool plugin_changed(RArchSession *as) {
	PluginData *cpd = as->data;
	if (!cpd) {
		return true;
	}
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config) != cpd->bigendian) {
		return true;
	}
	if (cpd->cpu && as->config->cpu && strcmp (cpd->cpu, as->config->cpu)) {
		eprintf ("cpudif\n");
		return true;
	}
	return false;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	csh handle = cs_handle_for_session (as);
	PluginData *pd;
	cs_insn *insn = NULL;
	if (as->config->syntax == R_ARCH_SYNTAX_REGNUM) {
		cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}

	if (plugin_changed (as)) {
		fini (as);
		init (as);
		handle = cs_handle_for_session (as);
	}
	pd = as->data;
	if (!pd || handle == 0) {
		return false;
	}
	int n, opsize = -1;

// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	op->addr = addr;
	op->size = 4;
	if (op->mnemonic) {
		*op->mnemonic = 0;
	}
	n = cs_disasm (handle, buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
			op->type = R_ANAL_OP_TYPE_ILL;
			opsize = 4;
		}
		goto beach;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_str_newf ("%s%s%s",
			insn->mnemonic,
			insn->op_str[0]?" ":"",
			insn->op_str);
		if (op->mnemonic) {
			r_str_replace_char (op->mnemonic, '$', 0);
		}
		if (R_STR_ISEMPTY (op->mnemonic)) {
			insn->id = MIPS_INS_INVALID;
		}
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	op->refptr = 0;
	switch (insn->id) {
	case MIPS_INS_INVALID:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case MIPS_INS_LB:
	case MIPS_INS_LBU:
	case MIPS_INS_LBUX:
		op->refptr = 1;
		/* fallthrough */
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWXC1:
		if (!op->refptr) {
			op->refptr = 4;
		}
		/* fallthrough */
	case MIPS_INS_LD:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
	case MIPS_INS_LDL:
	case MIPS_INS_LDR:
	case MIPS_INS_LDXC1:
			op->type = R_ANAL_OP_TYPE_LOAD;
			if (!op->refptr) {
				op->refptr = 8;
			}
			switch (OPERAND(1).type) {
			case MIPS_OP_MEM:
				if (OPERAND(1).mem.base == MIPS_REG_GP) {
					op->ptr = as->config->gp + OPERAND(1).mem.disp;
					if (REGID (0) == MIPS_REG_T9) {
						pd->t9_pre = op->ptr;
						RBin *bin = as->arch->binb.bin;
						const ut64 ptrv = mips_read_ptr_at (bin, op->ptr, R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config), as->config->bits);
						if (ptrv != UT64_MAX) {
							pd->t9_pre = ptrv;
						}
					}
				} else if (REGID (0) == MIPS_REG_T9) {
					pd->t9_pre = UT64_MAX;
				}
				break;
		case MIPS_OP_IMM:
			op->ptr = OPERAND(1).imm;
			break;
		case MIPS_OP_REG:
			// wtf?
			break;
		default:
			break;
		}
		// TODO: fill
		break;
	case MIPS_INS_SD:
	case MIPS_INS_SW:
	case MIPS_INS_SB:
	case MIPS_INS_SH:
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
	case MIPS_INS_SWL:
	case MIPS_INS_SWR:
	case MIPS_INS_SWXC1:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case MIPS_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case MIPS_INS_SYSCALL:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case MIPS_INS_BREAK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case MIPS_INS_JALR:
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->delay = 1;
		if (REGID (0) == MIPS_REG_25) {
			op->type = R_ANAL_OP_TYPE_RCALL;
			op->jump = pd->t9_pre;
			pd->t9_pre = UT64_MAX;
		}
		break;
	case MIPS_INS_JAL:
	case MIPS_INS_JALS:
	case MIPS_INS_JALX:
	case MIPS_INS_JRADDIUSP:
	case MIPS_INS_BAL:
	// (no blezal/bgtzal or blezall/bgtzall, only blezalc/bgtzalc)
	case MIPS_INS_BLTZAL: // Branch on < 0 and link
	case MIPS_INS_BGEZAL: // Branch on >= 0 and link
	case MIPS_INS_BLTZALL: // "likely" versions
	case MIPS_INS_BGEZALL:
	case MIPS_INS_BLTZALC: // compact versions
	case MIPS_INS_BLEZALC:
	case MIPS_INS_BGEZALC:
	case MIPS_INS_BGTZALC:
	case MIPS_INS_JIALC:
	case MIPS_INS_JIC:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0);

		switch (insn->id) {
		case MIPS_INS_JIALC:
		case MIPS_INS_JIC:
		case MIPS_INS_BLTZALC:
		case MIPS_INS_BLEZALC:
		case MIPS_INS_BGEZALC:
		case MIPS_INS_BGTZALC:
			// compact versions (no delay)
			op->delay = 0;
			op->fail = addr + 4;
			break;
		default:
			op->delay = 1;
			op->fail = addr + 8;
			break;
		}
		break;
	case MIPS_INS_LI:
	case MIPS_INS_LUI:
		SET_VAL (op, 1);
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case MIPS_INS_MOVE:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case MIPS_INS_ADD:
	case MIPS_INS_ADDI:
	case MIPS_INS_ADDU:
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADD:
	case MIPS_INS_DADDI:
	case MIPS_INS_DADDIU:
		SET_VAL (op, 2);
		op->sign = (insn->id == MIPS_INS_ADDI || insn->id == MIPS_INS_ADD);
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID(0) == MIPS_REG_T9) {
				pd->t9_pre += IMM(2);
		}
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -IMM(2);
		}
		break;
	case MIPS_INS_SUB:
	case MIPS_INS_SUBV:
	case MIPS_INS_SUBVI:
	case MIPS_INS_DSUBU:
	case MIPS_INS_FSUB:
	case MIPS_INS_FMSUB:
	case MIPS_INS_SUBU:
	case MIPS_INS_DSUB:
	case MIPS_INS_SUBS_S:
	case MIPS_INS_SUBS_U:
	case MIPS_INS_SUBUH:
	case MIPS_INS_SUBUH_R:
		SET_VAL (op,2);
		op->sign = insn->id == MIPS_INS_SUB;
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case MIPS_INS_MULV:
	case MIPS_INS_MULT:
	case MIPS_INS_MULSA:
	case MIPS_INS_FMUL:
	case MIPS_INS_MUL:
	case MIPS_INS_DMULT:
	case MIPS_INS_DMULTU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case MIPS_INS_XOR:
	case MIPS_INS_XORI:
		SET_VAL (op,2);
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case MIPS_INS_AND:
	case MIPS_INS_ANDI:
		SET_VAL (op,2);
		op->type = R_ANAL_OP_TYPE_AND;
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = R_ANAL_STACK_ALIGN;
		}
		break;
	case MIPS_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case MIPS_INS_OR:
	case MIPS_INS_ORI:
		SET_VAL (op,2);
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
	case MIPS_INS_FDIV:
	case MIPS_INS_DIV_S:
	case MIPS_INS_DIV_U:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case MIPS_INS_CMPGDU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPU:
	case MIPS_INS_CMPI:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case MIPS_INS_J:
	case MIPS_INS_B:
	case MIPS_INS_BZ:
	case MIPS_INS_BEQ:
	case MIPS_INS_BEQC:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BEQZC:
	case MIPS_INS_BNZ:
	case MIPS_INS_BNE:
	case MIPS_INS_BNEC:
	case MIPS_INS_BNEL:
	case MIPS_INS_BEQL:
	case MIPS_INS_BNEZ:
	case MIPS_INS_BNEZC:
	case MIPS_INS_BNEG:
	case MIPS_INS_BNEGI:
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
	case MIPS_INS_BLTZ:
	case MIPS_INS_BLTZL:
	case MIPS_INS_BLEZ:
	case MIPS_INS_BLEZL:
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZL:
	case MIPS_INS_BGTZ:
	case MIPS_INS_BGTZL:
	case MIPS_INS_BLEZC:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BLTZC:
	case MIPS_INS_BGTZC:
		if (insn->id == MIPS_INS_J || insn->id == MIPS_INS_B ) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
		}

		if (OPERAND(0).type == MIPS_OP_IMM) {
			op->jump = IMM(0);
		} else if (OPERAND(1).type == MIPS_OP_IMM) {
			op->jump = IMM(1);
		} else if (OPERAND(2).type == MIPS_OP_IMM) {
			op->jump = IMM(2);
		}

		switch (insn->id) {
		case MIPS_INS_BEQC:
		case MIPS_INS_BEQZC:
		case MIPS_INS_BNEC:
		case MIPS_INS_BNEZC:
		case MIPS_INS_BLEZC:
		case MIPS_INS_BGEZC:
		case MIPS_INS_BLTZC:
		case MIPS_INS_BGTZC:
			// compact versions (no delay)
			op->delay = 0;
			op->fail = addr+4;
			break;
		default:
			op->delay = 1;
			op->fail = addr+8;
			break;
		}

		break;
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->delay = 1;
		// register is $ra, so jmp is a return
		if (insn->detail->mips.operands[0].reg == MIPS_REG_RA) {
			op->type = R_ANAL_OP_TYPE_RET;
			pd->t9_pre = UT64_MAX;
		}
		if (REGID (0) == MIPS_REG_25) {
			op->jump = pd->t9_pre;
			pd->t9_pre = UT64_MAX;
		}
		break;
	case MIPS_INS_SLT:
	case MIPS_INS_SLTI:
		op->sign = true;
		SET_VAL (op, 2);
		break;
	case MIPS_INS_SLTIU:
		SET_VAL (op, 2);
		break;
	case MIPS_INS_SHRAV:
	case MIPS_INS_SHRAV_R:
	case MIPS_INS_SHRA:
	case MIPS_INS_SHRA_R:
	case MIPS_INS_SRA:
		op->type = R_ANAL_OP_TYPE_SAR;
		SET_VAL (op,2);
		break;
	case MIPS_INS_SHRL:
	case MIPS_INS_SRLV:
	case MIPS_INS_SRL:
		op->type = R_ANAL_OP_TYPE_SHR;
		SET_VAL (op,2);
		break;
	case MIPS_INS_SLLV:
	case MIPS_INS_SLL:
		op->type = R_ANAL_OP_TYPE_SHL;
		SET_VAL (op,2);
		break;
	}
beach:
	set_opdir (op);
	if (insn && mask & R_ARCH_OP_MASK_OPEX) {
		opex (&op->opex, handle, insn);
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		if (analop_esil (as, op, &handle, insn) != 0) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		op_fillval (as, op, &handle, insn);
	}
	cs_free (insn, n);
	return opsize;
}

static char *get_reg_profile(RArchSession * as) {
	const char *p = NULL;
	switch (as->config->bits) {
	default:
	case 32: p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=BP    fp\n"
		"=SN    v0\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=R0    v0\n"
		"=R1    v1\n"
		"gpr	zero	.32	?	0\n"
		"gpr	at	.32	4	0\n"
		"gpr	v0	.32	8	0\n"
		"gpr	v1	.32	12	0\n"
		"gpr	a0	.32	16	0\n"
		"gpr	a1	.32	20	0\n"
		"gpr	a2	.32	24	0\n"
		"gpr	a3	.32	28	0\n"
		"gpr	t0	.32	32	0\n"
		"gpr	t1	.32	36	0\n"
		"gpr	t2 	.32	40	0\n"
		"gpr	t3 	.32	44	0\n"
		"gpr	t4 	.32	48	0\n"
		"gpr	t5 	.32	52	0\n"
		"gpr	t6 	.32	56	0\n"
		"gpr	t7 	.32	60	0\n"
		"gpr	s0	.32	64	0\n"
		"gpr	s1	.32	68	0\n"
		"gpr	s2	.32	72	0\n"
		"gpr	s3	.32	76	0\n"
		"gpr	s4 	.32	80	0\n"
		"gpr	s5 	.32	84	0\n"
		"gpr	s6 	.32	88	0\n"
		"gpr	s7 	.32	92	0\n"
		"gpr	t8 	.32	96	0\n"
		"gpr	t9 	.32	100	0\n"
		"gpr	k0 	.32	104	0\n"
		"gpr	k1 	.32	108	0\n"
		"gpr	gp 	.32	112	0\n"
		"gpr	sp	.32	116	0\n"
		"gpr	fp	.32	120	0\n"
		"gpr	ra	.32	124	0\n"
		"gpr	pc	.32	128	0\n"
		"gpr	hi	.32	132	0\n"
		"gpr	lo	.32	136	0\n"
		"gpr	t	.32	140	0\n";
		break;
	case 64: p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=BP    fp\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=SN    v0\n"
		"=R0    v0\n"
		"=R1    v1\n"
		"gpr	zero	.64	?	0\n"
		"gpr	at	.64	8	0\n"
		"gpr	v0	.64	16	0\n"
		"gpr	v1	.64	24	0\n"
		"gpr	a0	.64	32	0\n"
		"gpr	a1	.64	40	0\n"
		"gpr	a2	.64	48	0\n"
		"gpr	a3	.64	56	0\n"
		"gpr	t0	.64	64	0\n"
		"gpr	t1	.64	72	0\n"
		"gpr	t2 	.64	80	0\n"
		"gpr	t3 	.64	88	0\n"
		"gpr	t4 	.64	96	0\n"
		"gpr	t5 	.64	104	0\n"
		"gpr	t6 	.64	112	0\n"
		"gpr	t7 	.64	120	0\n"
		"gpr	s0	.64	128	0\n"
		"gpr	s1	.64	136	0\n"
		"gpr	s2	.64	144	0\n"
		"gpr	s3	.64	152	0\n"
		"gpr	s4 	.64	160	0\n"
		"gpr	s5 	.64	168	0\n"
		"gpr	s6 	.64	176	0\n"
		"gpr	s7 	.64	184	0\n"
		"gpr	t8 	.64	192	0\n"
		"gpr	t9 	.64	200	0\n"
		"gpr	k0 	.64	208	0\n"
		"gpr	k1 	.64	216	0\n"
		"gpr	gp 	.64	224	0\n"
		"gpr	sp	.64	232	0\n"
		"gpr	fp	.64	240	0\n"
		"gpr	ra	.64	248	0\n"
		"gpr	pc	.64	256	0\n"
		"gpr	hi	.64	264	0\n"
		"gpr	lo	.64	272	0\n"
		"gpr	t	.64	280	0\n";
		break;
	}
	return p? strdup (p): NULL;
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_CODE_ALIGN || q == R_ARCH_INFO_MINOP_SIZE) {
		const char *cpu = as->config->cpu;
		if (cpu && !strcmp (cpu, "micro")) {
			return 2; // (anal->bits == 16) ? 2: 4;
		}
	}
	return 4;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static RList *preludes(RArchSession *as) {
	RList *l = r_list_newf (free);
	r_list_append (l, strdup ("27bd0000 ffffff00"));
	return l;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8 buf[4] = {0};
	int ret = mips_assemble (op->mnemonic, op->addr, buf);
	if (ret < 1) {
		return false;
	}
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)) {
		ut8 tmp = buf[0];
		buf[0] = buf[3];
		buf[3] = tmp;
		tmp = buf[1];
		buf[1] = buf[2];
		buf[2] = tmp;
	}
	free (op->bytes);
	op->bytes = r_mem_dup (buf, 4);
	op->size = 4;
	return true;
}

const RArchPlugin r_arch_plugin_mips_cs = {
	.meta = {
		.name = "mips",
		.author = "pancake",
		.desc = "Capstone MIPS analyzer",
		.license = "Apache-2.0",
	},
	.arch = "mips",
	.cpus = "mips32/64,micro,r6,v3,v2",
	.regs = get_reg_profile,
	.info = archinfo,
	.preludes = preludes,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.init = init,
	.fini = fini,
	.decode = decode,
	.encode = encode,
	.mnemonics = mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_mips_cs,
	.version = R2_VERSION
};
#endif
