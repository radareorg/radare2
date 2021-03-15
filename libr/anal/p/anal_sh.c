/* radare - LGPL - Copyright 2010-2013 eloi<limited-entropy.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define API static

#define LONG_SIZE 4
#define WORD_SIZE 2
#define BYTE_SIZE 1

/*
 * all processor instructions are implemented, but all FPU are missing
 * DIV1,MAC.W,MAC.L,rte,rts should be checked
 * also tests are written, but still could be some issues, if I misunderstand instructions.
 * If you found some bugs, please open an issue
*/

#define BIT_32(x)	x",0x80000000,&"
#define S16_EXT(x)	x",DUP,0x8000,&,?{,0xFFFFFFFFFFFF0000,|,}"
#define S32_EXT(x)	x",DUP,0x80000000,&,?{,0xFFFFFFFF00000000,|,}"
#define IS_T	"sr,0x1,&,"
#define SET_T	"0x1,sr,|="
#define CLR_T	"0xFFFFFFFE,sr,&="
//Macros for different instruction types

#define IS_CLRT(x)	x == 0x0008
#define IS_NOP(x)	x == 0x0009
#define IS_RTS(x)	x == 0x000b
#define IS_SETT(x)	x == 0x0018
#define IS_DIV0U(x)	x == 0x0019
#define IS_SLEEP(x)	x == 0x001b
#define IS_CLRMAC(x)	x == 0x0028
#define IS_RTE(x)	x == 0x002b

#define IS_STCSR1(x)	(((x) & 0xF0CF) == 0x0002)	//mask stc Rn,{SR,gbr,VBR,SSR}
#define IS_BSRF(x)	((x) & 0xf0ff) == 0x0003
#define IS_BRAF(x)	(((x) & 0xf0ff) == 0x0023)
#define IS_MOVB_REG_TO_R0REL(x)	(((x) & 0xF00F) == 0x0004)
#define IS_MOVW_REG_TO_R0REL(x)	(((x) & 0xF00F) == 0x0005)
#define IS_MOVL_REG_TO_R0REL(x)	(((x) & 0xF00F) == 0x0006)
#define IS_MULL(x)	(((x) & 0xF00F) == 0x0007)
#define IS_MOVB_R0REL_TO_REG(x)	(((x) & 0xF00F) == 0x000C)
#define IS_MOVW_R0REL_TO_REG(x)	(((x) & 0xF00F) == 0x000D)
#define IS_MOVL_R0REL_TO_REG(x)	(((x) & 0xF00F) == 0x000E)
#define IS_MACL(x)	(((x) & 0xF00F) == 0x000F)
#define IS_MOVT(x)	(((x) & 0xF0FF) == 0x0029)
#define IS_STSMACH(x)	(((x) & 0xF0FF) == 0x000A)
#define IS_STSMACL(x)	(((x) & 0xF0FF) == 0x001A)
#define IS_STSPR(x)	(((x) & 0xF0FF) == 0x002A)
//#define IS_STSFPUL(x)	(((x) & 0xF0FF) == 0x005A)	//FP*: todo maybe someday
//#define IS_STSFPSCR(x)	(((x) & 0xF0FF) == 0x006A)
#define IS_MOVB_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2000)
#define IS_MOVW_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2001)
#define IS_MOVL_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2002)
//#define invalid?(x)	(((x) & 0xF00F) == 0x2003)	//illegal on sh2e
#define IS_PUSHB(x)	(((x) & 0xF00F) == 0x2004)
#define IS_PUSHW(x)	(((x) & 0xF00F) == 0x2005)
#define IS_PUSHL(x)	(((x) & 0xF00F) == 0x2006)
#define IS_DIV0S(x)	(((x) & 0xF00F) == 0x2007)
#define IS_TSTRR(x)	(((x) & 0xF00F) == 0x2008)
#define IS_AND_REGS(x)	(((x) & 0xF00F) == 0x2009)
#define IS_XOR_REGS(x)	(((x) & 0xF00F) == 0x200A)
#define IS_OR_REGS(x)	(((x) & 0xF00F) == 0x200B)
#define IS_CMPSTR(x)	(((x) & 0xF00F) == 0x200C)
#define IS_XTRCT(x)	(((x) & 0xF00F) == 0x200D)
#define IS_MULUW(x)	(((x) & 0xF00F) == 0x200E)
#define IS_MULSW(x)	(((x) & 0xF00F) == 0x200F)
#define IS_CMPEQ(x)	(((x) & 0xF00F) == 0x3000)
//#define invalid?(x)	(((x) & 0xF00F) == 0x3001)
#define IS_CMPHS(x)	(((x) & 0xF00F) == 0x3002)
#define IS_CMPGE(x)	(((x) & 0xF00F) == 0x3003)
#define IS_CMPHI(x)	(((x) & 0xF00F) == 0x3006)
#define IS_CMPGT(x)	(((x) & 0xF00F) == 0x3007)
#define IS_DIV1(x)	(((x) & 0xF00F) == 0x3004)
#define IS_DMULU(x)	(((x) & 0xF00F) == 0x3005)
#define IS_DMULS(x)	(((x) & 0xF00F) == 0x300D)
#define IS_SUB(x)	(((x) & 0xF00F) == 0x3008)
//#define invalid?(x)	(((x) & 0xF00F) == 0x3009)
#define IS_SUBC(x)	(((x) & 0xF00F) == 0x300A)
#define IS_SUBV(x)	(((x) & 0xF00F) == 0x300B)
#define IS_ADD(x)	(((x) & 0xF00F) == 0x300C)
#define IS_ADDC(x)	(((x) & 0xF00F) == 0x300E)
#define IS_ADDV(x)	(((x) & 0xF00F) == 0x300F)
#define IS_MACW(x)	(((x) & 0xF00F) == 0x400F)
#define IS_JSR(x)	(((x) & 0xf0ff) == 0x400b)
#define IS_JMP(x)	(((x) & 0xf0ff) == 0x402b)
#define IS_CMPPL(x)	(((x) & 0xf0ff) == 0x4015)
#define IS_CMPPZ(x)	(((x) & 0xf0ff) == 0x4011)
#define IS_LDCSR(x) 	(((x) & 0xF0FF) == 0x400E)
#define IS_LDCGBR(x)	 	(((x) & 0xF0FF) == 0x401E)
#define IS_LDCVBR(x)	(((x) & 0xF0FF) == 0x402E)
#define IS_LDCLSR(x)	(((x) & 0xF0FF) == 0x4007)
#define IS_LDCLSRGBR(x)	(((x) & 0xF0FF) == 0x4017)
#define IS_LDCLSRVBR(x)	(((x) & 0xF0FF) == 0x4027)
#define IS_LDSMACH(x)	(((x) & 0xF0FF) == 0x400A)
#define IS_LDSMACL(x)	(((x) & 0xF0FF) == 0x401A)
#define IS_LDSLMACH(x)	(((x) & 0xF0FF) == 0x4006)
#define IS_LDSLMACL(x)	(((x) & 0xF0FF) == 0x4016)
#define IS_LDSPR(x)	(((x) & 0xF0FF) == 0x402A)
#define IS_LDSLPR(x)	(((x) & 0xF0FF) == 0x4026)
//#define IS_LDSFPUL(x)	(((x) & 0xF0FF) == 0x405A)	//FP*: todo maybe someday
//#define IS_LDSFPSCR(x)	(((x) & 0xF0FF) == 0x406A)
//#define IS_LDSLFPUL(x)	(((x) & 0xF0FF) == 0x4066)
//#define IS_LDSLFPSCR(x)	(((x) & 0xF0FF) == 0x4056)
#define IS_ROTCR(x)	(((x) & 0xF0FF) == 0x4025)
#define IS_ROTCL(x)	(((x) & 0xF0FF) == 0x4024)
#define IS_ROTL(x)	(((x) & 0xF0FF) == 0x4004)
#define IS_ROTR(x)	(((x) & 0xF0FF) == 0x4005)
//not on sh2e : shad, shld

//#define IS_SHIFT1(x)	(((x) & 0xF0DE) == 0x4000)	//unused (treated as switch-case)
//other shl{l,r}{,2,8,16} in switch case also.

#define IS_STSLMACL(x)	(((x) & 0xF0FF) == 0x4012)
#define IS_STSLMACH(x)	(((x) & 0xF0FF) == 0x4002)
#define IS_STCLSR(x)	(((x) & 0xF0FF) == 0x4003)
#define IS_STCLGBR(x)	(((x) & 0xF0FF) == 0x4013)
#define IS_STCLVBR(x)	(((x) & 0xF0FF) == 0x4023)
//todo: other stc.l not on sh2e
#define IS_STSLPR(x)	(((x) & 0xF0FF) == 0x4022)
//#define IS_STSLFPUL(x)	(((x) & 0xF0FF) == 0x4052)
//#define IS_STSLFPSCR(x)	(((x) & 0xF0FF) == 0x4062)
#define IS_TASB(x)	(((x) & 0xF0FF) == 0x401B)
#define IS_DT(x)	(((x) & 0xF0FF) == 0x4010)


#define IS_MOVB_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6000)
#define IS_MOVW_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6001)
#define IS_MOVL_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6002)
#define IS_MOV_REGS(x)	(((x) & 0xf00f) == 0x6003)
#define IS_MOVB_POP(x)	(((x) & 0xF00F) == 0x6004)
#define IS_MOVW_POP(x)	(((x) & 0xF00F) == 0x6005)
#define IS_MOVL_POP(x)	(((x) & 0xF00F) == 0x6006)
#define IS_NOT(x)	(((x) & 0xF00F) == 0x6007)
#define IS_SWAPB(x)	(((x) & 0xF00F) == 0x6008)
#define IS_SWAPW(x)	(((x) & 0xF00F) == 0x6009)
#define IS_NEG(x)	(((x) & 0xF00F) == 0x600B)
#define IS_NEGC(x)	(((x) & 0xF00F) == 0x600A)
#define IS_EXT(x)	(((x) & 0xF00C) == 0x600C)	//match ext{s,u}.{b,w}


#define IS_MOVB_R0_REGDISP(x)	(((x) & 0xFF00) == 0x8000)
#define IS_MOVW_R0_REGDISP(x)	(((x) & 0xFF00) == 0x8100)
//#define illegal?(x)	(((x) & 0xF900) == 0x8000)	//match 8{2,3,6,7}00
#define IS_MOVB_REGDISP_R0(x)	(((x) & 0xFF00) == 0x8400)
#define IS_MOVW_REGDISP_R0(x)	(((x) & 0xFF00) == 0x8500)
#define IS_CMPIMM(x)	(((x) & 0xFF00) == 0x8800)
//#define illegal?(x)	(((x) & 0xFB00) == 0x8A00)	//match 8{A,E}00
#define IS_BT(x)	(((x) & 0xff00) == 0x8900)
#define IS_BF(x)	(((x) & 0xff00) == 0x8B00)
#define IS_BTS(x)	(((x) & 0xff00) == 0x8D00)
#define IS_BFS(x)	(((x) & 0xff00) == 0x8F00)
#define IS_BT_OR_BF(x)	IS_BT(x)||IS_BTS(x)||IS_BF(x)||IS_BFS(x)

#define IS_MOVB_R0_GBRREF(x)	(((x) & 0xFF00) == 0xC000)
#define IS_MOVW_R0_GBRREF(x)	(((x) & 0xFF00) == 0xC100)
#define IS_MOVL_R0_GBRREF(x)	(((x) & 0xFF00) == 0xC200)
#define IS_TRAP(x)	(((x) & 0xFF00) == 0xC300)
#define IS_MOVB_GBRREF_R0(x)	(((x) & 0xFF00) == 0xC400)
#define IS_MOVW_GBRREF_R0(x)	(((x) & 0xFF00) == 0xC500)
#define IS_MOVL_GBRREF_R0(x)	(((x) & 0xFF00) == 0xC600)
#define IS_MOVA_PCREL_R0(x)	(((x) & 0xFF00) == 0xC700)
#define IS_BINLOGIC_IMM_R0(x)	(((x) & 0xFC00) == 0xC800)	//match C{8,9,A,B}00
#define IS_BINLOGIC_IMM_GBR(x)	(((x) & 0xFC00) == 0xCC00)	//match C{C,D,E,F}00 : *.b #imm, @(R0,gbr)


/* Compute PC-relative displacement for branch instructions */
#define GET_BRA_OFFSET(x)	((x) & 0x0fff)
#define GET_BTF_OFFSET(x)	((x) & 0x00ff)

/* Compute reg nr for BRAF,BSR,BSRF,JMP,JSR */
#define GET_TARGET_REG(x)	(((x) >> 8) & 0x0f)
#define GET_SOURCE_REG(x)	(((x) >> 4) & 0x0f)

/* index of PC reg in regs[] array*/
#define PC_IDX 16

/* for {bra,bsr} only: (sign-extend 12bit offset)<<1 + PC +4 */
static ut64 disarm_12bit_offset (RAnalOp *op, unsigned int insoff) {
	ut64 off = insoff;
	/* sign extend if higher bit is 1 (0x0800) */
	if ((off & 0x0800) == 0x0800)
	{
		off |= ~0xFFF;
	}
	return (op->addr) + (off << 1) + 4;
}

/* for bt,bf sign-extended offsets : return PC+4+ (exts.b offset)<<1 */
static ut64 disarm_8bit_offset (ut64 pc, ut32 offs) {
		/* pc (really, op->addr) is 64 bits, so we need to sign-extend
		 * to 64 bits instead of the 32 the actual CPU does */
		ut64 off = offs;
	/* sign extend if higher bit is 1 (0x08) */
	if ((off & 0x80) == 0x80)
	{
		off |= ~0xFF;
	}
	return (off << 1) + pc + 4;
}

static char *regs[]={"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","pc"};

static RAnalValue *anal_fill_ai_rg(RAnal *anal, int idx) {
	RAnalValue *ret = r_anal_value_new ();
	ret->reg = r_reg_get (anal->reg, regs[idx], R_REG_TYPE_GPR);
	return ret;
}

static RAnalValue *anal_fill_im(RAnal *anal, st32 v) {
	RAnalValue *ret = r_anal_value_new ();
	ret->imm = v;
	return ret;
}

/* Implements @(disp,Rn) , size=1 for .b, 2 for .w, 4 for .l */
static RAnalValue *anal_fill_reg_disp_mem(RAnal *anal, int reg, st64 delta, st64 size) {
	RAnalValue *ret = anal_fill_ai_rg (anal, reg);
	ret->memref = size;
	ret->delta = delta*size;
	return ret;
}

/* Rn */
static RAnalValue *anal_fill_reg_ref(RAnal *anal, int reg, st64 size) {
	RAnalValue *ret = anal_fill_ai_rg (anal, reg);
	ret->memref = size;
	return ret;
}

/* @(R0,Rx) references for all sizes */
static RAnalValue *anal_fill_r0_reg_ref(RAnal *anal, int reg, st64 size) {
	RAnalValue *ret = anal_fill_ai_rg (anal, 0);
	ret->regdelta = r_reg_get (anal->reg, regs[reg], R_REG_TYPE_GPR);
	ret->memref = size;
	return ret;
}

// @(disp,PC) for size=2(.w), size=4(.l). disp is 0-extended
static RAnalValue *anal_pcrel_disp_mov(RAnal* anal, RAnalOp* op, ut8 disp, int size) {
	RAnalValue *ret = r_anal_value_new ();
	if (size==2) {
		ret->base = op->addr + 4;
		ret->delta = disp << 1;
	} else {
		ret->base = (op->addr + 4) & ~0x03;
		ret->delta = disp << 2;
	}

	return ret;
}

//= PC+4+R<reg>
static RAnalValue *anal_regrel_jump(RAnal* anal, RAnalOp* op, ut8 reg) {
	RAnalValue *ret = r_anal_value_new ();
	ret->reg = r_reg_get (anal->reg, regs[reg], R_REG_TYPE_GPR);
	ret->base = op->addr + 4;
	return ret;
}

/* 16 decoder routines, based on 1st nibble value */
static int first_nibble_is_0(RAnal* anal, RAnalOp* op, ut16 code) { //STOP
	if (IS_BSRF (code)) {
		/* Call 'far' subroutine Rn+PC+4 */
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->delay = 1;
		op->dst = anal_regrel_jump (anal, op, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "1,SETD,pc,2,+,pr,=,r%d,2,+,pc,+=", GET_TARGET_REG (code));
	} else if (IS_BRAF (code)) {
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->dst = anal_regrel_jump (anal, op, GET_TARGET_REG (code));
		op->eob = true;
		op->delay = 1;
		r_strbuf_setf (&op->esil, "1,SETD,r%d,2,+,pc,+=", GET_TARGET_REG (code));
	} else if (IS_RTS (code)) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->delay = 1;
		op->eob = true;
		r_strbuf_setf (&op->esil, "pr,pc,=");
	} else if (IS_RTE (code)) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->delay = 1;
		op->eob = true;
		//r_strbuf_setf (&op->esil, "1,SETD,r15,[4],4,+,pc,=,r15,4,+,[4],0xFFF0FFF,&,sr,=,8,r15,+=");
		//not sure if should be added 4 to pc
		r_strbuf_setf (&op->esil, "1,SETD,r15,[4],pc,=,r15,4,+,[4],0xFFF0FFF,&,sr,=,8,r15,+=");
	} else if (IS_MOVB_REG_TO_R0REL (code)) {	//0000nnnnmmmm0100 mov.b <REG_M>,@(R0,<REG_N>)
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_r0_reg_ref (anal, GET_TARGET_REG (code), BYTE_SIZE);
		r_strbuf_setf (&op->esil, "r%d,0xFF,&,r0,r%d,+,=[1]", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVW_REG_TO_R0REL (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_r0_reg_ref (anal, GET_TARGET_REG (code), WORD_SIZE);
		r_strbuf_setf (&op->esil, "r%d,0xFFFF,&,r0,r%d,+,=[2]", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVL_REG_TO_R0REL (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_r0_reg_ref(anal, GET_TARGET_REG (code), LONG_SIZE);
		r_strbuf_setf (&op->esil, "r%d,r0,r%d,+,=[4]", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVB_R0REL_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_r0_reg_ref (anal, GET_SOURCE_REG (code), BYTE_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r0,r%d,+,[1],r%d,=,0x000000FF,r%d,&=,r%d,0x80,&,?{,0xFFFFFF00,r%d,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVW_R0REL_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_r0_reg_ref (anal, GET_SOURCE_REG (code), WORD_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r0,r%d,+,[2],r%d,=,0x0000FFFF,r%d,&=,r%d,0x8000,&,?{,0xFFFF0000,r%d,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVL_R0REL_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_r0_reg_ref (anal, GET_SOURCE_REG (code), LONG_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r0,r%d,+,[4],r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_NOP (code)) {
		op->type = R_ANAL_OP_TYPE_NOP;
		r_strbuf_setf (&op->esil, " ");
	} else if (IS_CLRT (code)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=");
	} else if (IS_SETT (code)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "0x1,sr,|=");
	} else if (IS_CLRMAC (code)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "0,mach,=,0,macl,=");
	} else if (IS_DIV0U (code)) {
		op->type = R_ANAL_OP_TYPE_DIV;
		r_strbuf_setf (&op->esil, "0xFFFFFCFE,sr,&=");
	} else if (IS_MOVT (code)) {
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "0x1,sr,&,r%d,=", GET_TARGET_REG (code));
	} else if (IS_MULL (code)) { //multiply long
		op->type = R_ANAL_OP_TYPE_MUL;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,*,macl,=", GET_TARGET_REG (code), GET_SOURCE_REG (code));
	} else if (IS_SLEEP (code)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "sleep_called,TRAP");
	} else if (IS_STSMACH (code)) {	//0000nnnn0000101_ sts MAC*,<REG_N>
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "mach,r%d,=", GET_TARGET_REG (code));
	} else if (IS_STSMACL (code)) {	//0000nnnn0000101_ sts MAC*,<REG_N>
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "macl,r%d,=", GET_TARGET_REG (code));
	} else if (IS_STSLMACL (code)) {
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "macl,r%d,=", GET_TARGET_REG (code));
	} else if (IS_STCSR1 (code)) {	//0000nnnn00010010 stc {sr,gbr,vbr,ssr},<REG_N>
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		//todo: plug in src
		switch(GET_SOURCE_REG (code)) {
		case 0:
			r_strbuf_setf (&op->esil, "sr,r%d,=", GET_TARGET_REG (code));
			break;
		case 1:
			r_strbuf_setf (&op->esil, "gbr,r%d,=", GET_TARGET_REG (code));
			break;
		case 2:
			r_strbuf_setf (&op->esil, "vbr,r%d,=", GET_TARGET_REG (code));
			break;
		default:
			r_strbuf_setf (&op->esil, "%s", "");
			break;

		}
	} else if (IS_STSPR (code)) {	//0000nnnn00101010 sts PR,<REG_N>
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "pr,r%d,=", GET_TARGET_REG (code));
	} else if (IS_MACL (code)) {
		r_strbuf_setf (&op->esil,
			"mach,0x80000000,&,!," //mach_old sign (0)
			S32_EXT("r%d,[4]")"," //@Rn sign extended
			S32_EXT("r%d,[4]")"," //@Rm sign extended
			"*," //(1)
			"macl,32,mach,<<,|," //macl | (mach << 32)
			"+," //MAC+@Rm*@Rn
			"32,"
			S32_EXT("r%d,[4]")"," //@Rn sign extended
			S32_EXT("r%d,[4]")"," //@Rm sign extended
			"*,"
			"4,r%d,+=," //Rn+=4
			"4,r%d,+=," //Rm+=4
			"0xffffffff00000000,&,>>,mach,=," //MACH > mach
			"0xffffffff,&,macl,=,"
			"0x2,sr,&,!,?{,BREAK,}," //if S==0 BREAK
			"0x00007fff,mach,>,"
			"0x80000000,mach,&,!,&,"
			"?{,0x00007fff,mach,=,0xffffffff,macl,=,}," //if (mach>0x00007fff&&mach>0) mac=0x00007fffffffffff
			"0xffff8000,mach,<,"
			"0x80000000,mach,&,!,!,&,"
			"?{,0xffff8000,mach,=,0x0,macl,=,}," //if (mach>0xffff8000&&mach<0) mac=0xffff800000000000
			, GET_TARGET_REG (code), GET_SOURCE_REG (code),
			GET_TARGET_REG (code), GET_SOURCE_REG (code),
			GET_TARGET_REG (code), GET_SOURCE_REG (code));
		op->type = R_ANAL_OP_TYPE_MUL;
	}
	return op->size;
}

//nibble=1; 0001nnnnmmmmi4*4 mov.l <REG_M>,@(<disp>,<REG_N>)
static int movl_reg_rdisp(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_STORE;
	op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
	op->dst = anal_fill_reg_disp_mem (anal, GET_TARGET_REG (code), code & 0x0F, LONG_SIZE);
	r_strbuf_setf (&op->esil, "r%d,r%d,0x%x,+,=[4]", GET_SOURCE_REG (code), GET_TARGET_REG (code), (code & 0xF) << 2);
	return op->size;
}

static int first_nibble_is_2(RAnal* anal, RAnalOp* op, ut16 code) {
	if (IS_MOVB_REG_TO_REGREF (code)) {	// 0010nnnnmmmm0000 mov.b <REG_M>,@<REG_N>
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_reg_ref (anal, GET_TARGET_REG (code), BYTE_SIZE);
		r_strbuf_setf (&op->esil, "r%d,r%d,=[1]", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVW_REG_TO_REGREF (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_reg_ref (anal, GET_TARGET_REG (code), WORD_SIZE);
		r_strbuf_setf (&op->esil, "r%d,r%d,=[2]", GET_SOURCE_REG (code) & 0xFF, GET_TARGET_REG (code));
	} else if (IS_MOVL_REG_TO_REGREF (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_reg_ref (anal, GET_TARGET_REG (code), LONG_SIZE);
		r_strbuf_setf (&op->esil, "r%d,r%d,=[4]", GET_SOURCE_REG (code) & 0xFF, GET_TARGET_REG (code));
	} else if (IS_AND_REGS (code)) {
		op->type = R_ANAL_OP_TYPE_AND;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,&=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_XOR_REGS (code)) {
		op->type = R_ANAL_OP_TYPE_XOR;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,^=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_OR_REGS (code)) {
		op->type = R_ANAL_OP_TYPE_OR;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,|=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_PUSHB (code)) {
		op->type = R_ANAL_OP_TYPE_PUSH;
		r_strbuf_setf (&op->esil, "1,r%d,-=,r%d,r%d,=[1]", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_PUSHW (code)) {
		op->type = R_ANAL_OP_TYPE_PUSH;
		r_strbuf_setf (&op->esil, "2,r%d,-=,r%d,r%d,=[2]", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_PUSHL (code)) {
		op->type = R_ANAL_OP_TYPE_PUSH;
		r_strbuf_setf (&op->esil, "4,r%d,-=,r%d,r%d,=[4]", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_TSTRR (code)) {
		op->type = R_ANAL_OP_TYPE_ACMP;
		r_strbuf_setf (&op->esil, "1,sr,|=,r%d,r%d,&,?{,0xFFFFFFFE,sr,&=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_CMPSTR (code)) {	//0010nnnnmmmm1100 cmp/str <REG_M>,<REG_N>
		op->type = R_ANAL_OP_TYPE_ACMP;	//maybe not?
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,24,r%d,r%d,^,>>,0xFF,&,!,?{,1,sr,|=,},16,r%d,r%d,^,>>,0xFF,&,!,?{,1,sr,|=,},8,r%d,r%d,^,>>,0xFF,&,!,?{,1,sr,|=,},r%d,r%d,^,0xFF,&,!,?{,1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_XTRCT (code)) {	//0010nnnnmmmm1101 xtrct <REG_M>,<REG_N>
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "16,r%d,0xFFFF,&,<<,16,r%d,0xFFFF0000,&,>>,|,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_DIV0S (code)) {
		op->type = R_ANAL_OP_TYPE_DIV;
		r_strbuf_setf (&op->esil, "0xFFFFFCFE,sr,&=,r%d,0x80000000,&,?{,0x200,sr,|=,},r%d,0x80000000,&,?{,0x100,sr,|=,},sr,1,sr,<<,^,0x200,&,?{,1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MULUW (code)) {
		op->type = R_ANAL_OP_TYPE_MUL;
		op->src[0] = anal_fill_ai_rg(anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg(anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,0xFFFF,&,r%d,0xFFFF,&,*,macl,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MULSW (code)) {	//0010nnnnmmmm111_ mul{s,u}.w <REG_M>,<REG_N>
		op->type = R_ANAL_OP_TYPE_MUL;
		op->src[0] = anal_fill_ai_rg(anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg(anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, S16_EXT("r%d") "," S16_EXT("r%d") ",*,macl,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	}

	return op->size;
}


static int first_nibble_is_3(RAnal* anal, RAnalOp* op, ut16 code) {
	//TODO Handle carry/overflow , CMP/xx?
	if (IS_ADD (code)) {
		op->type = R_ANAL_OP_TYPE_ADD;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,+=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_ADDC (code)) {
		op->type = R_ANAL_OP_TYPE_ADD;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "sr,0x1,&,0xFFFFFFFE,sr,&=,r%d,+=,31,$c,sr,|,sr,:=,r%d,r%d,+=,31,$c,sr,|,sr,:=", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_ADDV (code)) {
		op->type = R_ANAL_OP_TYPE_ADD;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,r%d,+=,31,$o,sr,|=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_SUB (code)) {
		op->type = R_ANAL_OP_TYPE_SUB;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,-=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_SUBC (code)) {
		op->type = R_ANAL_OP_TYPE_SUB;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "sr,1,&," CLR_T ",r%d,-=,31,$b,sr,|,sr,:=,r%d,r%d,-=,31,$b,sr,|,sr,:=", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_SUBV (code)) {
		op->type = R_ANAL_OP_TYPE_SUB;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, CLR_T ",r%d,r%d,-=,31,$o,sr,|,sr,:=", GET_SOURCE_REG(code), GET_TARGET_REG (code));
	} else if (IS_CMPEQ (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&,r%d,r%d,^,!,|,sr,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_CMPGE (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,r%d,>=,?{,0x1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_CMPGT (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,r%d,>,?{,0x1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_CMPHI (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x100000000,+,r%d,0x100000000,+,>,?{,0x1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_CMPHS (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x100000000,+,r%d,0x100000000,+,>=,?{,0x1,sr,|=,}", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_DIV1 (code)) {
		op->type = R_ANAL_OP_TYPE_DIV;
		op->src[0] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		r_strbuf_setf (&op->esil,
			"1,sr,>>,sr,^,0x80,&," //old_Q^M
			"0xFFFFFF7F,sr,&=,"
			"1,r%d,DUP,0x80000000,&,?{,0x80,sr,|=,},<<,sr,0x1,&,|,r%d,=," //shift Q<-Rn<-T
			"DUP,!,!,?{,"
			"r%d,NUM,"//Rn_old (before subtract)
			"r%d,r%d,+=,"
			"r%d,<,}{," //tmp0
			"r%d,NUM,"//Rn_old (before subtract)
			"r%d,r%d,-=,"
			"r%d,>,}," //tmp0
			"sr,0x80,&,!,!,^," //Q^tmp0
			"sr,0x100,&,?{,!,},"//if (M) !(Q^tmp0)
			"0xFFFFFF7F,sr,&=," //Q==0
			"?{,0x80,sr,|=,}," //Q=!(Q^tmp0)or(Q^tmp0)
			CLR_T","
			"1,sr,>>,sr,^,0x80,&,!,sr,|=", // sr=!Q^M
			GET_TARGET_REG (code), GET_TARGET_REG (code),
			GET_TARGET_REG (code),
			GET_SOURCE_REG(code), GET_TARGET_REG (code),
			GET_TARGET_REG (code),
			GET_TARGET_REG (code),
			GET_SOURCE_REG(code), GET_TARGET_REG (code),
			GET_TARGET_REG (code));
	} else if (IS_DMULU (code)) {
		op->type = R_ANAL_OP_TYPE_MUL;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "32,r%d,r%d,*,DUP,0xFFFFFFFF,&,macl,=,>>,mach,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_DMULS (code)) {
		op->type = R_ANAL_OP_TYPE_MUL;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->src[1] = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "32,r%d,r%d,0x80000000,&,?{,0xFFFFFFFF00000000,+,},r%d,r%d,0x80000000,&,?{,0xFFFFFFFF00000000,+,},*,DUP,0xFFFFFFFF,&,macl,=,>>,mach,=", GET_SOURCE_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	}
	return op->size;
}



static int first_nibble_is_4(RAnal* anal, RAnalOp* op, ut16 code) {
	switch(code & 0xF0FF) { //TODO: change to common } else if construction
	case 0x4020:	//shal
		op->type = R_ANAL_OP_TYPE_SAL;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x80000000,&,?{,0x1,sr,|=,},1,r%d,<<=", GET_TARGET_REG (code), GET_TARGET_REG (code));
		break;
	case 0x4021:	//shar
		op->type = R_ANAL_OP_TYPE_SAR;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x1,&,?{,0x1,sr,|=,},0,r%d,0x80000000,&,?{,0x80000000,+,},1,r%d,>>=,r%d,|=", GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
		break;
	case 0x4000:	//shll
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x80000000,&,?{,0x1,sr,|=,},1,r%d,<<=", GET_TARGET_REG (code), GET_TARGET_REG (code));
		break;
	case 0x4008:	//shll2
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_setf (&op->esil, "2,r%d,<<=", GET_TARGET_REG (code));
		break;
	case 0x4018:	//shll8
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_setf (&op->esil, "8,r%d,<<=", GET_TARGET_REG (code));
		break;
	case 0x4028:	//shll16
		op->type = R_ANAL_OP_TYPE_SHL;
		r_strbuf_setf (&op->esil, "16,r%d,<<=", GET_TARGET_REG (code));
		break;
	case 0x4001:	//shlr
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x1,&,?{,0x1,sr,|=,},1,r%d,>>=", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x4009:	//shlr2
		r_strbuf_setf (&op->esil, "2,r%d,>>=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x4019:	//shlr8
		r_strbuf_setf (&op->esil, "8,r%d,>>=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x4029:	//shlr16
		r_strbuf_setf (&op->esil, "16,r%d,>>=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	default:
		break;
	}

	if (IS_JSR (code)) {
		// op->type = R_ANAL_OP_TYPE_UCALL; //call to reg
		op->type = R_ANAL_OP_TYPE_RCALL; //call to reg
		op->delay = 1;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "1,SETD,pc,2,+,pr,=,r%d,pc,=", GET_TARGET_REG (code));
	} else if (IS_JMP (code)) {
		op->type = R_ANAL_OP_TYPE_UJMP; //jmp to reg
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		op->delay = 1;
		op->eob = true;
		r_strbuf_setf (&op->esil, "1,SETD,r%d,pc,=", GET_TARGET_REG (code));
	} else if (IS_CMPPL (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,0,r%d,>,?{,0x1,sr,|=,}", GET_TARGET_REG (code));
	} else if (IS_CMPPZ (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,0,r%d,>=,?{,0x1,sr,|=,}", GET_TARGET_REG (code));
	} else if (IS_LDCLSR (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],0x0FFF0FFF,&,sr,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_LDCLSRGBR (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],gbr,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_LDCLSRVBR (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],vbr,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
		//todo ssr?
	} else if (IS_LDSLMACH (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],mach,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_LDSLMACL (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],macl,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_LDSLPR (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		r_strbuf_setf (&op->esil, "r%d,[4],pr,=,4,r%d,+=", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_LDCSR (code)) {
		r_strbuf_setf (&op->esil, "r%d,0x0FFF0FFF,&,sr,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_LDCGBR (code)) {
		r_strbuf_setf (&op->esil, "r%d,gbr,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_LDCVBR (code)) {
		r_strbuf_setf (&op->esil, "r%d,vbr,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_LDSMACH (code)) {
		r_strbuf_setf (&op->esil, "r%d,mach,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_LDSMACL (code)) {
		r_strbuf_setf (&op->esil, "r%d,macl,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_LDSPR (code)) {
		r_strbuf_setf (&op->esil, "r%d,pr,=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (IS_ROTR (code)) {
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,0x1,&,sr,|=,0x1,r%d,>>>,r%d,=", GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = (code & 1)? R_ANAL_OP_TYPE_ROR:R_ANAL_OP_TYPE_ROL;
	} else if (IS_ROTL (code)) {
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,0x1,r%d,<<<,r%d,=,r%d,0x1,&,sr,|=", GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = (code & 1)? R_ANAL_OP_TYPE_ROR:R_ANAL_OP_TYPE_ROL;
	} else if (IS_ROTCR (code)) {
		r_strbuf_setf (&op->esil, "0,sr,0x1,&,?{,0x80000000,},0xFFFFFFFE,sr,&=,r%d,1,&,sr,|=,1,r%d,>>=,r%d,|=", GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = (code & 1)? R_ANAL_OP_TYPE_ROR:R_ANAL_OP_TYPE_ROL;
	} else if (IS_ROTCL (code)) {
		r_strbuf_setf (&op->esil, "sr,0x1,&,0xFFFFFFFE,sr,&=,r%d,0x80000000,&,?{,1,sr,|=,},1,r%d,<<=,r%d,|=", GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = (code & 1)? R_ANAL_OP_TYPE_ROR:R_ANAL_OP_TYPE_ROL;
	} else if (IS_STCLSR (code)) {
		r_strbuf_setf (&op->esil, "4,r%d,-=,sr,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (IS_STCLGBR (code)) {
		r_strbuf_setf (&op->esil, "4,r%d,-=,gbr,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (IS_STCLVBR (code)) {
		r_strbuf_setf (&op->esil, "4,r%d,-=,vbr,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (IS_STSLMACL (code)) {
		r_strbuf_setf (&op->esil, "4,r%d,-=,macl,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (IS_STSLMACH (code)) {
		r_strbuf_setf (&op->esil, "4,r%d,-=,mach,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (IS_STSLPR (code)) {
		op->type = R_ANAL_OP_TYPE_PUSH;
		r_strbuf_setf (&op->esil, "4,r%d,-=,pr,r%d,=[4]", GET_TARGET_REG (code), GET_TARGET_REG (code));
	} else if (IS_TASB (code)) {
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r%d,[1],!,?{,0x80,r%d,=[1],1,sr,|=,}", GET_TARGET_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_UNK;
	} else if (IS_DT (code)) {
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,1,r%d,-=,$z,sr,|,sr,:=", GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_UNK;
	} else if (IS_MACW(code)){
		r_strbuf_setf (&op->esil,
			"0x2,sr,&,!,?{," //if S==0
				S16_EXT("r%d,[2]")"," //@Rn sign extended
				S16_EXT("r%d,[2]")"," //@Rm sign extended
				"*,"
				"macl,32,mach,<<,|," //macl | (mach << 32)
				"+," //MAC+@Rm*@Rn
				"32,"
				S16_EXT("r%d,[2]")"," //@Rn sign extended
				S16_EXT("r%d,[2]")"," //@Rm sign extended
				"*,"
				"0xffffffff00000000,&,>>,mach,=," //MACH > mach
				"0xffffffff,&,macl,=,"
			"}{," //if S==1
				S16_EXT("r%d,[2]")"," //@Rn sign extended
				S16_EXT("r%d,[2]")"," //@Rm sign extended
				"*"
				"macl,+=," //macl+(@Rm+@Rm)
				"31,$o,?{," //if overflow
					"macl,0x80000000,&,?{,"
						"0x7fffffff,macl,=,"
					"}{,"
						"0x80000000,macl,=,"
					"},"
				"},"
			"},"
			"2,r%d,+=," //Rn+=2
			"2,r%d,+=,", //Rm+=2
			GET_TARGET_REG (code), GET_SOURCE_REG (code),
			GET_TARGET_REG (code), GET_SOURCE_REG (code),
			GET_TARGET_REG (code), GET_SOURCE_REG (code),
			GET_TARGET_REG (code), GET_SOURCE_REG (code));
		op->type = R_ANAL_OP_TYPE_MUL;
	}
	return op->size;
}

//nibble=5; 0101nnnnmmmmi4*4 mov.l @(<disp>,<REG_M>),<REG_N>
static int movl_rdisp_reg(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	op->src[0] = anal_fill_reg_disp_mem (anal, GET_SOURCE_REG (code), code & 0x0F, LONG_SIZE);
	r_strbuf_setf (&op->esil, "r%d,0x%x,+,[4],r%d,=", GET_SOURCE_REG (code), (code&0xF) * 4, GET_TARGET_REG (code));
	return op->size;
}


static int first_nibble_is_6(RAnal* anal, RAnalOp* op, ut16 code) {
	if (IS_MOV_REGS (code)) {
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVB_REGREF_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_reg_ref (anal, GET_SOURCE_REG (code), BYTE_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "0x000000FF,r%d,&=,r%d,[1],DUP,0x80,&,?{,0xFFFFFF00,|=,},r%d,=", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVW_REGREF_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_reg_ref (anal, GET_SOURCE_REG (code), WORD_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "0x0000FFFF,r%d,&=,r%d,[2],DUP,0x8000,&,?{,0xFFFF0000,|=,},r%d,=", GET_TARGET_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_MOVL_REGREF_TO_REG (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->src[0] = anal_fill_reg_ref (anal, GET_SOURCE_REG (code), LONG_SIZE);
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,[4],r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
	} else if (IS_EXT (code)) {
		//ext{s,u}.{b,w} instructs. todo : more detail ?
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		switch(code & 0xF) {
		case 0xC: //EXTU.B
			r_strbuf_setf (&op->esil, "r%d,0xFF,&,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
			break;
		case 0xD: //EXTU.W
			r_strbuf_setf (&op->esil, "r%d,0xFFFF,&,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
			break;
		case 0xE: //EXTS.B
			r_strbuf_setf (&op->esil, "r%d,0xFF,&,DUP,0x80,&,?{,0xFFFFFF00,|,},r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
			break;
		case 0xF: //EXTS.W
			r_strbuf_setf (&op->esil, "r%d,0xFFFF,&,DUP,0x8000,&,?{,0xFFFF0000,|,},r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
			break;
		default:
			r_strbuf_setf (&op->esil, "TODO,NOT IMPLEMENTED");
			break;
		}
	} else if (IS_MOVB_POP (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,[1],DUP,0x80,&,?{,0xFFFFFF00,|,},r%d,=,1,r%d,+=", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code));
	} else if (IS_MOVW_POP (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,[2],DUP,0x8000,&,?{,0xFFFF0000,|,},r%d,=,2,r%d,+=", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code));
	} else if (IS_MOVL_POP (code)) {
		op->type = R_ANAL_OP_TYPE_POP;
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
		r_strbuf_setf (&op->esil, "r%d,[4],r%d,=,4,r%d,+=", GET_SOURCE_REG (code), GET_TARGET_REG (code), GET_SOURCE_REG (code));
	} else if (IS_NEG (code)) {
		//todo: neg and negc details
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "r%d,0,-,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	} else if (IS_NEGC (code)) {
		op->type = R_ANAL_OP_TYPE_UNK;
		r_strbuf_setf (&op->esil, "1,sr,&,0xFFFFFFFE,sr,&=,r%d,+,0,-,31,$b,sr,|,sr,=,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	} else if (IS_NOT (code)) {
		//todo : details?
		r_strbuf_setf (&op->esil, "0xFFFFFFFF,r%d,^,r%d,=", GET_SOURCE_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_NOT;
		op->src[0] = anal_fill_ai_rg (anal, GET_SOURCE_REG (code));
		op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	} else if (IS_SWAPB (code)) {
		r_strbuf_setf (&op->esil, "r%d,0xFFFF0000,&,8,r%d,0xFF,&,<<,|,8,r%d,0xFF00,&,>>,|,r%d,=", GET_SOURCE_REG (code), GET_SOURCE_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
		//todo : details
	} else if (IS_SWAPW (code)) {
		r_strbuf_setf (&op->esil, "16,r%d,0xFFFF,&,<<,16,r%d,0xFFFF0000,&,>>,|,r%d,=", GET_SOURCE_REG (code), GET_SOURCE_REG (code), GET_TARGET_REG (code));
		op->type = R_ANAL_OP_TYPE_MOV;
	}
	return op->size;
}


//nibble=7; 0111nnnni8*1.... add #<imm>,<REG_N>
static int add_imm(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_ADD;
	op->src[0] = anal_fill_im (anal, (st8)(code & 0xFF)); //Casting to (st8) forces sign-extension.
	op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	r_strbuf_setf (&op->esil, "0x%x,DUP,0x80,&,?{,0xFFFFFF00,|,},r%d,+=", code & 0xFF, GET_TARGET_REG (code));
	return op->size;
}

static int first_nibble_is_8(RAnal* anal, RAnalOp* op, ut16 code) {
	if (IS_BT_OR_BF (code)) {
		op->type = R_ANAL_OP_TYPE_CJMP; //Jump if true or jump if false insns
		op->jump = disarm_8bit_offset (op->addr, GET_BTF_OFFSET (code));
		op->fail = op->addr + 2 ;
		op->eob = true;
		if (IS_BT (code)) {
			r_strbuf_setf (&op->esil, "sr,1,&,?{,0x%" PFMT64x ",pc,=,}", op->jump);
		} else if (IS_BTS (code)) {
			r_strbuf_setf (&op->esil, "1,SETD,sr,1,&,?{,0x%" PFMT64x ",pc,=,}", op->jump);
			op->delay = 1; //Only /S versions have a delay slot
		} else if (IS_BFS (code)) {
			r_strbuf_setf (&op->esil, "1,SETD,sr,1,&,!,?{,0x%" PFMT64x ",pc,=,}",op->jump);
			op->delay = 1; //Only /S versions have a delay slot
		} else if (IS_BF (code)) {
			r_strbuf_setf (&op->esil, "sr,1,&,!,?{,0x%" PFMT64x ",pc,=,}", op->jump);
		}
	} else if (IS_MOVB_REGDISP_R0 (code)) {
		// 10000100mmmmi4*1 mov.b @(<disp>,<REG_M>),R0
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = anal_fill_ai_rg (anal, 0);
		op->src[0] = anal_fill_reg_disp_mem (anal, GET_SOURCE_REG (code), code & 0x0F, BYTE_SIZE);
		r_strbuf_setf (&op->esil, "r%d,0x%x,+,[1],DUP,0x80,&,?{,0xFFFFFF00,|,},r0,=", GET_SOURCE_REG (code), code & 0xF);
	} else if (IS_MOVW_REGDISP_R0 (code)) {
		// 10000101mmmmi4*2 mov.w @(<disp>,<REG_M>),R0
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = anal_fill_ai_rg (anal, 0);
		op->src[0] = anal_fill_reg_disp_mem (anal, GET_SOURCE_REG (code), code & 0x0F, WORD_SIZE);
		r_strbuf_setf (&op->esil, "r%d,0x%x,+,[2],DUP,0x8000,&,?{,0xFFFF0000,|,},r0,=", GET_SOURCE_REG (code), (code & 0xF) * 2);
	} else if (IS_CMPIMM (code)) {
		op->type = R_ANAL_OP_TYPE_CMP;
		r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,0x%x,DUP,0x80,&,?{,0xFFFFFF00,|,},r0,==,$z,sr,|,sr,:=", code & 0xFF);
	} else if (IS_MOVB_R0_REGDISP (code)) {
		/* 10000000mmmmi4*1 mov.b R0,@(<disp>,<REG_M>)*/
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, 0);
		op->dst = anal_fill_reg_disp_mem (anal, GET_SOURCE_REG (code), code & 0x0F, BYTE_SIZE);
		r_strbuf_setf (&op->esil, "r0,0xFF,&,0x%x,r%d,+,=[1]", code & 0xF, GET_SOURCE_REG (code));
	} else if (IS_MOVW_R0_REGDISP (code)) {
		// 10000001mmmmi4*2 mov.w R0,@(<disp>,<REG_M>))
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, 0);
		op->dst = anal_fill_reg_disp_mem (anal, GET_SOURCE_REG (code), code & 0x0F, WORD_SIZE);
		r_strbuf_setf (&op->esil, "r0,0xFFFF,&,0x%x,r%d,+,=[2]", (code & 0xF) * 2, GET_SOURCE_REG (code));
	}
	return op->size;
}

//nibble=9; 1001nnnni8p2.... mov.w @(<disp>,PC),<REG_N>
static int movw_pcdisp_reg(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	op->src[0] = r_anal_value_new ();
	op->src[0]->base = (code & 0xFF) * 2+op->addr + 4;
	op->src[0]->memref=1;
	r_strbuf_setf (&op->esil, "0x%" PFMT64x ",[2],r%d,=,r%d,0x8000,&,?{,0xFFFF0000,r%d,|=,}", op->src[0]->base, GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	return op->size;
}

//nibble=A; 1010i12......... bra <bdisp12>
static int bra(RAnal* anal, RAnalOp* op, ut16 code) {
	/* Unconditional branch, relative to PC */
	op->type = R_ANAL_OP_TYPE_JMP;
	op->delay = 1;
	op->jump = disarm_12bit_offset (op, GET_BRA_OFFSET (code));
	op->eob = true;
	r_strbuf_setf (&op->esil, "1,SETD,0x%" PFMT64x ",pc,=", op->jump);
	return op->size;
}

//nibble=B; 1011i12......... bsr <bdisp12>
static int bsr(RAnal* anal, RAnalOp* op, ut16 code) {
	/* Subroutine call, relative to PC */
	op->type = R_ANAL_OP_TYPE_CALL;
	op->jump = disarm_12bit_offset (op, GET_BRA_OFFSET (code));
	op->delay = 1;
	r_strbuf_setf (&op->esil, "1,SETD,pc,2,+,pr,=,0x%" PFMT64x ",pc,=", op->jump);
	return op->size;
}

static int first_nibble_is_c(RAnal* anal, RAnalOp* op, ut16 code) {
	if (IS_TRAP (code)) {
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = (ut8)(code & 0xFF);
		r_strbuf_setf (&op->esil, "4,r15,-=,sr,r15,=[4],4,r15,-=,2,pc,-,r15,=[4],2,0x%x,<<,4,+,vbr,+,pc,=", code & 0xFF);
	} else if (IS_MOVA_PCREL_R0 (code)) {
		// 11000111i8p4.... mova @(<disp>,PC),R0
		op->type = R_ANAL_OP_TYPE_LEA;
		op->src[0] = anal_pcrel_disp_mov (anal, op, code & 0xFF, LONG_SIZE);	//this is wrong !
		op->dst = anal_fill_ai_rg (anal, 0); //Always R0
		r_strbuf_setf (&op->esil, "0x%x,pc,+,r0,=", (code & 0xFF) * 4);
	} else if (IS_BINLOGIC_IMM_R0 (code)) {	// 110010__i8 (binop) #imm, R0
		op->src[0] = anal_fill_im (anal, code & 0xFF);
		op->src[1] = anal_fill_ai_rg (anal, 0);	//Always R0
		op->dst = anal_fill_ai_rg (anal, 0); //Always R0 except tst #imm, R0
		switch(code & 0xFF00) {
		case 0xC800:	//tst
			//TODO : get correct op->dst ! (T flag)
			op->type = R_ANAL_OP_TYPE_ACMP;
			r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r0,0x%x,&,!,?{,1,sr,|=,}", code & 0xFF);
			break;
		case 0xC900:	//and
			op->type = R_ANAL_OP_TYPE_AND;
			r_strbuf_setf (&op->esil, "0x%x,r0,&=", code & 0xFF);
			break;
		case 0xCA00:	//xor
			op->type = R_ANAL_OP_TYPE_XOR;
			r_strbuf_setf (&op->esil, "0x%x,r0,^=", code & 0xFF);
			break;
		case 0xCB00:	//or
			op->type = R_ANAL_OP_TYPE_OR;
			r_strbuf_setf (&op->esil, "0x%x,r0,|=", code & 0xFF);
			break;
		}
	} else if (IS_BINLOGIC_IMM_GBR (code)) {	//110011__i8 (binop).b #imm, @(R0,gbr)
		op->src[0] = anal_fill_im (anal, code & 0xFF);
		switch(code & 0xFF00) {
		case 0xCC00:	//tst
			//TODO : get correct op->dst ! (T flag)
			op->type = R_ANAL_OP_TYPE_ACMP;
			r_strbuf_setf (&op->esil, "0xFFFFFFFE,sr,&=,r0,gbr,+,[1],0x%x,&,!,?{,1,sr,|=,}", code & 0xFF);
			break;
		case 0xCD00:	//and
			op->type = R_ANAL_OP_TYPE_AND;
			r_strbuf_setf (&op->esil, "r0,gbr,+,[1],0x%x,&,r0,gbr,+,=[1]", code & 0xFF);
			break;
		case 0xCE00:	//xor
			op->type = R_ANAL_OP_TYPE_XOR;
			r_strbuf_setf (&op->esil, "r0,gbr,+,[1],0x%x,^,r0,gbr,+,=[1]", code & 0xFF);
			break;
		case 0xCF00:	//or
			op->type = R_ANAL_OP_TYPE_OR;
			r_strbuf_setf (&op->esil, "r0,gbr,+,[1],0x%x,|,r0,gbr,+,=[1]", code & 0xFF);
			break;
		}
		//TODO : implement @(R0,gbr) dest and src[1]
	} else if (IS_MOVB_R0_GBRREF (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "r0,gbr,0x%x,+,=[1]", code & 0xFF);
	} else if (IS_MOVW_R0_GBRREF (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "r0,gbr,0x%x,+,=[2]", (code & 0xFF) * 2);
	} else if (IS_MOVL_R0_GBRREF (code)) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->src[0] = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "r0,gbr,0x%x,+,=[4]", (code & 0xFF) * 4);
	} else if (IS_MOVB_GBRREF_R0 (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "gbr,0x%x,+,[1],DUP,0x80,&,?{,0xFFFFFF00,|,},r0,=", (code & 0xFF));
	} else if (IS_MOVW_GBRREF_R0 (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "gbr,0x%x,+,[2],DUP,0x8000,&,?{,0xFFFF0000,|,},r0,=", (code & 0xFF)*2);
	} else if (IS_MOVL_GBRREF_R0 (code)) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->dst = anal_fill_ai_rg (anal, 0);
		r_strbuf_setf (&op->esil, "gbr,0x%x,+,[4],r0,=", (code & 0xFF) * 4);
	}

	return op->size;
}

//nibble=d; 1101nnnni8 : mov.l @(<disp>,PC), Rn
static int movl_pcdisp_reg(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	op->src[0] = anal_pcrel_disp_mov (anal, op, code & 0xFF, LONG_SIZE);
	//TODO: check it
	op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	//r_strbuf_setf (&op->esil, "0x%x,[4],r%d,=", (code & 0xFF) * 4 + (op->addr & 0xfffffff3) + 4, GET_TARGET_REG (code));
	r_strbuf_setf (&op->esil, "0x%" PFMT64x ",[4],r%d,=", (code & 0xFF) * 4 + ((op->addr >> 2)<<2) + 4, GET_TARGET_REG (code));
	return op->size;
}

//nibble=e; 1110nnnni8*1.... mov #<imm>,<REG_N>
static int mov_imm_reg(RAnal* anal, RAnalOp* op, ut16 code) {
	op->type = R_ANAL_OP_TYPE_MOV;
	op->dst = anal_fill_ai_rg (anal, GET_TARGET_REG (code));
	op->src[0] = anal_fill_im (anal, (st8)(code & 0xFF));
	r_strbuf_setf (&op->esil, "0x%x,r%d,=,r%d,0x80,&,?{,0xFFFFFF00,r%d,|=,}", code & 0xFF, GET_TARGET_REG (code), GET_TARGET_REG (code), GET_TARGET_REG (code));
	return op->size;
}

//nibble=f;
static int fpu_insn(RAnal* anal, RAnalOp* op, ut16 code) {
	//Not interested on FPU stuff for now
	op->family = R_ANAL_OP_FAMILY_FPU;
	return op->size;
}

/* Table of routines for further analysis based on 1st nibble */
static int (*first_nibble_decode[])(RAnal*,RAnalOp*,ut16) = {
	first_nibble_is_0,
	movl_reg_rdisp,
	first_nibble_is_2,
	first_nibble_is_3,
	first_nibble_is_4,
	movl_rdisp_reg,
	first_nibble_is_6,
	add_imm,
	first_nibble_is_8,
	movw_pcdisp_reg,
	bra,
	bsr,
	first_nibble_is_c,
	movl_pcdisp_reg,
	mov_imm_reg,
	fpu_insn
};


/* This is the basic operation analysis. Just initialize and jump to
 * routines defined in first_nibble_decode table
 */
static int sh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	ut8 op_MSB, op_LSB;
	int ret;
	if (!data || len < 2) {
		return 0;
	}
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	op->size = 2;

	op_MSB = anal->big_endian? data[0]: data[1];
	op_LSB = anal->big_endian? data[1]: data[0];
	ret = first_nibble_decode[(op_MSB>>4) & 0x0F](anal, op, (ut16)(op_MSB<<8 | op_LSB));

	return ret;
}

/* Set the profile register */
static bool sh_set_reg_profile(RAnal* anal) {
	//TODO Add system ( ssr, spc ) + fpu regs
	const char *p =
		"=PC	pc\n"
		"=SN	r0\n"
		"=SP	r15\n"
		"=BP	r14\n"
		"=A0	r4\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=R0	r0\n"
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
		"gpr	pc	.32	64	0\n"
		"gpr	pr	.32	68	0\n"
		"gpr	sr	.32	72	0\n"
		"gpr	gbr	.32	76	0\n"
		"gpr	vbr	.32	80	0\n"
		"gpr	mach	.32	84	0\n"
		"gpr	macl	.32	88	0\n";
	return r_reg_set_profile_string(anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
#if 0
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		return 4;
	}
#endif
	return 2; /* :) */
}


RAnalPlugin r_anal_plugin_sh = {
	.name = "sh",
	.desc = "SH-4 code analysis plugin",
	.license = "LGPL3",
	.arch = "sh",
	.archinfo = archinfo,
	.bits = 32,
	.op = &sh_op,
	.set_reg_profile = &sh_set_reg_profile,
	.esil = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sh,
	.version = R2_VERSION
};
#endif

