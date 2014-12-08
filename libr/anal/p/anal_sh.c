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

//Macros for different instruction types

#define IS_RTE(x)			x == 0x002b
#define IS_RTS(x)			x == 0x000b
#define IS_BSRF(x)			(x & 0xf0ff) == 0x0003
#define IS_BRAF(x)			(((x) & 0xf0ff) == 0x0023)
#define IS_MOVB_REG_TO_R0REL(x)		(((x) & 0xF00F) == 0x0004)
#define IS_MOVW_REG_TO_R0REL(x)		(((x) & 0xF00F) == 0x0005)
#define IS_MOVL_REG_TO_R0REL(x)		(((x) & 0xF00F) == 0x0006)
#define IS_MOVB_R0REL_TO_REG(x)		(((x) & 0xF00F) == 0x000C)
#define IS_MOVW_R0REL_TO_REG(x)		(((x) & 0xF00F) == 0x000D)
#define IS_MOVL_R0REL_TO_REG(x)		(((x) & 0xF00F) == 0x000E)

#define IS_MOVB_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2000)
#define IS_MOVW_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2001)
#define IS_MOVL_REG_TO_REGREF(x)	(((x) & 0xF00F) == 0x2002)
#define IS_PUSHB(x)			(((x) & 0xF00F) == 0x2004)
#define IS_PUSHW(x)			(((x) & 0xF00F) == 0x2005)
#define IS_PUSHL(x)			(((x) & 0xF00F) == 0x2006)
#define IS_AND_REGS(x)			(((x) & 0xF00F) == 0x2009)
#define IS_XOR_REGS(x)			(((x) & 0xF00F) == 0x200A)
#define IS_OR_REGS(x)			(((x) & 0xF00F) == 0x200B)

#define IS_ADD(x)			(((x) & 0xF00F) == 0x300C)
#define IS_ADDC(x)			(((x) & 0xF00F) == 0x300E)
#define IS_ADDV(x)			(((x) & 0xF00F) == 0x300F)
#define IS_SUB(x)			(((x) & 0xF00F) == 0x3008)
#define IS_SUBC(x)			(((x) & 0xF00F) == 0x300A)
#define IS_SUBV(x)			(((x) & 0xF00F) == 0x300B)

#define IS_JSR(x)			(((x) & 0xf0ff) == 0x400b)
#define IS_JMP(x)			(((x) & 0xf0ff) == 0x402b)

#define IS_MOV_REGS(x)			(((x) & 0xf00f) == 0x6003)
#define IS_MOVB_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6000)
#define IS_MOVW_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6001)
#define IS_MOVL_REGREF_TO_REG(x)	(((x) & 0xF00F) == 0x6002)


#define IS_BF(x)			(((x) & 0xff00) == 0x8B00)
#define IS_BFS(x)			(((x) & 0xff00) == 0x8F00)
#define IS_BT(x)			(((x) & 0xff00) == 0x8900)
#define IS_BTS(x)			(((x) & 0xff00) == 0x8D00)
#define IS_BT_OR_BF(x)			IS_BT(x)||IS_BTS(x)||IS_BF(x)||IS_BFS(x)
#define IS_MOVB_REGDISP_R0(x)		(((x) & 0xFF00) == 0x8400)
#define IS_MOVW_REGDISP_R0(x)		(((x) & 0xFF00) == 0x8500)

#define IS_TRAP(x)			(((x) & 0xFF00) == 0xC300)
#define IS_MOVA_PCREL_R0(x)		(((x) & 0xFF00) == 0xC700)
#define IS_AND_IMM_R0(x)		(((x) & 0xFF00) == 0xC900)
#define IS_XOR_IMM_R0(x)		(((x) & 0xFF00) == 0xCA00)
#define IS_OR_IMM_R0(x)			(((x) & 0xFF00) == 0xCB00)

/* Compute PC-relative displacement for branch instructions */
#define GET_BRA_OFFSET(x)	((x) & 0x0fff)
#define GET_BTF_OFFSET(x)	((x) & 0x00ff)

/* Compute reg nr for BRAF,BSR,BSRF,JMP,JSR */
#define GET_TARGET_REG(x)	((x >> 8) & 0x0f)
#define GET_SOURCE_REG(x)	((x >> 4) & 0x0f)

#define PC_IDX 16

static ut64 disarm_12bit_offset (RAnalOp *op, unsigned int insoff) {
	ut64 off = insoff;
	/* sign extend if higher bit is 1 (0x0800) */
	if ((off & 0x0800) == 0x0800)
		off |= ~0xFFF;
	return (op->addr<<1) + off + 4;
}

#if unused
static ut64 disarm_8bit_offset (unsigned int pc, unsigned int insoff) {
	ut64 add = insoff;
	/* sign extend if higher bit is 1 (0x08) */
	if ((add & 0x80) == 0x80)
		add |= 0x00;
	return (add<<1) + pc + 4; //2*sign_extend(displacement) + 4
}
#endif
static char *regs[]={"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","pc"};

static RAnalValue *anal_fill_ai_rg(RAnal *anal, int idx) {
        RAnalValue *ret = r_anal_value_new ();
        ret->reg = r_reg_get (anal->reg,regs[idx],R_REG_TYPE_GPR);
        return ret;
}

static RAnalValue *anal_fill_im(RAnal *anal, st32 v) {
        RAnalValue *ret = r_anal_value_new ();
        ret->imm = v;
        return ret;
}

/* Implements @(disp,Rn) , size=1 for .b, 2 for .w, 4 for .l */
static RAnalValue *anal_fill_reg_disp_mem(RAnal *anal, int reg, st64 delta, st64 size) {
	RAnalValue *ret = anal_fill_ai_rg(anal,reg);
	ret->memref = size;
	ret->delta = delta*size;
	return ret;
}

static RAnalValue *anal_fill_reg_ref(RAnal *anal, int reg, st64 size){
	RAnalValue *ret = anal_fill_ai_rg(anal,reg);
	ret->memref = size;
	return ret;
}

/* @(R0,Rx) references for all sizes */
static RAnalValue *anal_fill_r0_reg_ref(RAnal *anal, int reg,st64 size){
	RAnalValue *ret = anal_fill_ai_rg(anal,0);
	ret->regdelta = r_reg_get(anal->reg,regs[reg],R_REG_TYPE_GPR);
	ret->memref = size;
	return ret;
}

#if unused
static st32 sign_extend_12b(st32 v){
	if( v & 0x800 ){
		v |= 0xFFFFF000;
	}
	return v;
}
#endif

static RAnalValue *anal_pcrel_disp_mov(RAnal* anal,RAnalOp* op,st8 disp){
	RAnalValue *ret = r_anal_value_new ();
	ret->base = op->addr;
	ret->delta = (op->addr & 0x02)?WORD_SIZE:LONG_SIZE;
	ret->delta = ret->delta + disp*LONG_SIZE;
	return ret;
}

static RAnalValue *anal_regrel_jump(RAnal* anal,RAnalOp* op, ut8 reg){
	RAnalValue *ret = r_anal_value_new ();
	ret->reg = r_reg_get(anal->reg,regs[reg],R_REG_TYPE_GPR);
	ret->delta = op->addr+4;
	return ret;
}



/* 16 decoder routines, based on 1st nibble value */
static int first_nibble_is_0(RAnal* anal, RAnalOp* op, ut16 code){
	if(IS_BSRF(code)){
		/* Call 'far' subroutine Rn+PC+4 */
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->delay = 1;
		op->dst = anal_regrel_jump(anal,op,GET_TARGET_REG(code));
	} else if (IS_BRAF(code)){
		/* Unconditional branch to Rn+PC+4, no delay slot */
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->dst = anal_regrel_jump(anal,op,GET_TARGET_REG(code));
		op->eob = R_TRUE;
	} else if( IS_RTS(code) ){
		/* Ret from subroutine. Returns to pr */
		//TODO Convert into jump pr?
		op->type = R_ANAL_OP_TYPE_RET;
		op->delay = 1;
		op->eob = R_TRUE;
	} else if (IS_RTE(code)){
		//TODO Convert into jmp spc? Indicate ssr->sr as well?
		op->type = R_ANAL_OP_TYPE_RET;
		op->delay = 1;
		op->eob = R_TRUE;
	} else if (IS_MOVB_REG_TO_R0REL(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_r0_reg_ref(anal,GET_TARGET_REG(code),BYTE_SIZE);
	} else if (IS_MOVW_REG_TO_R0REL(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_r0_reg_ref(anal,GET_TARGET_REG(code),WORD_SIZE);
	} else if (IS_MOVL_REG_TO_R0REL(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_r0_reg_ref(anal,GET_TARGET_REG(code),LONG_SIZE);
	} else if (IS_MOVB_R0REL_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_r0_reg_ref(anal,GET_SOURCE_REG(code),BYTE_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_MOVW_R0REL_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_r0_reg_ref(anal,GET_SOURCE_REG(code),WORD_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_MOVL_R0REL_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_r0_reg_ref(anal,GET_SOURCE_REG(code),LONG_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} 

	//TODO Check missing insns, specially STC might be interesting 
	return op->size;
}

static int movl_reg_rdisp(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_MOV;
	op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
	op->dst = anal_fill_reg_disp_mem(anal,GET_TARGET_REG(code),code&0x0F,LONG_SIZE);
	return op->size;
}



static int first_nibble_is_2(RAnal* anal, RAnalOp* op, ut16 code){
	//TODO handle mov.x Rm, @Rn, (X)OR/AND regs, 
	if (IS_MOVB_REG_TO_REGREF(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_reg_ref(anal,GET_TARGET_REG(code),BYTE_SIZE);
	} else if (IS_MOVW_REG_TO_REGREF(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_reg_ref(anal,GET_TARGET_REG(code),WORD_SIZE);
	} else if (IS_MOVL_REG_TO_REGREF(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_reg_ref(anal,GET_TARGET_REG(code),LONG_SIZE);
	} else if (IS_AND_REGS(code)){
		op->type = R_ANAL_OP_TYPE_AND;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_XOR_REGS(code)){
		op->type = R_ANAL_OP_TYPE_XOR;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_OR_REGS(code)){
		op->type = R_ANAL_OP_TYPE_OR;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	}
	//TODO Handle 'pushes' (mov Rm,@-Rn)
	//TODO Handle CMP/STR ?? 
	return op->size;
}


static int first_nibble_is_3(RAnal* anal, RAnalOp* op, ut16 code){
	//TODO Handle carry/overflow , CMP/xx?
	if( IS_ADD(code) || IS_ADDC(code) || IS_ADDV(code) ){
		op->type = R_ANAL_OP_TYPE_ADD;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if ( IS_SUB(code) || IS_SUBC(code) || IS_SUBV(code)){
		op->type = R_ANAL_OP_TYPE_SUB;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	}
	return op->size;
}

static int first_nibble_is_4(RAnal* anal, RAnalOp* op, ut16 code){
	if(IS_JSR(code)){
		op->type = R_ANAL_OP_TYPE_UCALL; //call to reg 
		op->delay = 1;
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if ( IS_JMP(code) ){
		op->type = R_ANAL_OP_TYPE_UJMP; //jmp to reg 
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
		op->delay = 1;
		op->eob = R_TRUE;
	}
	//TODO shifts + many system insns + CMP/P[L|Z]??
	return op->size;
}

static int movl_rdisp_reg(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_MOV;
	op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	op->src[0] = anal_fill_reg_disp_mem(anal,GET_SOURCE_REG(code),code&0x0F,LONG_SIZE);
	return op->size;
}


static int first_nibble_is_6(RAnal* anal, RAnalOp* op, ut16 code){
	if(IS_MOV_REGS(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_ai_rg(anal,GET_SOURCE_REG(code));
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_MOVB_REGREF_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_reg_ref(anal,GET_SOURCE_REG(code),BYTE_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_MOVW_REGREF_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_reg_ref(anal,GET_SOURCE_REG(code),WORD_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	} else if (IS_MOVL_REGREF_TO_REG(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_fill_reg_ref(anal,GET_SOURCE_REG(code),LONG_SIZE);
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	}
	//TODO neg(c) + MOV.L @Rm+,Rn 
	return op->size;
}


static int add_imm(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_ADD;
	op->src[0] = anal_fill_im(anal, (st8)(code&0xFF)); //Casting to (st8) forces sign-extension.
	op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	return op->size;
}

static int first_nibble_is_8(RAnal* anal, RAnalOp* op, ut16 code){
	if (IS_BT_OR_BF(code)){
		op->type = R_ANAL_OP_TYPE_CJMP; //Jump if true or jump if false insns
		op->jump = (op->addr << 1) +4 + (st8)GET_BTF_OFFSET(code);
		op->fail = op->addr + 2 ;
		op->eob  = R_TRUE;
		if (IS_BTS(code) || IS_BFS(code))
			op->delay = 1; //Only /S versions have a delay slot
	} else if (IS_MOVB_REGDISP_R0(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
		op->src[0] = anal_fill_reg_disp_mem(anal,GET_SOURCE_REG(code),code&0x0F,BYTE_SIZE);
	} else if (IS_MOVW_REGDISP_R0(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
		op->src[0] = anal_fill_reg_disp_mem(anal,GET_SOURCE_REG(code),code&0x0F,WORD_SIZE);
	}
	//TODO some movs + CMP/EQ??
	return op->size;
}

static int movw_pcdisp_reg(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_MOV;
	op->dst = anal_fill_ai_rg(anal, GET_TARGET_REG(code));
	op->src[0] = anal_fill_reg_disp_mem(anal,PC_IDX,code&0xFF,WORD_SIZE);
	return op->size;
}

static int bra(RAnal* anal, RAnalOp* op, ut16 code){
	/* Unconditional branch, relative to PC */
	op->type = R_ANAL_OP_TYPE_JMP;
	op->delay = 1;
	op->jump = disarm_12bit_offset(op,GET_BRA_OFFSET(code));
	op->eob  = R_TRUE;
	return op->size;
}

static int bsr(RAnal* anal, RAnalOp* op, ut16 code){
	/* Subroutine call, relative to PC */
	op->type = R_ANAL_OP_TYPE_CALL;
	op->jump = disarm_12bit_offset(op,GET_BRA_OFFSET(code));
	op->delay = 1;
	return op->size;
}


static int first_nibble_is_c(RAnal* anal, RAnalOp* op, ut16 code){
	if (IS_TRAP(code)){
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = (ut8)(code&0xFF);
	} else if (IS_MOVA_PCREL_R0(code)){
		op->type = R_ANAL_OP_TYPE_MOV;
		op->src[0] = anal_pcrel_disp_mov(anal,op,code&0xFF);
		op->dst = anal_fill_ai_rg(anal,0); //Always R0
	} else if (IS_AND_IMM_R0(code)){
		op->type = R_ANAL_OP_TYPE_AND;
		op->src[0] = anal_fill_im(anal,code&0xFF);
		op->dst = anal_fill_ai_rg(anal,0); //Always R0
	} else if (IS_OR_IMM_R0(code)){
		op->type = R_ANAL_OP_TYPE_OR;
		op->src[0] = anal_fill_im(anal,code&0xFF);
		op->dst = anal_fill_ai_rg(anal,0); //Always R0
	} else if (IS_XOR_IMM_R0(code)){
		op->type = R_ANAL_OP_TYPE_XOR;
		op->src[0] = anal_fill_im(anal,code&0xFF);
		op->dst = anal_fill_ai_rg(anal,0); //Always R0
	}
	//TODO Logic insns referencing GBR
	return op->size;
}

static int movl_pcdisp_reg(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_MOV;
	op->src[0] = anal_pcrel_disp_mov(anal,op,code&0x0F);
	op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code));
	return op->size;
}

static int mov_imm_reg(RAnal* anal, RAnalOp* op, ut16 code){
	op->type = R_ANAL_OP_TYPE_MOV;
	op->dst = anal_fill_ai_rg(anal,GET_TARGET_REG(code)); 
	op->src[0] = anal_fill_im(anal,(st8)(code & 0xFF));
	return op->size;
}

static int fpu_insn(RAnal* anal, RAnalOp* op, ut16 code){
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
static int sh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_MSB,op_LSB;
	int ret;
	if (data == NULL)
		return 0;
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	op->size = 2;

	op_MSB = (anal->big_endian)? data[0]:data[1];
	op_LSB = (anal->big_endian)? data[1]:data[0];
	ret =  first_nibble_decode[(op_MSB>>4) & 0x0F](anal, op, (ut16)(op_MSB<<16 | op_LSB));
	return ret;
}

/* Set the profile register */
static int sh_set_reg_profile(RAnal* anal){
	//TODO Add system ( ssr, spc ) + fpu regs 
	const char *p = "=pc    pc\n"
		"=sp    r15\n"
		"=bp    r14\n"
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
		"gpr	mach	.32	80	0\n"
		"gpr	macl	.32	84	0\n";
	return r_reg_set_profile_string(anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_sh = {
	.name = "sh",
	.desc = "SH-4 code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_SH,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &sh_op,
	.set_reg_profile = &sh_set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sh
};
#endif
