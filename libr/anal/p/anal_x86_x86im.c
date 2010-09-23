/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "x86/x86im/x86im.h"

static const char *gpr8[] = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
static const char *gpr8b[] = {
	"spl", "bpl", "sil", "dil" };
static const char *gpr16[] = {
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
static const char *gpr32[] = {
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
static const char *gpr64[] = {
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

static const char* anal_reg(ut32 rop) {
	const char **table;

	if (X86IM_IO_ROP_IS_GPR8 (rop))
		table = gpr8;
	else
	if (X86IM_IO_ROP_IS_GPR8B (rop))
		table = gpr8b;
	else
	if (X86IM_IO_ROP_IS_GPR16 (rop))
		table = gpr16;
	else
	if (X86IM_IO_ROP_IS_GPR32 (rop))
		table = gpr32;
	else
	if (X86IM_IO_ROP_IS_GPR64 (rop))
		table = gpr64;
	return table[X86IM_IO_ROP_GET_ID (rop)];
}

/* 0x0ff */
/* io.imm = rel 0x0ff */
static RAnalValue *anal_fill_r(RAnal *anal, x86im_instr_object io, ut64 addr) {
	RAnalValue *ret = r_anal_value_new ();
	st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	ret->base = addr + io.len + imm;
	return ret;
}

/* dword sel:0x0ff */
/* io.selector = sel; io.imm = 0x0ff */
static RAnalValue *anal_fill_f(RAnal *anal, x86im_instr_object io) {
	RAnalValue *ret = r_anal_value_new ();
	st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	ret->sel = io.selector;
	ret->delta = imm;
	return ret;
}

/* n */
/* io.imm = n */
static RAnalValue *anal_fill_im(RAnal *anal, x86im_instr_object io) {
	RAnalValue *ret = r_anal_value_new ();
	st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	ret->imm = imm;
	return ret;
}

/* reg */
/* io.rop[0] = reg */
static RAnalValue *anal_fill_ai_rg(RAnal *anal, x86im_instr_object io, int idx) {
	RAnalValue *ret = r_anal_value_new ();
	ret->reg = r_reg_get (anal->reg,
			anal_reg (io.rop[idx]), R_REG_TYPE_GPR);
	return ret;
}

/* [0x0ff | reg1+reg2+0x0ff] */
/* io.mem_base = reg1; io.mem_index = reg2; io.disp = 0x0ff */
static RAnalValue *anal_fill_ai_mm(RAnal *anal, x86im_instr_object io) {
	RAnalValue *ret = r_anal_value_new ();
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);
	if (io.mem_base == 0) {
		ret->memref = anal->bits/8;
		ret->base = disp;
	} else {
		ret->reg = r_reg_get (anal->reg,
				anal_reg (io.mem_base), R_REG_TYPE_GPR);
		ret->delta = disp;
		if (io.mem_index != 0)
			ret->regdelta = r_reg_get (anal->reg,
					anal_reg (io.mem_index), R_REG_TYPE_GPR);
	}
	return ret;
}

static void anal_jmp(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->eob = R_TRUE;
	switch (io.id) {
	case X86IM_IO_ID_JMP_N_R_S: /* jmp short 0x0ff */ 
	case X86IM_IO_ID_JMP_N_R:   /* jmp 0x0ff */
		aop->type = R_ANAL_OP_TYPE_JMP;
		aop->dst = anal_fill_r (anal, io, aop->addr);
		aop->jump = aop->addr + io.len + imm;
		break;
	case X86IM_IO_ID_JMP_N_AI_MM: /* jmp  [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_JMP_F_AI_MM: /* jmp dword far  [0x0ff | reg1+reg2+0x0ff] */
		aop->type = R_ANAL_OP_TYPE_UJMP;
		aop->dst = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0)
			aop->ref = disp;
		break;
	case X86IM_IO_ID_JMP_N_AI_RG: /* jmp reg */
		aop->type = R_ANAL_OP_TYPE_UJMP;
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		break;
	case X86IM_IO_ID_JMP_F_A: /* jmp dword sel:0x0ff */
		aop->type = R_ANAL_OP_TYPE_UJMP;
		aop->dst = anal_fill_f (anal, io);
		/* TODO: Deprecate */
		aop->selector = io.selector;
		aop->ref = imm;
		break;
	}
}

static void anal_cjmp(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);

	aop->eob = R_TRUE;
	switch (io.id) {
	case X86IM_IO_ID_JCC_S: /* j* 0x0ff */
	case X86IM_IO_ID_JCC_N: /* j* dword 0x0ff */ 
		aop->type = R_ANAL_OP_TYPE_CJMP;
		aop->dst = anal_fill_r (anal, io, aop->addr);
		aop->fail = aop->addr + io.len;
		aop->jump = aop->addr + io.len + imm;
		break;
	}
}

static void anal_call(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	switch (io.id) {
	case X86IM_IO_ID_CALL_N_R: /* call 0x0ff */
		aop->type = R_ANAL_OP_TYPE_CALL;
		aop->dst = anal_fill_r (anal, io, aop->addr);
		aop->jump = aop->addr + io.len + imm;
		aop->fail = aop->addr + io.len;
		break;
	case X86IM_IO_ID_CALL_N_AI_MM: /* call [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_CALL_F_AI_MM: /* call dword far [0x0ff | reg1+reg2+0x0ff] */
		aop->type = R_ANAL_OP_TYPE_UCALL;
		aop->dst = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0)
			aop->ref = disp;
		break;
	case X86IM_IO_ID_CALL_N_AI_RG: /* call reg */
		aop->type = R_ANAL_OP_TYPE_UCALL;
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->fail = aop->addr + io.len;
		break;
	case X86IM_IO_ID_CALL_F_A: /* call dword sel:0x0ff */
		aop->type = R_ANAL_OP_TYPE_UCALL;
		aop->dst = anal_fill_f (anal, io);
		/* TODO: Deprecate */
		aop->selector = io.selector;
		aop->ref = imm;
		aop->fail = aop->addr + io.len;
		break;
	}
}

static void anal_ret(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);

	aop->eob = R_TRUE;
	aop->type = R_ANAL_OP_TYPE_RET;
	switch (io.id) {
	case X86IM_IO_ID_RET_N: /* ret */
	case X86IM_IO_ID_RET_F: /* retf */
		aop->stackptr = anal->bits/8;
		break;
	case X86IM_IO_ID_RET_N_IM: /* ret n */
	case X86IM_IO_ID_RET_F_IM: /* retf n */
		aop->dst = anal_fill_im (anal, io);
		aop->stackptr = anal->bits/8 + imm;
		/* TODO: Deprecate */
		aop->value = imm;
		break;
	}
}

static void anal_hlt(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	aop->eob = R_TRUE;
	aop->type = R_ANAL_OP_TYPE_RET;
}

static void anal_mov(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->type = R_ANAL_OP_TYPE_MOV;
	switch (io.id) {
	case X86IM_IO_ID_MOV_MM_RG:  /* mov [0x0ff | reg1+reg2+0x0ff], reg */
	case X86IM_IO_ID_MOV_MM_AC:
		aop->src[0] = anal_fill_ai_mm (anal, io);
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* mov [0x0ff], reg */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov [ebp+0x0ff], reg */
			aop->stackop = R_ANAL_STACK_SET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_R2_R1: /* mov reg2, reg1 */
	case X86IM_IO_ID_MOV_R1_R2:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_MOV_RG_MM: /* mov reg, [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_MOV_AC_MM:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* mov reg, [0x0ff] */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov reg, [ebp+0x0ff] */
			aop->stackop = R_ANAL_STACK_GET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_MM_IM: /* mov [0x0ff | reg1+reg2+0x0ff], 0x1 */
		aop->dst = anal_fill_ai_mm (anal, io);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* [0x0ff], 0x1 */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov [ebp+0x0ff], 0x1 */
			aop->stackop = R_ANAL_STACK_SET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_RG_IM: /* mov reg, 0x1 */
	case X86IM_IO_ID_MOV_AC_IM:
		/* io.imm = 0x1 & io.rop[0] = reg */
		break;
	case X86IM_IO_ID_MOV_CR0_RG: /* mov cr0, reg */
	case X86IM_IO_ID_MOV_CR2_RG: /* mov cr2, reg */
	case X86IM_IO_ID_MOV_CR3_RG: /* mov cr3, reg */
	case X86IM_IO_ID_MOV_CR4_RG: /* mov cr4, reg */
	case X86IM_IO_ID_MOV_CRX_RG: /* mov cr*, reg */
		/* io.rop[0] = cr & io.rop[1] = reg */
		break;
	case X86IM_IO_ID_MOV_RG_CRX: /* mov reg, cr* */
		/* io.rop[0] = reg & io.rop[1] = cr */
		break;
	case X86IM_IO_ID_MOV_DRX_RG: /* mov dr*, reg */
		/* io.rop[0] = dr & io.rop[1] = reg */
		break;
	case X86IM_IO_ID_MOV_RG_DRX: /* mov reg, dr* */
		/* io.rop[0] = reg & io.rop[1] = dr */
		break;
	case X86IM_IO_ID_MOV_SR_MM: /* mov sr, [reg1+reg2+0ff | 0x0ff] */
		/* io.rop[0] = sr & io.mem_base = reg1 & io.mem_index = reg2 &
		 * io.disp = 0x0ff */
		break;
	case X86IM_IO_ID_MOV_MM_SR: /* mov [reg1+reg2+0ff | 0x0ff], sr */
		/* io.rop[0] = sr & io.mem_base = reg1 & io.mem_index = reg2 &
		 * io.disp = 0x0ff */
		break;
	case X86IM_IO_ID_MOV_SR_RG: /* mov sr, reg */
		/* io.rop[0] = sr & io.rop[1] = reg */
		break;
	case X86IM_IO_ID_MOV_RG_SR: /* mov reg, sr */
		/* io.rop[0] = reg & io.rop[1] = sr */
		break;
	}
}

static void anal_cmp(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->type = R_ANAL_OP_TYPE_CMP;
	switch (io.id) {
	case X86IM_IO_ID_CMP_MM_RG: /* cmp [0x0ff | reg1+reg2+0x0ff], reg */
		aop->src[0] = anal_fill_ai_mm (anal, io);
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* cmp [0x0ff], reg */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_CMP_R1_R2: /* cmp reg2, reg1 */
	case X86IM_IO_ID_CMP_R2_R1:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_CMP_RG_MM: /* cmp reg, [0x0ff | reg1+reg2+0x0ff] */
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* cmp reg, [0x0ff] */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_CMP_MM_IM: /* cmp [0x0ff | reg1+reg2+0x0ff], 0x1 */
		aop->dst = anal_fill_ai_mm (anal, io);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* cmp [0x0ff], 0x1 */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* cmp [ebp+0x0ff], 0x1*/
			aop->stackop = R_ANAL_STACK_GET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_CMP_RG_IM: /* cmp reg, 0x1 */
	case X86IM_IO_ID_CMP_AC_IM:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_im (anal, io);
		break;
	}
}

static void anal_push(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	switch (io.id) {
	case X86IM_IO_ID_PUSH_MM: /* push [0x0ff | reg1+reg2+0x0ff] */
		aop->type = R_ANAL_OP_TYPE_UPUSH;
		aop->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		aop->stackptr = io.mem_size;
		if (io.mem_base == 0) { /* push [0x0ff] */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* push [ebp+0x0ff] */
			aop->stackop = R_ANAL_STACK_GET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_PUSH_RG1: /* push reg */
	case X86IM_IO_ID_PUSH_RG2:
		aop->type = R_ANAL_OP_TYPE_UPUSH;
		aop->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_16))
			aop->stackptr = 2;
		else if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_32))
			aop->stackptr = 4;
		else if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_64))
			aop->stackptr = 8;
		break;
	case X86IM_IO_ID_PUSH_IM: /* push 0x1 */
		aop->type = R_ANAL_OP_TYPE_PUSH;
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		aop->value = imm;
		aop->stackptr = io.imm_size;
		break;
	case X86IM_IO_ID_PUSH_SR1: /* push sr */
	case X86IM_IO_ID_PUSH_SR2:
		/* io.rop[0] = sr */
		aop->type = R_ANAL_OP_TYPE_UPUSH;
		break;
	case X86IM_IO_ID_PUSHAD: /* pushad */
	case X86IM_IO_ID_PUSHF: /* pushf */
		aop->type = R_ANAL_OP_TYPE_UPUSH;
		break;
	}
}

static void anal_pop(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->type = R_ANAL_OP_TYPE_POP;
	switch (io.id) {
	case X86IM_IO_ID_POP_MM: /* pop [0x0ff | reg1+reg2+0x0ff] */
		aop->dst = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* pop [0x0ff] */
			aop->ref = disp;
		}
		aop->stackptr = -io.mem_size;
		break;
	case X86IM_IO_ID_POP_RG1: /* pop reg */
	case X86IM_IO_ID_POP_RG2:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_16))
			aop->stackptr = -2;
		else
		if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_32))
			aop->stackptr = -4;
		else
		if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_64))
			aop->stackptr = -8;
		break;
	case X86IM_IO_ID_POP_SR2: /* pop sr */
	case X86IM_IO_ID_POP_SR1:
		/* io.rop[0] = sr */
		break;
	case X86IM_IO_ID_POPAD: /* popad */
	case X86IM_IO_ID_POPF: /* popf */
		break;
	}
}

static void anal_add(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->type = R_ANAL_OP_TYPE_ADD;
	switch (io.id) {
	case X86IM_IO_ID_ADD_MM_RG: /* add [0x0ff | reg1+reg2+0x0ff], reg */
		aop->src[0] = anal_fill_ai_mm (anal, io);
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add [0x0ff], reg */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* add [ebp+0x0ff], reg*/
			aop->stackop = R_ANAL_STACK_SET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_RG_MM: /* add reg, [0x0ff | reg1+reg2+0x0ff] */
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add reg, [0x0ff] */
			aop->ref = disp;
		} else 
		if ((io.mem_base & X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* add reg, [ebp+0x0ff] */
			aop->stackop = R_ANAL_STACK_GET;
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_R1_R2: /* add reg2, reg1 */
	case X86IM_IO_ID_ADD_R2_R1:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_ADD_MM_IM: /* add [0x0ff | reg1+reg2+0x0ff], 0x1 */
		aop->dst = anal_fill_ai_mm (anal, io);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add [0x0ff], 0x1 */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_RG_IM: /* add reg, 0x1 */
	case X86IM_IO_ID_ADD_AC_IM:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.rop[0] & X86IM_IO_ROP_ID_ESP) { /* add esp, 0x1 */
			aop->stackop = R_ANAL_STACK_INCSTACK;
			aop->value = imm;
			aop->stackptr = -imm;
		}
		break;
	}
}

static void anal_sub(RAnal *anal, RAnalOp *aop, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	aop->type = R_ANAL_OP_TYPE_SUB;
	switch (io.id) {
	case X86IM_IO_ID_SUB_MM_RG: /* sub [0x0ff | reg1+reg2+0x0ff], reg */
		aop->src[0] = anal_fill_ai_mm (anal, io);
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub [0x0ff], reg */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_R1_R2: /* sub reg2, reg1 */
	case X86IM_IO_ID_SUB_R2_R1:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_SUB_RG_MM: /* sub reg, [0x0ff | reg1+reg2+0x0ff] */
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub reg, [0x0ff] */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_MM_IM: /* sub [0x0ff | reg1+reg2+0x0ff], 0x1 */
		aop->dst = anal_fill_ai_mm (anal, io);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub [0x0ff], 0x1 */
			aop->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_RG_IM: /* sub reg, 0x1 */
	case X86IM_IO_ID_SUB_AC_IM:
		aop->dst = anal_fill_ai_rg (anal, io, 0);
		aop->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.rop[0] & X86IM_IO_ROP_ID_ESP) { /* sub esp, 0x1*/
			aop->stackop = R_ANAL_STACK_INCSTACK;
			aop->value = imm;
			aop->stackptr = imm;
		}
		break;
	}
}

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *data, int len) {
	x86im_instr_object io;
	st64 imm, disp;
	char mnem[256];

	if (data == NULL)
		return 0;

	memset (aop, '\0', sizeof (RAnalOp));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->addr = addr;
	aop->jump = aop->fail = -1;
	aop->ref = aop->value = -1;

	if ((x86im_dec (&io,
			anal->bits == 32 ? X86IM_IO_MODE_32BIT : X86IM_IO_MODE_64BIT,
			(unsigned char*)data)) == X86IM_STATUS_SUCCESS) {
		if (io.len > len)
			return 0;
		x86im_fmt_format_name (&io, mnem);	
		aop->mnemonic = strdup (mnem);
		imm = r_hex_bin_truncate (io.imm, io.imm_size);
		disp = r_hex_bin_truncate (io.disp, io.disp_size);
		if (X86IM_IO_IS_GPI_JMP (&io)) /* jump */
			anal_jmp (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_JCC (&io)) /* conditional jump*/
			anal_cjmp (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_CALL (&io)) /* call */
			anal_call (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_RET (&io)) /* ret */
			anal_ret (anal, aop, io);
		else
		if (io.id == X86IM_IO_ID_HLT) /* htl */
			anal_hlt (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_MOV (&io)) /* mov */
			anal_mov (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_CMP (&io)) /* cmp */
			anal_cmp (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_PUSH (&io)) /* push */
			anal_push (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_POP (&io)) /* pop */
			anal_pop (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_ADD (&io)) /* add */
			anal_add (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_SUB (&io)) /* sub */
			anal_sub (anal, aop, io);
		else
		if (X86IM_IO_IS_GPI_MUL (&io)) { /* mul */
			aop->type = R_ANAL_OP_TYPE_MUL;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_DIV (&io)) { /* div */
			aop->type = R_ANAL_OP_TYPE_DIV;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHR (&io)) { /* shr */
			aop->type = R_ANAL_OP_TYPE_SHR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHL (&io)) { /* shl */
			aop->type = R_ANAL_OP_TYPE_SHL;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_OR (&io)) { /* or */
			aop->type = R_ANAL_OP_TYPE_OR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_AND (&io)) { /* and */
			aop->type = R_ANAL_OP_TYPE_AND;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_XOR (&io)) { /* xor */
			aop->type = R_ANAL_OP_TYPE_XOR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_NOT (&io)) { /* not */
			aop->type = R_ANAL_OP_TYPE_NOT;
			aop->value = imm;
		}
		aop->length = io.len;
		aop->nopcode = io.opcode_count;
	}

	return aop->length;
}

struct r_anal_plugin_t r_anal_plugin_x86_x86im = {
	.name = "x86_x86im",
	.desc = "X86 x86im analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_x86im
};
#endif
