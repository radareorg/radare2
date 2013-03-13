/* radare - LGPL - Copyright 2009-2013 - nibble */

#include <string.h>

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "x86/x86im/x86im.h"

static const char *gpr8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
static const char *gpr8b[] = { "spl", "bpl", "sil", "dil" };
static const char *gpr16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
static const char *gpr32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
static const char *gpr64[] = {
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
static const char unkreg[] = "";

static const char* anal_reg(ut32 rop) {
	const char **table = NULL;
	if (X86IM_IO_ROP_IS_GPR8 (rop))  table = gpr8;  else
	if (X86IM_IO_ROP_IS_GPR8B (rop)) table = gpr8b; else
	if (X86IM_IO_ROP_IS_GPR16 (rop)) table = gpr16; else
	if (X86IM_IO_ROP_IS_GPR32 (rop)) table = gpr32; else
	if (X86IM_IO_ROP_IS_GPR64 (rop)) table = gpr64; else
	if (rop == X86IM_IO_ROP_ID_RIP) return "rip";
	return table? table[X86IM_IO_ROP_GET_ID (rop)]: unkreg;
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
	ret->memref = anal->bits/8;
	if (io.mem_base == 0) {
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

static int anal_jmp(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->eob = R_TRUE;
	switch (io.id) {
	case X86IM_IO_ID_JMP_N_R_S: /* jmp short 0x0ff */ 
	case X86IM_IO_ID_JMP_N_R:   /* jmp 0x0ff */
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + io.len + imm;
		op->dst = anal_fill_r (anal, io, op->addr);
		break;
	case X86IM_IO_ID_JMP_N_AI_MM: /* jmp  [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_JMP_F_AI_MM: /* jmp dword far  [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_mm (anal, io);
		op->type = R_ANAL_OP_TYPE_UJMP;
		/* TODO: Deprecate */
		if (io.mem_base == 0)
			op->ref = disp;
		if (anal->iob.io != NULL) {
			if (io.mem_base == X86IM_IO_ROP_ID_RIP) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = 0LL;
				anal->iob.read_at(anal->iob.io, op->addr + io.len + disp,
						(ut8*)&op->jump, anal->bits==64?8:4);
			} else if (io.mem_base == 0) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = 0LL;
				anal->iob.read_at(anal->iob.io, disp,
						(ut8*)&op->jump, anal->bits==64?8:4);
			}
		}
		break;
	case X86IM_IO_ID_JMP_N_AI_RG: /* jmp reg */
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->dst = anal_fill_ai_rg (anal, io, 0);
		break;
	case X86IM_IO_ID_JMP_F_A: /* jmp dword sel:0x0ff */
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->dst = anal_fill_f (anal, io);
		/* TODO: Deprecate */
		op->selector = io.selector;
		op->ref = imm;
		break;
	}
	if (anal->bits==16)
		op->jump--;
	return io.len;
}

static void anal_cjmp(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);

	op->eob = R_TRUE;
	switch (io.id) {
	case X86IM_IO_ID_JCC_S: /* j* 0x0ff */
	case X86IM_IO_ID_JCC_N: /* j* dword 0x0ff */ 
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->dst = anal_fill_r (anal, io, op->addr);
		op->fail = op->addr + io.len;
		op->jump = op->addr + io.len + imm;
		if (anal->bits==16)
			op->jump--;
		break;
	}
}

static void anal_call(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	switch (io.id) {
	case X86IM_IO_ID_CALL_N_R: /* call 0x0ff */
		op->type = R_ANAL_OP_TYPE_CALL;
		op->dst = anal_fill_r (anal, io, op->addr);
		op->jump = op->addr + io.len + imm;
		op->fail = op->addr + io.len;
		break;
	case X86IM_IO_ID_CALL_N_AI_MM: /* call [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_CALL_F_AI_MM: /* call dword far [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_mm (anal, io);
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->fail = op->addr + io.len;
		/* TODO: Deprecate */
		if (io.mem_base == 0)
			op->ref = disp;

		if (anal->iob.io != NULL) {
			if (io.mem_base == X86IM_IO_ROP_ID_RIP) {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = 0LL;
				anal->iob.read_at(anal->iob.io, op->addr + io.len + disp,
						(ut8*)&op->jump, anal->bits==64?8:4);
			} else if (io.mem_base == 0) {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = 0LL;
				anal->iob.read_at(anal->iob.io, disp,
						(ut8*)&op->jump, anal->bits==64?8:4);
			}
		}
		break;
	case X86IM_IO_ID_CALL_N_AI_RG: /* call reg */
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->fail = op->addr + io.len;
		break;
	case X86IM_IO_ID_CALL_F_A: /* call dword sel:0x0ff */
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->dst = anal_fill_f (anal, io);
		/* TODO: Deprecate */
		op->selector = io.selector;
		op->ref = imm;
		op->fail = op->addr + io.len;
		break;
	}
}

static void anal_ret(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);

	op->eob = R_TRUE;
	op->type = R_ANAL_OP_TYPE_RET;
	switch (io.id) {
	case X86IM_IO_ID_RET_N: /* ret */
	case X86IM_IO_ID_RET_F: /* retf */
		op->stackptr = anal->bits/8;
		break;
	case X86IM_IO_ID_RET_N_IM: /* ret n */
	case X86IM_IO_ID_RET_F_IM: /* retf n */
		op->dst = anal_fill_im (anal, io);
		op->stackptr = anal->bits/8 + imm;
		/* TODO: Deprecate */
		op->value = imm;
		break;
	}
}

static void anal_hlt(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	op->eob = R_TRUE;
	op->type = R_ANAL_OP_TYPE_TRAP; // not really..
}

static void anal_mov(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	//st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_MOV;
	switch (io.id) {
	case X86IM_IO_ID_MOV_MM_RG:  /* mov [0x0ff | reg1+reg2+0x0ff], reg */
	case X86IM_IO_ID_MOV_MM_AC:
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* mov [0x0ff], reg */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov [ebp+0x0ff], reg */
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_R2_R1: /* mov reg2, reg1 */
	case X86IM_IO_ID_MOV_R1_R2:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_MOV_RG_MM: /* mov reg, [0x0ff | reg1+reg2+0x0ff] */
	case X86IM_IO_ID_MOV_AC_MM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* mov reg, [0x0ff] */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov reg, [ebp+0x0ff] */
			op->stackop = R_ANAL_STACK_GET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_MM_IM: /* mov [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* [0x0ff], 0x1 */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* mov [ebp+0x0ff], 0x1 */
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_MOV_RG_IM: /* mov reg, 0x1 */
	case X86IM_IO_ID_MOV_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
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

static void anal_cmp(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	//st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_CMP;
	switch (io.id) {
	case X86IM_IO_ID_CMP_MM_RG: /* cmp [0x0ff | reg1+reg2+0x0ff], reg */
		op->src[0] = anal_fill_ai_mm (anal, io);
		op->src[1] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) /* cmp [0x0ff], reg */
			op->ref = disp;
		break;
	case X86IM_IO_ID_CMP_R1_R2: /* cmp reg2, reg1 */
	case X86IM_IO_ID_CMP_R2_R1:
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		op->src[1] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_CMP_RG_MM: /* cmp reg, [0x0ff | reg1+reg2+0x0ff] */
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		op->src[1] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* cmp reg, [0x0ff] */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_CMP_MM_IM: /* cmp [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->src[0] = anal_fill_ai_mm (anal, io);
		op->src[1] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* cmp [0x0ff], 0x1 */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* cmp [ebp+0x0ff], 0x1*/
			op->stackop = R_ANAL_STACK_GET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_CMP_RG_IM: /* cmp reg, 0x1 */
	case X86IM_IO_ID_CMP_AC_IM:
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		op->src[1] = anal_fill_im (anal, io);
		break;
	}
}

static void anal_test(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	//st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_CMP;
	switch (io.id) {
	case X86IM_IO_ID_TEST_MM_R1: /* test [0x0ff | reg1+reg2+0x0ff], reg */
		op->src[0] = anal_fill_ai_mm (anal, io);
		op->src[1] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* test [0x0ff], reg */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_TEST_R1_R2: /* test reg2, reg1 */
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		op->src[1] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_TEST_MM_IM: /* test [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->src[0] = anal_fill_ai_mm (anal, io);
		op->src[1] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* test [0x0ff], 0x1 */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* test [ebp+0x0ff], 0x1*/
			op->stackop = R_ANAL_STACK_GET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_TEST_RG_IM: /* test reg, 0x1 */
	case X86IM_IO_ID_TEST_AC_IM:
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		op->src[1] = anal_fill_im (anal, io);
		break;
	}
}

static void anal_push(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	switch (io.id) {
	case X86IM_IO_ID_PUSH_MM: /* push [0x0ff | reg1+reg2+0x0ff] */
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		op->stackptr = io.mem_size;
		if (io.mem_base == 0) { /* push [0x0ff] */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* push [ebp+0x0ff] */
			op->stackop = R_ANAL_STACK_GET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_PUSH_RG1: /* push reg */
	case X86IM_IO_ID_PUSH_RG2:
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (X86IM_IO_ROP_IS_GPR16(io.rop[0]))
			op->stackptr = 2;
		else if (X86IM_IO_ROP_IS_GPR32(io.rop[0]))
			op->stackptr = 4;
		else if (X86IM_IO_ROP_IS_GPR64(io.rop[0]))
			op->stackptr = 8;
		break;
	case X86IM_IO_ID_PUSH_IM: /* push 0x1 */
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		op->stackptr = io.imm_size;
		break;
	case X86IM_IO_ID_PUSH_SR1: /* push sr */
	case X86IM_IO_ID_PUSH_SR2:
		/* io.rop[0] = sr */
		op->type = R_ANAL_OP_TYPE_UPUSH;
		break;
	case X86IM_IO_ID_PUSHAD: /* pushad */
	case X86IM_IO_ID_PUSHF: /* pushf */
		op->type = R_ANAL_OP_TYPE_UPUSH;
		break;
	}
}

static void anal_pop(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	//st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_POP;
	switch (io.id) {
	case X86IM_IO_ID_POP_MM: /* pop [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* pop [0x0ff] */
			op->ref = disp;
		}
		op->stackptr = -io.mem_size;
		break;
	case X86IM_IO_ID_POP_RG1: /* pop reg */
	case X86IM_IO_ID_POP_RG2:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (X86IM_IO_ROP_IS_GPR16 (io.rop[0]))
			op->stackptr = -2;
		else
		if (X86IM_IO_ROP_IS_GPR32 (io.rop[0]))
			op->stackptr = -4;
		else
		if (X86IM_IO_ROP_IS_GPR64 (io.rop[0]))
			op->stackptr = -8;
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

static void anal_add(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_ADD;
	switch (io.id) {
	case X86IM_IO_ID_ADD_MM_RG: /* add [0x0ff | reg1+reg2+0x0ff], reg */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add [0x0ff], reg */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* add [ebp+0x0ff], reg*/
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_RG_MM: /* add reg, [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add reg, [0x0ff] */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* add reg, [ebp+0x0ff] */
			op->stackop = R_ANAL_STACK_GET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_R1_R2: /* add reg2, reg1 */
	case X86IM_IO_ID_ADD_R2_R1:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_ADD_MM_IM: /* add [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* add [0x0ff], 0x1 */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_ADD_RG_IM: /* add reg, 0x1 */
	case X86IM_IO_ID_ADD_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (X86IM_IO_ROP_GET_ID (io.rop[0]) == X86IM_IO_ROP_ID_ESP) { /* add esp, 0x1 */
			op->stackop = R_ANAL_STACK_INCSTACK;
			op->value = imm;
			op->stackptr = -imm;
		}
		break;
	}
}

static void anal_sub(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_SUB;
	switch (io.id) {
	case X86IM_IO_ID_SUB_MM_RG: /* sub [0x0ff | reg1+reg2+0x0ff], reg */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub [0x0ff], reg */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_R1_R2: /* sub reg2, reg1 */
	case X86IM_IO_ID_SUB_R2_R1:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_SUB_RG_MM: /* sub reg, [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub reg, [0x0ff] */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_MM_IM: /* sub [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* sub [0x0ff], 0x1 */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_SUB_RG_IM: /* sub reg, 0x1 */
	case X86IM_IO_ID_SUB_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		if (X86IM_IO_ROP_GET_ID (io.rop[0]) == X86IM_IO_ROP_ID_ESP) { /* sub esp, 0x1*/
			op->stackop = R_ANAL_STACK_INCSTACK;
			op->value = imm;
			op->stackptr = imm;
		}
		break;
	}
}

static void anal_and(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_AND;
	switch (io.id) {
	case X86IM_IO_ID_AND_MM_RG: /* and [0x0ff | reg1+reg2+0x0ff], reg */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* and [0x0ff], reg */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* and [ebp+0x0ff], reg*/
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_AND_RG_MM: /* and reg, [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* and reg, [0x0ff] */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_AND_R1_R2: /* and reg2, reg1 */
	case X86IM_IO_ID_AND_R2_R1:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_AND_MM_IM: /* and [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		if (io.mem_base == 0) { /* and [0x0ff], 0x1 */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_AND_RG_IM: /* and reg, 0x1 */
	case X86IM_IO_ID_AND_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		break;
	}
}

static void anal_or(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_OR;
	switch (io.id) {
	case X86IM_IO_ID_OR_MM_RG: /* or [0x0ff | reg1+reg2+0x0ff], reg */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* or [0x0ff], reg */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* or [ebp+0x0ff], reg*/
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_OR_RG_MM: /* or reg, [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* or reg, [0x0ff] */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_OR_R1_R2: /* or reg2, reg1 */
	case X86IM_IO_ID_OR_R2_R1:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_OR_MM_IM: /* or [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		if (io.mem_base == 0) { /* or [0x0ff], 0x1 */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_OR_RG_IM: /* or reg, 0x1 */
	case X86IM_IO_ID_OR_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		break;
	}
}

static void anal_xor(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	st64 imm, disp;
	imm = r_hex_bin_truncate (io.imm, io.imm_size);
	disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_XOR;
	switch (io.id) {
	case X86IM_IO_ID_XOR_MM_RG: /* xor [0x0ff | reg1+reg2+0x0ff], reg */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_ai_rg (anal, io, 0);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* xor [0x0ff], reg */
			op->ref = disp;
		} else 
		if ((X86IM_IO_ROP_GET_ID (io.mem_base) == X86IM_IO_ROP_ID_EBP) &&
			io.mem_index == 0) { /* xor [ebp+0x0ff], reg*/
			op->stackop = R_ANAL_STACK_SET;
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_XOR_RG_MM: /* xor reg, [0x0ff | reg1+reg2+0x0ff] */
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_mm (anal, io);
		/* TODO: Deprecate */
		if (io.mem_base == 0) { /* xor reg, [0x0ff] */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_XOR_R1_R2: /* xor reg2, reg1 */
	case X86IM_IO_ID_XOR_R2_R1:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_ai_rg (anal, io, 1);
		break;
	case X86IM_IO_ID_XOR_MM_IM: /* xor [0x0ff | reg1+reg2+0x0ff], 0x1 */
		op->dst = anal_fill_ai_mm (anal, io);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		if (io.mem_base == 0) { /* xor [0x0ff], 0x1 */
			op->ref = disp;
		}
		break;
	case X86IM_IO_ID_XOR_RG_IM: /* xor reg, 0x1 */
	case X86IM_IO_ID_XOR_AC_IM:
		op->dst = anal_fill_ai_rg (anal, io, 0);
		op->src[0] = anal_fill_im (anal, io);
		/* TODO: Deprecate */
		op->value = imm;
		break;
	}
}

static void anal_lea(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	//st64 imm = r_hex_bin_truncate (io.imm, io.imm_size);
	//st64 disp = r_hex_bin_truncate (io.disp, io.disp_size);

	op->type = R_ANAL_OP_TYPE_LEA;
	/* lea reg, [0x0ff | reg1+reg2+0x0ff] */
	op->dst = anal_fill_ai_rg (anal, io, 0);
	op->src[0] = anal_fill_ai_mm (anal, io);
}

static void anal_int(RAnal *anal, RAnalOp *op, x86im_instr_object io) {
	op->type = R_ANAL_OP_TYPE_SWI;
	switch (io.id) {
	case X86IM_IO_ID_INTN:
		op->value = io.imm; /* io.imm doesn't need to be trucated here */
		break;
	case X86IM_IO_ID_INT3:
		op->value = 3;
		break;
	case X86IM_IO_ID_INTO:
		break;
	}
}

extern int x86_udis86_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len);
static int x86_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	x86im_instr_object io;
	st64 imm;
	char mnem[256];
	int ret;

	if (data == NULL)
		return 0;

	memset (op, '\0', sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ref = op->value = -1;

	if (!memcmp ("\xf3\xc3", data, 2)) {
		op->type = R_ANAL_OP_TYPE_RET;
		return op->length = 2;
	}
	ret = -1;
	if (anal->bits==64)
		ret = (x86im_dec (&io, X86IM_IO_MODE_64BIT, (ut8*)data));
	if (ret != X86IM_STATUS_SUCCESS)
		ret = (x86im_dec (&io, X86IM_IO_MODE_32BIT, (ut8*)data));
	if (anal->bits==16) {
		switch (io.id) {
		case X86IM_IO_ID_JCC_S:
		case X86IM_IO_ID_JCC_N:
		case X86IM_IO_ID_JMP_F_AI_MM:
		case X86IM_IO_ID_CALL_N_R:
		case X86IM_IO_ID_CALL_F_AI_MM:
		case X86IM_IO_ID_CALL_N_AI_MM:
		case X86IM_IO_ID_JMP_N_R:
		case X86IM_IO_ID_JMP_N_R_S:
		case X86IM_IO_ID_CALL_F_A:
			io.len = 3;
			imm = io.imm & 0xffff;
			break;
		default:
			return x86_udis86_op (anal, op, addr, data, len);
		}
	}
	switch (io.id) {
	case X86IM_IO_ID_OUT_IM:
	case X86IM_IO_ID_OUT_RG:
	case X86IM_IO_ID_OUTSX:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case X86IM_IO_ID_IN_IM:
	case X86IM_IO_ID_IN_RG:
	case X86IM_IO_ID_INSX:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	}
	
	if (ret == X86IM_STATUS_SUCCESS) {
		if (io.len > len)
			return 0;
		x86im_fmt_format_name (&io, mnem);	
		op->mnemonic = strdup (mnem);
		imm = r_hex_bin_truncate (io.imm, io.imm_size);
		//disp = r_hex_bin_truncate (io.disp, io.disp_size);
		if (X86IM_IO_IS_GPI_JMP (&io)) /* jump */
			io.len = anal_jmp (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_JCC (&io)) /* conditional jump*/
			anal_cjmp (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_CALL (&io)) /* call */
			anal_call (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_RET (&io)) /* ret */
			anal_ret (anal, op, io);
		else
		if (io.id == X86IM_IO_ID_HLT) /* htl */
			anal_hlt (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_MOV (&io)) /* mov */
			anal_mov (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_CMP (&io)) /* cmp */
			anal_cmp (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_TEST (&io)) /* test */
			anal_test (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_PUSH (&io)) /* push */
			anal_push (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_POP (&io)) /* pop */
			anal_pop (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_ADD (&io)) /* add */
			anal_add (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_SUB (&io)) /* sub */
			anal_sub (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_INT (&io)) { /* int */
			anal_int (anal, op, io);
			if (op->value == 3)
				op->type = R_ANAL_OP_TYPE_TRAP;
		} else
		if (X86IM_IO_IS_GPI_MUL (&io)) { /* mul */
			op->type = R_ANAL_OP_TYPE_MUL;
			op->value = imm;
		} else
		if (X86IM_IO_IS_GPI_DIV (&io)) { /* div */
			op->type = R_ANAL_OP_TYPE_DIV;
			op->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHR (&io)) { /* shr */
			op->type = R_ANAL_OP_TYPE_SHR;
			op->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHL (&io)) { /* shl */
			op->type = R_ANAL_OP_TYPE_SHL;
			op->value = imm;
		} else
		if (X86IM_IO_IS_GPI_OR (&io)) /* or */
			anal_or (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_AND (&io)) /* and */
			anal_and (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_XOR (&io)) /* xor */
			anal_xor (anal, op, io);
		else
		if (X86IM_IO_IS_GPI_NOT (&io)) { /* not */
			op->type = R_ANAL_OP_TYPE_NOT;
			op->value = imm;
		} else
		if (io.id == X86IM_IO_ID_NOP) /* nop */
			op->type = R_ANAL_OP_TYPE_NOP;
		else
		if (io.id == X86IM_IO_ID_LEA) /* lea */
			anal_lea (anal, op, io);
		else
		if (io.id == X86IM_IO_ID_LEAVE) /* leave */
			op->type = R_ANAL_OP_TYPE_LEAVE;
		op->length = io.len;
		op->nopcode = io.opcode_count;
	}
	return op->length;
}

static int set_reg_profile(RAnal *anal) {
	/* XXX Dupped Profiles */
// TODO: add support for 16 bit
	if (anal->bits == 32)
#if __WINDOWS__
		return r_reg_set_profile_string (anal->reg,
				"=pc	eip\n"
				"=sp	esp\n"
				"=bp	ebp\n"
				"=a0	eax\n"
				"=a1	ebx\n"
				"=a2	ecx\n"
				"=a3	edi\n"
				"drx	dr0	.32	4	0\n"
				"drx	dr1	.32	8	0\n"
				"drx	dr2	.32	12	0\n"
				"drx	dr3	.32	16	0\n"
				"drx	dr6	.32	20	0\n"
				"drx	dr7	.32	24	0\n"
				/* floating save area 4+4+4+4+4+4+4+80+4 = 112 */
				"seg	gs	.32	132	0\n"
				"seg	fs	.32	136	0\n"
				"seg	es	.32	140	0\n"
				"seg	ds	.32	144	0\n"
				"gpr	edi	.32	156	0\n"
				"gpr	esi	.32	160	0\n"
				"gpr	ebx	.32	164	0\n"
				"gpr	edx	.32	168	0\n"
				"gpr	ecx	.32	172	0\n"
				"gpr	eax	.32	176	0\n"
				"gpr	ebp	.32	180	0\n"
				"gpr	esp	.32	196	0\n"
				"gpr	eip	.32	184	0\n"
				"seg	cs	.32	184	0\n"
				"seg	ds	.32	152	0\n"
				"seg	gs	.32	140	0\n"
				"seg	fs	.32	144	0\n"
				"gpr	eflags	.32	192	0	c1p.a.zstido.n.rv\n" // XXX must be flg
				"seg	ss	.32	200	0\n"
				/* +512 bytes for maximum supoprted extension extended registers */
				);
#else
		return r_reg_set_profile_string (anal->reg,
				"=pc	eip\n"
				"=sp	esp\n"
				"=bp	ebp\n"
				"=a0	eax\n"
				"=a1	ebx\n"
				"=a2	ecx\n"
				"=a3	edi\n"
				"gpr	eip	.32	48	0\n"
				"gpr	ip	.16	48	0\n"
				"gpr	oeax	.32	44	0\n"
				"gpr	eax	.32	24	0\n"
				"gpr	ax	.16	24	0\n"
				"gpr	ah	.8	24	0\n"
				"gpr	al	.8	25	0\n"
				"gpr	ebx	.32	0	0\n"
				"gpr	bx	.16	0	0\n"
				"gpr	bh	.8	0	0\n"
				"gpr	bl	.8	1	0\n"
				"gpr	ecx	.32	4	0\n"
				"gpr	cx	.16	4	0\n"
				"gpr	ch	.8	4	0\n"
				"gpr	cl	.8	5	0\n"
				"gpr	edx	.32	8	0\n"
				"gpr	dx	.16	8	0\n"
				"gpr	dh	.8	8	0\n"
				"gpr	dl	.8	9	0\n"
				"gpr	esp	.32	60	0\n"
				"gpr	sp	.16	60	0\n"
				"gpr	ebp	.32	20	0\n"
				"gpr	bp	.16	20	0\n"
				"gpr	esi	.32	12	0\n"
				"gpr	si	.16	12	0\n"
				"gpr	edi	.32	16	0\n"
				"gpr	di	.16	16	0\n"
				"seg	xfs	.32	36	0\n"
				"seg	xgs	.32	40	0\n"
				"seg	xcs	.32	52	0\n"
				"seg	cs	.16	52	0\n"
				"seg	xss	.32	52	0\n"
				"gpr	eflags	.32	56	0	c1p.a.zstido.n.rv\n"
				"gpr	flags	.16	56	0\n"
				"flg	carry	.1	.448	0\n"
				"flg	flag_p	.1	.449	0\n"
				"flg	flag_a	.1	.450	0\n"
				"flg	zero	.1	.451	0\n"
				"flg	sign	.1	.452	0\n"
				"flg	flag_t	.1	.453	0\n"
				"flg	flag_i	.1	.454	0\n"
				"flg	flag_d	.1	.455	0\n"
				"flg	flag_o	.1	.456	0\n"
				"flg	flag_r	.1	.457	0\n"
				"drx	dr0	.32	0	0\n"
				"drx	dr1	.32	4	0\n"
				"drx	dr2	.32	8	0\n"
				"drx	dr3	.32	12	0\n"
				//"drx	dr4	.32	16	0\n"
				//"drx	dr5	.32	20	0\n"
				"drx	dr6	.32	24	0\n"
				"drx	dr7	.32	28	0\n");
#endif
	else return r_reg_set_profile_string (anal->reg,
				"=pc	rip\n"
				"=sp	rsp\n"
				"=bp	rbp\n"
				"=a0	rax\n"
				"=a1	rbx\n"
				"=a2	rcx\n"
				"=a3	rdx\n"
				"# no profile defined for x86-64\n"
				"gpr	r15	.64	0	0\n"
				"gpr	r14	.64	8	0\n"
				"gpr	r13	.64	16	0\n"
				"gpr	r12	.64	24	0\n"
				"gpr	rbp	.64	32	0\n"
				"gpr	ebp	.32	32	0\n"
				"gpr	rbx	.64	40	0\n"
				"gpr	ebx	.32	40	0\n"
				"gpr	r11	.64	48	0\n"
				"gpr	r10	.64	56	0\n"
				"gpr	r9	.64	64	0\n"
				"gpr	r8	.64	72	0\n"
				"gpr	rax	.64	80	0\n"
				"gpr	eax	.32	80	0\n"
				"gpr	rcx	.64	88	0\n"
				"gpr	ecx	.32	88	0\n"
				"gpr	rdx	.64	96	0\n"
				"gpr	edx	.32	96	0\n"
				"gpr	rsi	.64	104	0\n"
				"gpr	esi	.32	104	0\n"
				"gpr	rdi	.64	112	0\n"
				"gpr	edi	.32	112	0\n"
				"gpr	oeax	.64	120	0\n"
				"gpr	rip	.64	128	0\n"
				"seg	cs	.64	136	0\n"
				//"flg	eflags	.64	144	0\n"
				"gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
				"gpr	rsp	.64	152	0\n"
				"seg	ss	.64	160	0\n"
				"seg	fs_base	.64	168	0\n"
				"seg	gs_base	.64	176	0\n"
				"seg	ds	.64	184	0\n"
				"seg	es	.64	192	0\n"
				"seg	fs	.64	200	0\n"
				"seg	gs	.64	208	0\n"
				"drx	dr0	.32	0	0\n"
				"drx	dr1	.32	4	0\n"
				"drx	dr2	.32	8	0\n"
				"drx	dr3	.32	12	0\n"
				"drx	dr6	.32	24	0\n"
				"drx	dr7	.32	28	0\n");
}

struct r_anal_plugin_t r_anal_plugin_x86 = {
	.name = "x86",
	.desc = "X86 analysis plugin (x86im backend)",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.op = &x86_op,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86
};
#endif
