#include <stdio.h>
#include <stdbool.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_anal.h>
#include "hexagon.h"
#include "hexagon_insn.h"

int hexagon_anal_instruction(HexInsn *hi, RAnalOp *op) {
	switch (hi->instruction) {
	case HEX_INS_CALL__R22_2: {
		// call #r22:2
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = op->addr + (st32) hi->ops[0].op.imm;
		break;
	}
	case HEX_INS_IF__PU__CALL__R15_2: {
		// if (Pu) call #r15:2
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		break;
	}
	case HEX_INS_IF__NOT_PU_CALL__R15_2: {
		// if !Pu call #r15:2
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS____1____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, #-1) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS____1____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, #-1) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___TSTBIT__RS___0____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = tstbit (Rs, #0) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS____1____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, #-1) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS____1____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, #-1) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___TSTBIT__RS___0____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = tstbit (Rs, #0) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS____1____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, #-1) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS____1____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, #-1) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___TSTBIT__RS___0____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = tstbit (Rs, #0) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS____1____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, #-1) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS____1____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, #-1) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___TSTBIT__RS___0____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = tstbit (Rs, #0) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS___U5____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, #U5) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS___U5____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, #U5) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS___U5____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, #U5) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS___U5____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, #U5) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS___U5____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, #U5) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS___U5____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, #U5) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS___U5____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, #U5) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS___U5____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, #U5) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS___U5____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gtu (Rs, #U5) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS___U5____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gtu (Rs, #U5) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS___U5____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gtu (Rs, #U5) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS___U5____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gtu (Rs, #U5) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS____1____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, #-1) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS____1____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, #-1) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___TSTBIT__RS___0____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = tstbit (Rs, #0) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS____1____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, #-1) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS____1____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, #-1) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___TSTBIT__RS___0____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = tstbit (Rs, #0) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS____1____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, #-1) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS____1____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, #-1) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___TSTBIT__RS___0____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = tstbit (Rs, #0) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS____1____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, #-1) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS____1____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, #-1) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___TSTBIT__RS___0____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = tstbit (Rs, #0) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS___U5____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, #U5) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS___U5____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, #U5) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS___U5____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, #U5) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS___U5____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, #U5) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS___U5____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, #U5) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS___U5____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, #U5) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS___U5____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, #U5) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS___U5____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, #U5) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS___U5____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gtu (Rs, #U5) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS___U5____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gtu (Rs, #U5) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS___U5____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gtu (Rs, #U5) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS___U5____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gtu (Rs, #U5) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS__RT____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, Rt) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS__RT____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, Rt) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS__RT____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, Rt) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS__RT____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, Rt) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS__RT____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.eq (Rs, Rt) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS__RT____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.eq (Rs, Rt) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_EQ__RS__RT____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.eq (Rs, Rt) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_EQ__RS__RT____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.eq (Rs, Rt) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS__RT____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, Rt) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS__RT____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, Rt) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS__RT____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, Rt) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS__RT____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, Rt) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS__RT____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gt (Rs, Rt) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS__RT____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gt (Rs, Rt) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GT__RS__RT____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gt (Rs, Rt) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GT__RS__RT____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gt (Rs, Rt) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS__RT____IF__P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gtu (Rs, Rt) ; if (p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS__RT____IF__P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gtu (Rs, Rt) ; if (p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS__RT____IF__P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gtu (Rs, Rt) ; if (p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS__RT____IF__P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gtu (Rs, Rt) ; if (p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS__RT____IF___NOT_P0_NEW__JUMP_NT__R9_2: {
		// p0 = cmp.gtu (Rs, Rt) ; if (!p0.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS__RT____IF___NOT_P1_NEW__JUMP_NT__R9_2: {
		// p1 = cmp.gtu (Rs, Rt) ; if (!p1.new) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P0___CMP_GTU__RS__RT____IF___NOT_P0_NEW__JUMP_T__R9_2: {
		// p0 = cmp.gtu (Rs, Rt) ; if (!p0.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_P1___CMP_GTU__RS__RT____IF___NOT_P1_NEW__JUMP_T__R9_2: {
		// p1 = cmp.gtu (Rs, Rt) ; if (!p1.new) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_JUMP__R22_2: {
		// jump #r22:2
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + (st32) hi->ops[0].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__PU__JUMP_NT__R15_2: {
		// if (Pu) jump:nt #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__PU__JUMP_T__R15_2: {
		// if (Pu) jump:t #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__NOT_PU_JUMP_NT__R15_2: {
		// if !Pu jump:nt #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__NOT_PU_JUMP_T__R15_2: {
		// if !Pu jump:t #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__PU_NEW__JUMP_NT__R15_2: {
		// if (Pu.new) jump:nt #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__PU_NEW__JUMP_T__R15_2: {
		// if (Pu.new) jump:t #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__NOT_PU_NEW_JUMP_NT__R15_2: {
		// if !Pu.new jump:nt #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__NOT_PU_NEW_JUMP_T__R15_2: {
		// if !Pu.new jump:t #r15:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS__NOT____0__JUMP_NT__R13_2: {
		// if (Rs != #0) jump:nt #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS__NOT____0__JUMP_T__R13_2: {
		// if (Rs != #0) jump:t #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS_GT_EQ___0__JUMP_NT__R13_2: {
		// if (Rs> = #0) jump:nt #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS_GT_EQ___0__JUMP_T__R13_2: {
		// if (Rs> = #0) jump:t #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS__EQ___0__JUMP_NT__R13_2: {
		// if (Rs == #0) jump:nt #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS__EQ___0__JUMP_T__R13_2: {
		// if (Rs == #0) jump:t #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS_LT_EQ___0__JUMP_NT__R13_2: {
		// if (Rs< = #0) jump:nt #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__RS_LT_EQ___0__JUMP_T__R13_2: {
		// if (Rs< = #0) jump:t #r13:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_RD____U6___JUMP__R9_2: {
		// Rd = #U6 ; jump #r9:2
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_MULT_RD___RS___JUMP__R9_2: {
		// Rd = Rs ; jump #r9:2
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_DEALLOC_RETURN: {
		// dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__PS_NEW__DEALLOC_RETURN_NT: {
		// if (Ps.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__PS__DEALLOC_RETURN: {
		// if (Ps) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__PS_NEW__DEALLOC_RETURN_T: {
		// if (Ps.new) dealloc_return:t
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__NOT_PS_NEW_DEALLOC_RETURN_NT: {
		// if !Ps.new dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__NOT_PS_DEALLOC_RETURN: {
		// if !Ps dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__NOT_PS_NEW_DEALLOC_RETURN_T: {
		// if !Ps.new dealloc_return:t
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (cmp.eq (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW__RT___JUMP_T__R9_2: {
		// if (cmp.eq (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (!cmp.eq (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW__RT___JUMP_T__R9_2: {
		// if (!cmp.eq (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (cmp.gt (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW__RT___JUMP_T__R9_2: {
		// if (cmp.gt (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (!cmp.gt (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW__RT___JUMP_T__R9_2: {
		// if (!cmp.gt (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (cmp.gtu (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__NS_NEW__RT___JUMP_T__R9_2: {
		// if (cmp.gtu (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__NS_NEW__RT___JUMP_NT__R9_2: {
		// if (!cmp.gtu (Ns.new, Rt)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__NS_NEW__RT___JUMP_T__R9_2: {
		// if (!cmp.gtu (Ns.new, Rt)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__RT__NS_NEW___JUMP_NT__R9_2: {
		// if (cmp.gt (Rt, Ns.new)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__RT__NS_NEW___JUMP_T__R9_2: {
		// if (cmp.gt (Rt, Ns.new)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__RT__NS_NEW___JUMP_NT__R9_2: {
		// if (!cmp.gt (Rt, Ns.new)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__RT__NS_NEW___JUMP_T__R9_2: {
		// if (!cmp.gt (Rt, Ns.new)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__RT__NS_NEW___JUMP_NT__R9_2: {
		// if (cmp.gtu (Rt, Ns.new)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__RT__NS_NEW___JUMP_T__R9_2: {
		// if (cmp.gtu (Rt, Ns.new)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__RT__NS_NEW___JUMP_NT__R9_2: {
		// if (!cmp.gtu (Rt, Ns.new)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__RT__NS_NEW___JUMP_T__R9_2: {
		// if (!cmp.gtu (Rt, Ns.new)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (cmp.eq (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW___U5___JUMP_T__R9_2: {
		// if (cmp.eq (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (!cmp.eq (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW___U5___JUMP_T__R9_2: {
		// if (!cmp.eq (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (cmp.gt (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW___U5___JUMP_T__R9_2: {
		// if (cmp.gt (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (!cmp.gt (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW___U5___JUMP_T__R9_2: {
		// if (!cmp.gt (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (cmp.gtu (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GTU__NS_NEW___U5___JUMP_T__R9_2: {
		// if (cmp.gtu (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__NS_NEW___U5___JUMP_NT__R9_2: {
		// if (!cmp.gtu (Ns.new, #U5)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GTU__NS_NEW___U5___JUMP_T__R9_2: {
		// if (!cmp.gtu (Ns.new, #U5)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__TSTBIT__NS_NEW___0___JUMP_NT__R9_2: {
		// if (tstbit (Ns.new, #0)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__TSTBIT__NS_NEW___0___JUMP_T__R9_2: {
		// if (tstbit (Ns.new, #0)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_TSTBIT__NS_NEW___0___JUMP_NT__R9_2: {
		// if (!tstbit (Ns.new, #0)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_TSTBIT__NS_NEW___0___JUMP_T__R9_2: {
		// if (!tstbit (Ns.new, #0)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW____1___JUMP_NT__R9_2: {
		// if (cmp.eq (Ns.new, #-1)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_EQ__NS_NEW____1___JUMP_T__R9_2: {
		// if (cmp.eq (Ns.new, #-1)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW____1___JUMP_NT__R9_2: {
		// if (!cmp.eq (Ns.new, #-1)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_EQ__NS_NEW____1___JUMP_T__R9_2: {
		// if (!cmp.eq (Ns.new, #-1)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW____1___JUMP_NT__R9_2: {
		// if (cmp.gt (Ns.new, #-1)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF__CMP_GT__NS_NEW____1___JUMP_T__R9_2: {
		// if (cmp.gt (Ns.new, #-1)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW____1___JUMP_NT__R9_2: {
		// if (!cmp.gt (Ns.new, #-1)) jump:nt #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_IF___NOT_CMP_GT__NS_NEW____1___JUMP_T__R9_2: {
		// if (!cmp.gt (Ns.new, #-1)) jump:t #r9:2
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (st32) hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	}
	case HEX_INS_DUPLEX_RD_____1___DEALLOC_RETURN: {
		// Rd = #-1 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD_____1___IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = #-1 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD_____1___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = #-1 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD_____1___IF__P0__DEALLOC_RETURN: {
		// Rd = #-1 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD_____1___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = #-1 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD____U6___DEALLOC_RETURN: {
		// Rd = #u6 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD____U6___IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = #u6 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD____U6___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = #u6 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD____U6___IF__P0__DEALLOC_RETURN: {
		// Rd = #u6 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD____U6___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = #u6 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___RS___DEALLOC_RETURN: {
		// Rd = Rs ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___RS___IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = Rs ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___RS___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = Rs ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___RS___IF__P0__DEALLOC_RETURN: {
		// Rd = Rs ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___RS___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = Rs ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS____1____DEALLOC_RETURN: {
		// Rd = add (Rs, #-1) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS____1____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = add (Rs, #-1) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS____1____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Rs, #-1) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS____1____IF__P0__DEALLOC_RETURN: {
		// Rd = add (Rs, #-1) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS____1____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Rs, #-1) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS___1____DEALLOC_RETURN: {
		// Rd = add (Rs, #1) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS___1____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = add (Rs, #1) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS___1____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Rs, #1) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS___1____IF__P0__DEALLOC_RETURN: {
		// Rd = add (Rs, #1) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__RS___1____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Rs, #1) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__SP___U6_2____DEALLOC_RETURN: {
		// Rd = add (Sp, #u6:2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__SP___U6_2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = add (Sp, #u6:2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__SP___U6_2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Sp, #u6:2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__SP___U6_2____IF__P0__DEALLOC_RETURN: {
		// Rd = add (Sp, #u6:2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ADD__SP___U6_2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = add (Sp, #u6:2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___1____DEALLOC_RETURN: {
		// Rd = and (Rs, #1) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___1____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = and (Rs, #1) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___1____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = and (Rs, #1) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___1____IF__P0__DEALLOC_RETURN: {
		// Rd = and (Rs, #1) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___1____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = and (Rs, #1) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___255____DEALLOC_RETURN: {
		// Rd = and (Rs, #255) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___255____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = and (Rs, #255) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___255____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = and (Rs, #255) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___255____IF__P0__DEALLOC_RETURN: {
		// Rd = and (Rs, #255) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___AND__RS___255____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = and (Rs, #255) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMB__RS____U3_0____DEALLOC_RETURN: {
		// Rd = memb (Rs + #u3:0) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMB__RS____U3_0____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memb (Rs + #u3:0) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMB__RS____U3_0____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memb (Rs + #u3:0) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMB__RS____U3_0____IF__P0__DEALLOC_RETURN: {
		// Rd = memb (Rs + #u3:0) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMB__RS____U3_0____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memb (Rs + #u3:0) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMH__RS____U3_1____DEALLOC_RETURN: {
		// Rd = memh (Rs + #u3:1) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMH__RS____U3_1____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memh (Rs + #u3:1) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMH__RS____U3_1____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memh (Rs + #u3:1) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMH__RS____U3_1____IF__P0__DEALLOC_RETURN: {
		// Rd = memh (Rs + #u3:1) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMH__RS____U3_1____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memh (Rs + #u3:1) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUB__RS____U4_0____DEALLOC_RETURN: {
		// Rd = memub (Rs + #u4:0) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUB__RS____U4_0____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memub (Rs + #u4:0) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUB__RS____U4_0____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memub (Rs + #u4:0) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUB__RS____U4_0____IF__P0__DEALLOC_RETURN: {
		// Rd = memub (Rs + #u4:0) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUB__RS____U4_0____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memub (Rs + #u4:0) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUH__RS____U3_1____DEALLOC_RETURN: {
		// Rd = memuh (Rs + #u3:1) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUH__RS____U3_1____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memuh (Rs + #u3:1) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUH__RS____U3_1____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memuh (Rs + #u3:1) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUH__RS____U3_1____IF__P0__DEALLOC_RETURN: {
		// Rd = memuh (Rs + #u3:1) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMUH__RS____U3_1____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memuh (Rs + #u3:1) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__RS____U4_2____DEALLOC_RETURN: {
		// Rd = memw (Rs + #u4:2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__RS____U4_2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memw (Rs + #u4:2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__RS____U4_2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memw (Rs + #u4:2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__RS____U4_2____IF__P0__DEALLOC_RETURN: {
		// Rd = memw (Rs + #u4:2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__RS____U4_2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memw (Rs + #u4:2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__SP____U5_2____DEALLOC_RETURN: {
		// Rd = memw (Sp + #u5:2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__SP____U5_2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = memw (Sp + #u5:2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__SP____U5_2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memw (Sp + #u5:2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__SP____U5_2____IF__P0__DEALLOC_RETURN: {
		// Rd = memw (Sp + #u5:2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___MEMW__SP____U5_2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = memw (Sp + #u5:2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTB__RS____DEALLOC_RETURN: {
		// Rd = sxtb (Rs) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTB__RS____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = sxtb (Rs) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTB__RS____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = sxtb (Rs) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTB__RS____IF__P0__DEALLOC_RETURN: {
		// Rd = sxtb (Rs) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTB__RS____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = sxtb (Rs) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTH__RS____DEALLOC_RETURN: {
		// Rd = sxth (Rs) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTH__RS____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = sxth (Rs) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTH__RS____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = sxth (Rs) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTH__RS____IF__P0__DEALLOC_RETURN: {
		// Rd = sxth (Rs) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___SXTH__RS____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = sxth (Rs) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ZXTH__RS____DEALLOC_RETURN: {
		// Rd = zxth (Rs) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ZXTH__RS____IF___NOT__P0__DEALLOC_RETURN: {
		// Rd = zxth (Rs) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ZXTH__RS____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = zxth (Rs) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ZXTH__RS____IF__P0__DEALLOC_RETURN: {
		// Rd = zxth (Rs) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RD___ZXTH__RS____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rd = zxth (Rs) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0___U2____DEALLOC_RETURN: {
		// Rdd = combine (#0, #u2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0___U2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (#0, #u2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0___U2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#0, #u2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0___U2____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (#0, #u2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0___U2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#0, #u2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0__RS____DEALLOC_RETURN: {
		// Rdd = combine (#0, Rs) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0__RS____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (#0, Rs) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0__RS____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#0, Rs) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0__RS____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (#0, Rs) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___0__RS____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#0, Rs) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___1___U2____DEALLOC_RETURN: {
		// Rdd = combine (#1, #u2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___1___U2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (#1, #u2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___1___U2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#1, #u2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___1___U2____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (#1, #u2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___1___U2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#1, #u2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___2___U2____DEALLOC_RETURN: {
		// Rdd = combine (#2, #u2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___2___U2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (#2, #u2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___2___U2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#2, #u2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___2___U2____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (#2, #u2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___2___U2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#2, #u2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___3___U2____DEALLOC_RETURN: {
		// Rdd = combine (#3, #u2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___3___U2____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (#3, #u2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___3___U2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#3, #u2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___3___U2____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (#3, #u2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE___3___U2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (#3, #u2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE__RS___0____DEALLOC_RETURN: {
		// Rdd = combine (Rs, #0) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE__RS___0____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = combine (Rs, #0) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE__RS___0____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (Rs, #0) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE__RS___0____IF__P0__DEALLOC_RETURN: {
		// Rdd = combine (Rs, #0) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___COMBINE__RS___0____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = combine (Rs, #0) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___MEMD__SP____U5_3____DEALLOC_RETURN: {
		// Rdd = memd (Sp + #u5:3) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___MEMD__SP____U5_3____IF___NOT__P0__DEALLOC_RETURN: {
		// Rdd = memd (Sp + #u5:3) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___MEMD__SP____U5_3____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = memd (Sp + #u5:3) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___MEMD__SP____U5_3____IF__P0__DEALLOC_RETURN: {
		// Rdd = memd (Sp + #u5:3) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RDD___MEMD__SP____U5_3____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rdd = memd (Sp + #u5:3) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RS__RX____DEALLOC_RETURN: {
		// Rx = add (Rs, Rx) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RS__RX____IF___NOT__P0__DEALLOC_RETURN: {
		// Rx = add (Rs, Rx) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RS__RX____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rs, Rx) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RS__RX____IF__P0__DEALLOC_RETURN: {
		// Rx = add (Rs, Rx) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RS__RX____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rs, Rx) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX___S7____DEALLOC_RETURN: {
		// Rx = add (Rx, #s7) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX___S7____IF___NOT__P0__DEALLOC_RETURN: {
		// Rx = add (Rx, #s7) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX___S7____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rx, #s7) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX___S7____IF__P0__DEALLOC_RETURN: {
		// Rx = add (Rx, #s7) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX___S7____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rx, #s7) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX__RS____DEALLOC_RETURN: {
		// Rx = add (Rx, Rs) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX__RS____IF___NOT__P0__DEALLOC_RETURN: {
		// Rx = add (Rx, Rs) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX__RS____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rx, Rs) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX__RS____IF__P0__DEALLOC_RETURN: {
		// Rx = add (Rx, Rs) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_RX___ADD__RX__RS____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// Rx = add (Rx, Rs) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0__RD____0___DEALLOC_RETURN: {
		// if (! p0) Rd = #0 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0__RD____0___IF___NOT__P0__DEALLOC_RETURN: {
		// if (! p0) Rd = #0 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0__RD____0___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// if (! p0) Rd = #0 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0__RD____0___IF__P0__DEALLOC_RETURN: {
		// if (! p0) Rd = #0 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0__RD____0___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// if (! p0) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0_NEW__RD____0___DEALLOC_RETURN: {
		// if (! p0.new) Rd = #0 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0_NEW__RD____0___IF___NOT__P0__DEALLOC_RETURN: {
		// if (! p0.new) Rd = #0 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0_NEW__RD____0___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// if (! p0.new) Rd = #0 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0_NEW__RD____0___IF__P0__DEALLOC_RETURN: {
		// if (! p0.new) Rd = #0 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF___NOT__P0_NEW__RD____0___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// if (! p0.new) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0__RD____0___DEALLOC_RETURN: {
		// if (p0) Rd = #0 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0__RD____0___IF___NOT__P0__DEALLOC_RETURN: {
		// if (p0) Rd = #0 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0__RD____0___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// if (p0) Rd = #0 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0__RD____0___IF__P0__DEALLOC_RETURN: {
		// if (p0) Rd = #0 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0__RD____0___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// if (p0) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0_NEW__RD____0___DEALLOC_RETURN: {
		// if (p0.new) Rd = #0 ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0_NEW__RD____0___IF___NOT__P0__DEALLOC_RETURN: {
		// if (p0.new) Rd = #0 ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0_NEW__RD____0___IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// if (p0.new) Rd = #0 ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0_NEW__RD____0___IF__P0__DEALLOC_RETURN: {
		// if (p0.new) Rd = #0 ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_IF__P0_NEW__RD____0___IF__P0_NEW__DEALLOC_RETURN_NT: {
		// if (p0.new) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_P0___CMP_EQ__RS___U2____DEALLOC_RETURN: {
		// p0 = cmp.eq (Rs, #u2) ; dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_P0___CMP_EQ__RS___U2____IF___NOT__P0__DEALLOC_RETURN: {
		// p0 = cmp.eq (Rs, #u2) ; if (! p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_P0___CMP_EQ__RS___U2____IF___NOT__P0_NEW__DEALLOC_RETURN_NT: {
		// p0 = cmp.eq (Rs, #u2) ; if (! p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_P0___CMP_EQ__RS___U2____IF__P0__DEALLOC_RETURN: {
		// p0 = cmp.eq (Rs, #u2) ; if (p0) dealloc_return
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	case HEX_INS_DUPLEX_P0___CMP_EQ__RS___U2____IF__P0_NEW__DEALLOC_RETURN_NT: {
		// p0 = cmp.eq (Rs, #u2) ; if (p0.new) dealloc_return:nt
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
	}
	return op->size;
}
