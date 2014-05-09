/* 
 * radare2 - LGPL - Copyright 2013-2014 - pancake 
 * fixes by nanomad
 */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <arm.h>

/*
 * Returns the postion of register @reg in @insn. 
 * Returns -1 if not found
 */
static int op_get_arm_reg_pos(cs_arm * arm, arm_reg reg) {
    int i = 0;
    if(arm) {
        for(i = 0; i< arm->op_count; ++i) {
            if(arm->operands[i].type == ARM_OP_REG && arm->operands[i].reg == reg) {
                return i;
            }
        }
    }
    return -1;
}

void parse_insn_cond(cs_insn * insn, RAnalOp *op) {
    if(insn->detail) {
        cs_arm *arm = &(insn->detail->arm);
        switch(arm->cc) {
        case ARM_CC_EQ:
            op->cond = R_ANAL_COND_EQ;
            break;
        case ARM_CC_NE:
            op->cond = R_ANAL_COND_NE;
            break;
        case ARM_CC_GE:
            op->cond = R_ANAL_COND_GE;
            break;
        case ARM_CC_LT:
            op->cond = R_ANAL_COND_LT;
            break;
        case ARM_CC_GT:
            op->cond = R_ANAL_COND_GT;
            break;
        case ARM_CC_LE:
            op->cond = R_ANAL_COND_LE;
            break;
        case ARM_CC_AL:
            op->cond = R_ANAL_COND_AL;
            break;
        default:
            break;
        }
    }
    op->fail = insn->address + 4;
}

static void parse_call_jump_dest(cs_insn* insn, RAnalOp* op) {
    if(insn->detail) {
        cs_arm *arm = &(insn->detail->arm);
        if(arm->op_count == 1) {
            cs_arm_op *arm_op = &(arm->operands[0]);
            switch(arm_op->type) {
                case ARM_OP_IMM:
                    op->jump = arm_op->imm;
                    break;
                case ARM_OP_REG:
                    /* BX LR and similar */
                    op->type = (arm_op->reg == ARM_REG_LR) ? R_ANAL_OP_TYPE_RET : op->type;
                    break;
                default:
                    break;
            }
        }
    }
}

static void parse_stack_op(cs_insn* insn, RAnalOp* op, unsigned isAdd) {
    if(insn->detail) {
        cs_arm * arm = &(insn->detail->arm);
        // (ADD)|(SUB) SP, SP, #imm
        if(arm->op_count == 3 && 
            arm->operands[0].type == ARM_OP_REG &&
            arm->operands[0].reg == ARM_REG_SP && 
            arm->operands[1].type == ARM_OP_REG && 
            arm->operands[1].reg == ARM_REG_SP && 
            arm->operands[2].type == ARM_OP_IMM
        ) {
            op->stackop = R_ANAL_STACK_INC;
            op->val = (arm->operands[2].imm);
            if(isAdd) {
                op->val = -(op->val);
            }
        }
        
    }
}

static void parse_possible_pop_return(cs_insn* insn, RAnalOp* op) {
    if(insn->detail) {
        cs_arm * arm = &(insn->detail->arm);
        int pos = op_get_arm_reg_pos(arm, ARM_REG_PC);
        /* POP(r...,pc) and similar */
        if(pos >= 0) {
            op->type = R_ANAL_OP_TYPE_RET;
        }
    }
}

static void parse_possible_implict_jump(cs_insn* insn, RAnalOp* op) {
    if(insn->detail) {
        cs_arm * arm = &(insn->detail->arm);
        int pos = op_get_arm_reg_pos(arm, ARM_REG_PC);
        if(pos == 0 && arm->op_count == 2) {
            // MOV/LDR PC, #ARM_OP_IMM
            if(arm->operands[1].type == ARM_OP_IMM) {
                op->jump = arm->operands[1].imm;
                op->type == R_ANAL_OP_TYPE_JMP;
                op->eob = 1;
            } else if(arm->operands[1].type == ARM_OP_MEM) {
                unsigned int base = arm->operands[1].mem.base;
                if(base == ARM_REG_PC) {
                    // TODO: MOV/LDR PC, [PC, #offset]
                    //int offset = (arm->operands[1].mem.disp) * (arm->operands[1].mem.scale);
                    op->type == R_ANAL_OP_TYPE_JMP;
                    op->eob = 1;
                    // op->jump = *(op->ptr);
                }
            } else if(arm->operands[1].type == ARM_OP_REG && arm->operands[1].reg == ARM_REG_LR) {
                op->type = R_ANAL_OP_TYPE_RET;
            }
        }
    }
}

static void parse_memory_access(cs_insn* insn, RAnalOp* op) {
    if(insn->detail) {
        cs_arm * arm = &(insn->detail->arm);
        int i = 0;
        for(i=0; i<arm->op_count; ++i) {
            if(arm->operands[i].type == ARM_OP_MEM) {
                arm_op_mem *opmem = &(arm->operands[i].mem);
                if(opmem->base == ARM_REG_PC) {
                    unsigned int base = insn->address;
                    unsigned int offset = opmem->disp;
                    int dir = opmem->scale;
                    op->type = R_ANAL_OP_TYPE_LOAD;
                    op->ptr = base + (offset * dir) + (insn->size == 4 ? 8 : 4);
                } else if(!opmem->base) {
                    op->type = R_ANAL_OP_TYPE_LOAD;
                    op->ptr = opmem->disp;
                }
                return;
            }
        }
    }
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
    int n = 0;
	int mode = (a->bits==16)? CS_MODE_THUMB : CS_MODE_ARM;
    int arch = (a->bits==64)? CS_ARCH_ARM64 : CS_ARCH_ARM;
    cs_err ret =  cs_open (arch, mode, &handle);
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = (a->bits == 16) ? 2 : 4;
	if (ret == CS_ERR_OK) {
		n = cs_disasm_ex (handle, (ut8*)buf, len, addr, 1, &insn);
		if (n<1 || !insn->id) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
            parse_insn_cond(insn, op);
            parse_memory_access(insn, op);
            switch (insn->id) {
			case ARM_INS_ADD:
				op->type = R_ANAL_OP_TYPE_ADD;
                parse_stack_op(insn, op, 1);
				break;
            case ARM_INS_SUB:
                op->type = R_ANAL_OP_TYPE_SUB;
                parse_stack_op(insn, op, 0);
                break;
			case ARM_INS_TST:
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			case ARM_INS_ROR:
                op->type = R_ANAL_OP_TYPE_ROR;
                break;
			case ARM_INS_LSL:
                op->type = R_ANAL_OP_TYPE_SHL;
                break;
			case ARM_INS_LSR:
                op->type = R_ANAL_OP_TYPE_SHR;
				break;
            case ARM_INS_PUSH:
                break;
            case ARM_INS_POP:
                parse_possible_pop_return(insn, op);
                break;
			case ARM_INS_STR:
                op->type = R_ANAL_OP_TYPE_STORE;
                break;
			case ARM_INS_LDR:
                op->type = R_ANAL_OP_TYPE_LOAD;
                parse_possible_implict_jump(insn, op);
				break;
			case ARM_INS_BL:
			case ARM_INS_BLX:
				op->type = R_ANAL_OP_TYPE_CALL;
                parse_call_jump_dest(insn, op);
				break;
			case ARM_INS_B:
			case ARM_INS_BX:
			case ARM_INS_BXJ:
				op->type = R_ANAL_OP_TYPE_JMP;
                op->eob = 1;
                parse_call_jump_dest(insn, op);
				break;
            case ARM_INS_MOV:
                op->type = R_ANAL_OP_TYPE_MOV;
                parse_possible_implict_jump(insn, op);
			}
		}
        cs_free (insn, n);
	}
	cs_close (&handle);
	return op->size;
}

RAnalPlugin r_anal_plugin_arm_cs = {
	.name = "arm.cs",
	.desc = "Capstone ARM analyzer",
	.license = "BSD",
	.arch = R_SYS_ARCH_ARM,
	.bits = 16|32|64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm_cs
};
#endif
