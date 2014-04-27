/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <arm.h>

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode = (a->bits==16)? CS_MODE_THUMB: CS_MODE_ARM;
	int n, ret = (a->bits==64)?
		cs_open (CS_ARCH_ARM64, mode, &handle):
		cs_open (CS_ARCH_ARM, mode, &handle);
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	if (ret == CS_ERR_OK) {
		n = cs_disasm_ex (handle, (ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
			switch (insn->id) {
			case ARM_INS_ADD:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case ARM_INS_TST:
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			case ARM_INS_ROR:
			case ARM_INS_ORN:
			case ARM_INS_LSL:
			case ARM_INS_LSR:
				break;
			case ARM_INS_PUSH:
			case ARM_INS_STR:
			case ARM_INS_POP:
			case ARM_INS_LDR:
				break;
			case ARM_INS_BL:
			case ARM_INS_BLX:
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case ARM_INS_B:
			case ARM_INS_BX:
			case ARM_INS_BXJ:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = 0;
				break;
			}
			cs_free (insn, n);
		}
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
