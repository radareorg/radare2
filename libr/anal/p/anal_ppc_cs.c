/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <ppc.h>

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32: 0;
	mode = CS_MODE_BIG_ENDIAN;
	int n, ret = cs_open (CS_ARCH_PPC, mode, &handle);
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 4;
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
		n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn->size;
			switch (insn->id) {
			case PPC_INS_LI:
			case PPC_INS_LIS:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case PPC_INS_SC:
				op->type = R_ANAL_OP_TYPE_SWI;
				break;
			case PPC_INS_NOP:
				op->type = R_ANAL_OP_TYPE_NOP;
				break;
			case PPC_INS_STW:
			case PPC_INS_STWBRX:
			case PPC_INS_STWCX:
			case PPC_INS_STWU:
			case PPC_INS_STWUX:
			case PPC_INS_STWX:
				op->type = R_ANAL_OP_TYPE_STORE;
				break;
			case PPC_INS_LA:
			case PPC_INS_LBZ:
			case PPC_INS_LBZU:
			case PPC_INS_LBZUX:
			case PPC_INS_LBZX:
			case PPC_INS_LD:
			case PPC_INS_LDARX:
			case PPC_INS_LDBRX:
			case PPC_INS_LDU:
			case PPC_INS_LDUX:
			case PPC_INS_LDX:
			case PPC_INS_LFD:
			case PPC_INS_LFDU:
			case PPC_INS_LFDUX:
			case PPC_INS_LFDX:
			case PPC_INS_LFIWAX:
			case PPC_INS_LFIWZX:
			case PPC_INS_LFS:
			case PPC_INS_LFSU:
			case PPC_INS_LFSUX:
			case PPC_INS_LFSX:
			case PPC_INS_LHA:
			case PPC_INS_LHAU:
			case PPC_INS_LHAUX:
			case PPC_INS_LHAX:
			case PPC_INS_LHBRX:
			case PPC_INS_LHZ:
			case PPC_INS_LHZU:
			case PPC_INS_LWA:
			case PPC_INS_LWARX:
			case PPC_INS_LWAUX:
			case PPC_INS_LWAX:
			case PPC_INS_LWBRX:
			case PPC_INS_LWZ:
			case PPC_INS_LWZU:
			case PPC_INS_LWZUX:
			case PPC_INS_LWZX:

				op->type = R_ANAL_OP_TYPE_LOAD;
				break;
			case PPC_INS_ADD:
			case PPC_INS_ADDI:
			case PPC_INS_ADDC:
			case PPC_INS_ADDE:
			case PPC_INS_ADDIC:
			case PPC_INS_ADDIS:
			case PPC_INS_ADDME:
			case PPC_INS_ADDZE:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case PPC_INS_B:
			case PPC_INS_BA:
			case PPC_INS_BC:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = insn->detail->ppc.operands[0].imm;
				switch (insn->detail->ppc.operands[0].type) {
				case PPC_OP_CRX:
					op->type = R_ANAL_OP_TYPE_CJMP;
					op->jump = insn->detail->ppc.operands[1].imm;
					op->fail = addr+4;
					break;
				case PPC_OP_REG:
					op->type = R_ANAL_OP_TYPE_CJMP;
					op->jump = insn->detail->ppc.operands[1].imm;
					op->fail = addr+4;
					//op->type = R_ANAL_OP_TYPE_UJMP;
				default:
					break;
				}
				break;
			case PPC_INS_XOR:
			case PPC_INS_XORI:
			case PPC_INS_XORIS:
				op->type = R_ANAL_OP_TYPE_XOR;
				break;
			case PPC_INS_DIVD:
			case PPC_INS_DIVDU:
			case PPC_INS_DIVW:
			case PPC_INS_DIVWU:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case PPC_INS_BL:
			case PPC_INS_BLA:
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case PPC_INS_BLR:
			case PPC_INS_BLRL:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case PPC_INS_AND:
			case PPC_INS_NAND:
			case PPC_INS_ANDI:
			case PPC_INS_ANDIS:
				op->type = R_ANAL_OP_TYPE_AND;
				break;
			case PPC_INS_OR:
			case PPC_INS_ORC:
			case PPC_INS_ORI:
			case PPC_INS_ORIS:
				op->type = R_ANAL_OP_TYPE_OR;
				break;
			}
			cs_free (insn, n);
		}
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC analysis",
	.license = "BSD",
	.arch = R_SYS_ARCH_PPC,
	.bits = 32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ppc_cs
};
#endif
