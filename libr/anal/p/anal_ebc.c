/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <ebc_disas.h>

static int ebc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int ret;
	ebc_command_t cmd;
	ut8 opcode = buf[0] & EBC_OPCODE_MASK;

	if (op == NULL)
		return 2;

	ret = op->length = ebc_decode_command(buf, &cmd);

	if (ret < 0)
		return ret;

	if (opcode == EBC_JMP || opcode == EBC_JMP8) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_JMP;

		if (opcode == EBC_JMP8) {
			unsigned jmpadr = buf[1];
			op->jump = addr + 2 + (jmpadr * 2);
			op->fail = addr + (jmpadr * 2);
		}
	} else if ((opcode >= EBC_MOVBW && opcode <= EBC_MOVSND) ||
			opcode == EBC_MOVQQ || opcode == EBC_MOVNW ||
			opcode == EBC_MOVND || opcode == EBC_MOVREL ||
			opcode == EBC_MOVI || opcode == EBC_MOVIN ||
			opcode == EBC_EXTNDB || opcode == EBC_EXTNDW ||
			opcode == EBC_EXTNDD) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (opcode == EBC_RET) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if ((opcode >= EBC_CMPEQ && opcode <= EBC_CMPUGTE) ||
			(opcode >= EBC_CMPIEQ && opcode <= EBC_CMPIUGTE)) {
		op->type = R_ANAL_OP_TYPE_CMP;
	} else if (opcode == EBC_SHR) {
		op->type = R_ANAL_OP_TYPE_SHR;
	} else if (opcode == EBC_SHL) {
		op->type = R_ANAL_OP_TYPE_SHL;
	} else if (opcode == EBC_OR) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if (opcode == EBC_XOR) {
		op->type = R_ANAL_OP_TYPE_XOR;
	} else if (opcode == EBC_MUL) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if (opcode == EBC_PUSH) {
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (opcode == EBC_POP) {
		op->type = R_ANAL_OP_TYPE_POP;
	} else if (opcode == EBC_AND) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if (opcode == EBC_ADD) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if (opcode == EBC_SUB) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (opcode == EBC_NEG) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (opcode == EBC_CALL) {
		int32_t addr_call;

		if ((buf[1] & 0x7) == 0 && TEST_BIT(buf[0], 6) == 0) {
			addr_call = *(int32_t*)(buf + 2);

			if (TEST_BIT(buf[1], 4)) {
				op->jump = (addr + 6 + addr_call);
			} else {
				op->jump = addr_call;
			}
		}
		op->type = R_ANAL_OP_TYPE_UCALL;

	} else if (opcode == EBC_RET) {
		op->type = R_ANAL_OP_TYPE_LEAVE;
	} else if (opcode == EBC_BREAK) {
		op->type = R_ANAL_OP_TYPE_SWI;
	} else op->type = R_ANAL_OP_TYPE_UNK;

	return ret;
}

struct r_anal_plugin_t r_anal_plugin_ebc = {
	.name = "ebc",
	.desc = "EBC code analysis plugin",
	.arch = R_SYS_ARCH_EBC,
	.bits = 64,
	.init = NULL,
	.fini = NULL,
	.op = &ebc_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ebc
};
#endif
