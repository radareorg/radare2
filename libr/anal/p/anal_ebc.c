/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <ebc_disas.h>

static void ebc_anal_jmp8(RAnalOp *op, ut64 addr, const ut8 *buf)
{
	int jmpadr = (int8_t)buf[1];
	op->jump = addr + 2 + (jmpadr * 2);
	op->addr = addr;
	op->fail = addr + 2;

	if (TEST_BIT(buf[0], 7)) {
		op->type = R_ANAL_OP_TYPE_CJMP;
	} else {
		op->type = R_ANAL_OP_TYPE_JMP;
	}
}

static void ebc_anal_jmp(RAnalOp *op, ut64 addr, const ut8 *buf)
{
	int32_t jmpaddr;
	jmpaddr = *(int32_t*)(buf + 2);
	op->fail = addr + 6;

	if (TEST_BIT(buf[1], 4)) {
		op->jump = addr + 6 + jmpaddr;
	} else {
		op->jump = jmpaddr;
	}

	if (buf[1] & 0x7) {
		op->type = R_ANAL_OP_TYPE_UJMP;
	} else {
		if (TEST_BIT(buf[1], 7)) {
			op->type = R_ANAL_OP_TYPE_CJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
		}
	}
}

static void ebc_anal_call(RAnalOp *op, ut64 addr, const ut8 *buf)
{
	int32_t addr_call;

	op->fail = addr + 6;
	if ((buf[1] & 0x7) == 0 && TEST_BIT(buf[0], 6) == 0
			&& TEST_BIT(buf[0], 7)) {
		addr_call = *(int32_t*)(buf + 2);

		if (TEST_BIT(buf[1], 4)) {
			op->jump = (addr + 6 + addr_call);
		} else {
			op->jump = addr_call;
		}
		op->type = R_ANAL_OP_TYPE_CALL;
	} else {
		op->type = R_ANAL_OP_TYPE_UCALL;
	}
}

static int ebc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int ret;
	ebc_command_t cmd;
	ut8 opcode = buf[0] & EBC_OPCODE_MASK;

	if (op == NULL)
		return 2;

	memset(op, 0, sizeof (RAnalOp));
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	ret = op->size = ebc_decode_command(buf, &cmd);

	if (ret < 0)
		return ret;

	switch (opcode) {
		case EBC_JMP8:
			ebc_anal_jmp8(op, addr, buf);
			break;
		case EBC_JMP:
			ebc_anal_jmp(op, addr, buf);
			break;
		case EBC_MOVBW:
		case EBC_MOVWW:
		case EBC_MOVDW:
		case EBC_MOVQW:
		case EBC_MOVBD:
		case EBC_MOVWD:
		case EBC_MOVDD:
		case EBC_MOVQD:
		case EBC_MOVSNW:
		case EBC_MOVSND:
		case EBC_MOVQQ:
		case EBC_MOVNW:
		case EBC_MOVND:
		case EBC_MOVI:
		case EBC_MOVIN:
		case EBC_MOVREL:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case EBC_RET:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case EBC_CMPEQ:
		case EBC_CMPLTE:
		case EBC_CMPGTE:
		case EBC_CMPULTE:
		case EBC_CMPUGTE:
		case EBC_CMPIEQ:
		case EBC_CMPILTE:
		case EBC_CMPIGTE:
		case EBC_CMPIULTE:
		case EBC_CMPIUGTE:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case EBC_SHR:
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case EBC_SHL:
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case EBC_OR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case EBC_XOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case EBC_MUL:
			op->type = R_ANAL_OP_TYPE_MUL;
			break;
		case EBC_PUSH:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case EBC_POP:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case EBC_AND:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case EBC_ADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case EBC_SUB:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case EBC_NEG:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case EBC_CALL:
			ebc_anal_call(op, addr, buf);
			break;
		case EBC_BREAK:
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_UNK;
			break;
	}

	return ret;
}

struct r_anal_plugin_t r_anal_plugin_ebc = {
	.name = "ebc",
	.desc = "EBC code analysis plugin",
	.license = "LGPL3",
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
