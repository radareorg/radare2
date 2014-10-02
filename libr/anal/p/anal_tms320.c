/*
 * TMS320 disassembly analizer
 *
 * Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>
 *
 * Distributed under LGPL
 */

#include <r_anal.h>

#include "../../asm/arch/tms320/tms320_dasm.h"

static tms320_dasm_t engine = { 0 };

typedef int (* TMS_ANAL_OP_FN)(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);

int tms320_c54x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55x_plus_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);

static boolt match(const char * str, const char * token) {
	return !strncasecmp(str, token, strlen(token));
}

int tms320_c54x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	// TODO: add the implementation
	return 0;
}

int tms320_c55x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	const char * str = engine.syntax;

	op->delay = 0;
	op->size = tms320_dasm(&engine, buf, len);
	op->type = R_ANAL_OP_TYPE_NULL;

	str = strstr(str, "||") ? str + 3 : str;

	if (match(str, "B ")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		if (match(str, "B AC"))
			op->type = R_ANAL_OP_TYPE_UJMP;
	} else if (match(str, "BCC ") || match(str, "BCCU ")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
	} else if (match(str, "CALL ")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		if (match(str, "CALL AC"))
			op->type = R_ANAL_OP_TYPE_UCALL;
	} else if (match(str, "CALLCC ")) {
		op->type = R_ANAL_OP_TYPE_CCALL;
	} else if (match(str, "RET")) {
		op->type = R_ANAL_OP_TYPE_RET;
		if (match(str, "RETCC"))
			op->type = R_ANAL_OP_TYPE_CRET;
	} else if (match(str, "MOV ")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (match(str, "PSHBOTH ")) {
		op->type = R_ANAL_OP_TYPE_UPUSH;
	} else if (match(str, "PSH ")) {
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (match(str, "POPBOTH ") || match(str, "POP ")) {
		op->type = R_ANAL_OP_TYPE_POP;
	} else if (match(str, "CMP ")) {
		op->type = R_ANAL_OP_TYPE_CMP;
	} else if (match(str, "CMPAND ")) {
		op->type = R_ANAL_OP_TYPE_ACMP;
	} else if (match(str, "NOP")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (match(str, "INTR ")) {
		op->type = R_ANAL_OP_TYPE_SWI;
	} else if (match(str, "TRAP ")) {
		op->type = R_ANAL_OP_TYPE_TRAP;
	} else if (match(str, "INVALID")) {
		op->type = R_ANAL_OP_TYPE_UNK;
	}

	return op->size;
}

int tms320_op(RAnal * anal, RAnalOp * op, ut64 addr, const ut8 * buf, int len) {
	TMS_ANAL_OP_FN aop = tms320_c55x_op;

	if (anal->cpu && strcasecmp(anal->cpu, "c54x") == 0)
		aop = tms320_c54x_op;
	if (anal->cpu && strcasecmp(anal->cpu, "c55x") == 0)
		aop = tms320_c55x_op;
	if (anal->cpu && strcasecmp(anal->cpu, "c55x+") == 0)
		aop = tms320_c55x_plus_op;

	return aop(anal, op, addr, buf, len);
}

static int tms320_init(void * unused) {
	return tms320_dasm_init (&engine);
}

static int tms320_fini(void * unused) {
	return tms320_dasm_fini (&engine);
}

struct r_anal_plugin_t r_anal_plugin_tms320 = {
	.name = "tms320",
	.arch = R_SYS_ARCH_TMS320,
	.bits = 32,
	.desc = "TMS320 DSP family code analisys plugin",
	.init = tms320_init,
	.fini = tms320_fini,
	.license = "LGPLv3",
	.op = &tms320_op,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tms320,
};
#endif
