/* radare2 - LGPL - Copyright 2017 - xvilka */
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/wasm/wasm.h"
#include "../../bin/format/wasm/wasm.h"

ut64 cf_stack [128] = { 0 };
int cf_stack_ptr = 0;

static ut64 get_cf_offset(RAnal *anal, const ut8 *data)
{
	char flgname[64] = {0};
	st32 n;
	read_i32_leb128 (data, data + 1, &n);
	sprintf(flgname, "fcn.%d", n);
	RFlagItem *fi = anal->flb.get (anal->flb.f, flgname);
	if (fi) return fi->offset;
	return (ut64)-1;
}

static int wasm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	WasmOp wop = {0};

	memset (op, '\0', sizeof (RAnalOp));
	int ret = wasm_dis (&wop, data, len);
	op->size = ret;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->id = wop.op;
	switch (wop.op) {
	/* Calls here are using index instead of address */
	case WASM_OP_BLOCK:
		cf_stack_ptr++;
		break;
	case WASM_OP_CALL:
	case WASM_OP_CALLINDIRECT:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = get_cf_offset (anal, data);
		break;
	case WASM_OP_BR:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = get_cf_offset (anal, data);
		break;
	case WASM_OP_BRIF:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = get_cf_offset (anal, data);
		break;
	default:
		break;
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.op = &wasm_op,
	.esil = false,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_wasm,
	.version = R2_VERSION
};
#endif
