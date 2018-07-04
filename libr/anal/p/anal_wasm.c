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
WasmOpCodes op_old = 0;

static ut64 get_cf_offset(RAnal *anal, const ut8 *data) {
	char flgname[64] = {0};
	snprintf(flgname, sizeof (flgname), "sym.fnc.%d", data[1]);
	RFlagItem *fi = anal->flb.get (anal->flb.f, flgname);
	if (fi) {
		return fi->offset;
	}
	return UT64_MAX;
}

static ut64 find_if_else(ut64 addr, const ut8 *data, int len) {
	WasmOp wop = {0};
	st32 count = 0;
	ut32 offset = addr;
	while (len > 0) {
		wasm_dis (&wop, data, len);
		switch (wop.op) {
		/* Calls here are using index instead of address */
		case WASM_OP_IF:
			count++;
			break;
		case WASM_OP_ELSE:
			if (!count) {
				return offset + 2;
			}
			break;
		case WASM_OP_END:
			if (!count) {
				return offset;
			} else {
				count--;
			}
			break;
		default:
			break;
		}
		offset++;
		data++;
		len--;
	}
	return UT64_MAX;
}

static int wasm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	WasmOp wop = {0};
	memset (op, '\0', sizeof (RAnalOp));
	int ret = wasm_dis (&wop, data, len);
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = ret;
	op->addr = addr;
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->id = wop.op;

	if (!strncmp(wop.txt, "invalid", 7)) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	} else {
		switch (wop.op) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = find_if_else (addr + 1, data + op->size, len - op->size);
			op->fail = addr + op->size;
			break;
		case WASM_OP_IF:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = find_if_else (addr + 1, data + op->size, len - op->size);
			op->fail = addr + op->size;
			break;
		case WASM_OP_ELSE:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = find_if_else (addr + 1, data + op->size, len - op->size);
			break;
		case WASM_OP_END:
			if (op_old == WASM_OP_CALL || op_old == WASM_OP_CALLINDIRECT || op_old == WASM_OP_RETURN) {
				op->eob = true;
			}
			break;
		case WASM_OP_GETLOCAL:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case WASM_OP_SETLOCAL:
		case WASM_OP_TEELOCAL:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case WASM_OP_I32EQZ:
		case WASM_OP_I32EQ:
		case WASM_OP_I32NE:
		case WASM_OP_I32LTS:
		case WASM_OP_I32LTU:
		case WASM_OP_I32GTS:
		case WASM_OP_I32GTU:
		case WASM_OP_I32LES:
		case WASM_OP_I32LEU:
		case WASM_OP_I32GES:
		case WASM_OP_I32GEU:
		case WASM_OP_I64EQZ:
		case WASM_OP_I64EQ:
		case WASM_OP_I64NE:
		case WASM_OP_I64LTS:
		case WASM_OP_I64LTU:
		case WASM_OP_I64GTS:
		case WASM_OP_I64GTU:
		case WASM_OP_I64LES:
		case WASM_OP_I64LEU:
		case WASM_OP_I64GES:
		case WASM_OP_I64GEU:
		case WASM_OP_F32EQ:
		case WASM_OP_F32NE:
		case WASM_OP_F32LT:
		case WASM_OP_F32GT:
		case WASM_OP_F32LE:
		case WASM_OP_F32GE:
		case WASM_OP_F64EQ:
		case WASM_OP_F64NE:
		case WASM_OP_F64LT:
		case WASM_OP_F64GT:
		case WASM_OP_F64LE:
		case WASM_OP_F64GE:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case WASM_OP_BLOCK:
			cf_stack_ptr++;
			break;
		case WASM_OP_CALL:
		case WASM_OP_CALLINDIRECT:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = get_cf_offset (anal, data);
			op->fail = addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			break;
		case WASM_OP_BR:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = get_cf_offset (anal, data);
			op->fail = addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			break;
		case WASM_OP_BRIF:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = get_cf_offset (anal, data);
			op->fail = addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			break;
		case WASM_OP_RETURN:
			op->type = R_ANAL_OP_TYPE_CRET;
			if (find_if_else (addr + 1, data + op->size, len - op->size) == (addr + 1)) {
				op->type = R_ANAL_OP_TYPE_RET;
			}
		default:
			break;
		}
		op_old = wop.op;
	}
	return op->size;
}

static int archinfo(RAnal *a, int q) {
	return 1;
}

RAnalPlugin r_anal_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.archinfo = archinfo,
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
