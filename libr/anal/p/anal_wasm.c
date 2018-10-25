/* radare2 - LGPL - Copyright 2017 - xvilka */
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/wasm/wasm.h"
#include "../../bin/format/wasm/wasm.h"

#define WASM_STACK_SIZE 256
#define WASM_END_SIZE (1)

static struct wasm_stack_t {
	ut64 loop;
	ut64 end;
	int size;
} wasm_stack [WASM_STACK_SIZE];
int wasm_stack_ptr = 0;
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


static ut64 find_if_else(ut64 addr, const ut8 *data, int len, bool is_loop) {
	WasmOp wop = {0};
	st32 count = 0;
	ut32 offset = addr;
	while (len > 0) {
		int ret = wasm_dis (&wop, data, len);
		switch (wop.op) {
		/* Calls here are using index instead of address */
		case WASM_OP_BLOCK:
			count++;
			break;
		case WASM_OP_LOOP:
			count++;
			break;
		case WASM_OP_IF:
			count++;
			break;
		case WASM_OP_ELSE:
			if (!count && !is_loop) {
				return offset + ret;
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
		offset += ret;
		data += ret;
		len -= ret;
	}
	return UT64_MAX;
}

static void set_br_jump(RAnalOp *op, const ut8 *data) {
	ut32 pos = wasm_stack_ptr - *(data  + 1);
	if (pos < wasm_stack_ptr) {
		ut64 jump = wasm_stack[pos].end;
		if (jump != UT64_MAX) {
			op->jump = jump + 1; // always pointing to an 'end'
		}
	}
}

static int wasm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut64 addr2 = UT64_MAX;
	int i;
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

	if (!strncmp (wop.txt, "invalid", 7)) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}
	if (wasm_stack_ptr >= WASM_STACK_SIZE) {
		op->type = R_ANAL_OP_TYPE_NULL;
		return -1;
	} else {
		switch (wop.op) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
			//op->type = R_ANAL_OP_TYPE_CJMP;
			addr2 = find_if_else (addr + op->size, data + op->size, len - op->size, true);
			if (addr2 != UT64_MAX) {
				wasm_stack[wasm_stack_ptr].loop = addr;
				wasm_stack[wasm_stack_ptr].end = addr2;
				wasm_stack[wasm_stack_ptr].size = wop.len;
				wasm_stack_ptr++;
				addr2 = UT64_MAX;
			}
			//op->fail = addr + op->size;
			break;
		case WASM_OP_BLOCK:
			addr2 = find_if_else (addr + op->size, data + op->size, len - op->size, true);
			if (addr2 != UT64_MAX) {
				wasm_stack[wasm_stack_ptr].loop = UT64_MAX;
				wasm_stack[wasm_stack_ptr].end = addr2;
				wasm_stack[wasm_stack_ptr].size = wop.len;
				wasm_stack_ptr++;
				addr2 = UT64_MAX;
			}
			break;
		case WASM_OP_IF:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = find_if_else (addr + op->size, data + op->size, len - op->size, false);
			op->fail = addr + op->size;
			break;
		case WASM_OP_ELSE:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = find_if_else (addr + op->size, data + op->size, len - op->size, false);
			break;
		case WASM_OP_END:
			if (addr != UT64_MAX) {
				for (i = 0; i < wasm_stack_ptr; ++i) {
					if (wasm_stack[i].end == addr && wasm_stack[i].loop != UT64_MAX) {
						op->type = R_ANAL_OP_TYPE_CJMP;
						op->jump = wasm_stack[i].loop;
						op->fail = addr + op->size;
						break;
					}
				}
			}
			if (op_old == WASM_OP_CALL || op_old == WASM_OP_CALLINDIRECT || op_old == WASM_OP_RETURN) {
				op->eob = true;
				for (i = wasm_stack_ptr - 1; i > 0; --i) {
					if (addr > wasm_stack[i].loop && addr < wasm_stack[i].end) {
						op->eob = false;
						break;
					}
				}
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
		case WASM_OP_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
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
			set_br_jump(op, data);
			break;
		case WASM_OP_BRIF:
			op->fail = addr + op->size;
			op->type = R_ANAL_OP_TYPE_CJMP;
			set_br_jump(op, data);
			break;
		case WASM_OP_RETURN:
			op->type = R_ANAL_OP_TYPE_CRET;
			if (find_if_else (addr + op->size, data + op->size, len - op->size, false) == (addr + 1)) {
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

static int wasm_pre_anal(RAnal *a, struct r_anal_state_type_t *state, ut64 addr) {
	int i;
	for (i = 0; i < WASM_STACK_SIZE; ++i) {
		wasm_stack[i].loop = UT64_MAX;
		wasm_stack[i].end = UT64_MAX;
	}
	wasm_stack_ptr = 0;
	return 1;
}

RAnalPlugin r_anal_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.archinfo = archinfo,
	.pre_anal_fn_cb = wasm_pre_anal,
	.op = &wasm_op,
	.esil = false,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_wasm,
	.version = R2_VERSION
};
#endif
