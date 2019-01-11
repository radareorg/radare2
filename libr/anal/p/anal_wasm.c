/* radare2 - LGPL - Copyright 2017-2018 - xvilka */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#undef R_IPI
#define R_IPI static
#include "../../bin/format/wasm/wasm.h"
#include "../../asm/arch/wasm/wasm.c"

#define WASM_STACK_SIZE 256

static ut64 scope_hint = UT64_MAX; 
static WasmOpCodes op_old = 0;

// finds the address of the call function (essentially where to jump to).
static ut64 get_cf_offset(RAnal *anal, const ut8 *data) {
	r_cons_push ();
	char *s = anal->coreb.cmdstrf (anal->coreb.core, "isq~[0:%d]", data[1]);
	r_cons_pop ();
	if (s) {
		ut64 n = r_num_get (NULL, s);
		free (s);
		return n;
	}
	return UT64_MAX;
}

// analyzes the wasm opcode.
static int wasm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	WasmOp wop = {0};
	RAnalHint *hint = NULL;
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

	if (!wop.txt || !strncmp (wop.txt, "invalid", 7)) {
		op->type = R_ANAL_OP_TYPE_ILL;
		free (wop.txt);
		return -1;
	}
	switch (wop.op) {
	/* Calls here are using index instead of address */
	case WASM_OP_LOOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		scope_hint--;
		r_anal_hint_set_jump (anal, scope_hint, addr);
		r_anal_hint_set_bits (anal, scope_hint, 1);
		eprintf ("[wasm][loop ] 0x%llx 0x%016llx \n", addr, scope_hint);
		break;
	case WASM_OP_BLOCK:
		op->type = R_ANAL_OP_TYPE_NOP;
		scope_hint--;
		r_anal_hint_set_jump (anal, scope_hint, addr);
		r_anal_hint_set_bits (anal, scope_hint, 0);
		eprintf ("[wasm][block] 0x%llx 0x%016llx \n", addr, scope_hint);
		break;
	case WASM_OP_IF:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = addr + op->size;
		scope_hint--;
		r_anal_hint_set_jump (anal, scope_hint, addr);
		r_anal_hint_set_bits (anal, scope_hint, 0);
		if ((hint = r_anal_hint_get (anal, addr)) && hint->jump) {
			op->jump = hint->jump;
			eprintf ("[wasm][if   ] 0x%llx 0x%016llx hint: 0x%llx\n", addr, scope_hint, hint->jump);
		} else {
			eprintf ("[wasm][if   ] 0x%llx 0x%016llx \n", addr, scope_hint);
		}
		break;
	case WASM_OP_ELSE:
		op->type = R_ANAL_OP_TYPE_JMP;
		// get if and set hint.
		if ((hint = r_anal_hint_get (anal, addr))) {
			op->jump = hint->jump;
			eprintf ("[wasm][else ] 0x%llx 0x%016llx hint: 0x%llx\n", addr, scope_hint, hint->jump);
		} else if ((hint = r_anal_hint_get (anal, scope_hint))) {
			r_anal_hint_set_jump (anal, hint->jump, op->jump + op->size);
			eprintf ("[wasm][else ] 0x%llx 0x%016llx \n", addr, scope_hint);
		}
		r_anal_hint_unset_jump(anal, scope_hint);
		r_anal_hint_set_jump (anal, scope_hint, addr);
		break;
	case WASM_OP_BR:
		op->type = R_ANAL_OP_TYPE_JMP;
		{
			ut32 val;
			read_u32_leb128 (data + 1, data + len, &val);
			ut64 pos = scope_hint + val;
			if ((hint = r_anal_hint_get (anal, scope_hint))) {
				op->jump = hint->jump;
				eprintf ("[wasm] br at %016llx\n", op->jump);
			} else {
				eprintf ("[wasm] cannot find jump for br\n");
			}
		}
		break;
	case WASM_OP_BRIF:
		op->fail = addr + op->size;
		op->type = R_ANAL_OP_TYPE_CJMP;
		{
			ut32 val;
			read_u32_leb128 (data + 1, data + len, &val);
			ut64 pos = scope_hint + val;
			if ((hint = r_anal_hint_get (anal, scope_hint))) {
				op->jump = hint->jump;
				eprintf ("[wasm] if_br at %016llx\n", op->jump);
			} else {
				eprintf ("[wasm] cannot find jump for if_br\n");
			}
		}
		break;
	case WASM_OP_END:
		op->type = R_ANAL_OP_TYPE_NOP;
		if (scope_hint < UT64_MAX) {
			hint = r_anal_hint_get (anal, scope_hint);
			if (hint && hint->bits) {
				// loop
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = hint->jump;
				eprintf ("[wasm][end  ] 0x%llx 0x%016llx hint: 0x%llx (loop)\n", addr, scope_hint, addr);
			} else if (hint) {
				// if/else/block
				r_anal_hint_unset_jump (anal, hint->jump);
				r_anal_hint_set_jump (anal, hint->jump, addr);
				eprintf ("[wasm][end  ] 0x%llx 0x%016llx hint: 0x%llx (if/else/block)\n", addr, scope_hint, hint->jump);
			}
			r_anal_hint_set_jump (anal, scope_hint, UT64_MAX);
			r_anal_hint_set_bits (anal, scope_hint, 0);
			r_anal_hint_del (anal, scope_hint, 1);
			scope_hint++;
		} else {
			eprintf ("[wasm][end  ] 0x%llx 0x%016llx (ret) 0x%llx\n", addr, scope_hint, addr);
			// all wasm routines ends with an end.
			op->eob = true;
			op->type = R_ANAL_OP_TYPE_RET;
		}
		break;
	case WASM_OP_I32REMS:
	case WASM_OP_I32REMU:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case WASM_OP_GETLOCAL:
	case WASM_OP_I32LOAD:
	case WASM_OP_I64LOAD:
	case WASM_OP_F32LOAD:
	case WASM_OP_F64LOAD:
	case WASM_OP_I32LOAD8S:
	case WASM_OP_I32LOAD8U:
	case WASM_OP_I32LOAD16S:
	case WASM_OP_I32LOAD16U:
	case WASM_OP_I64LOAD8S:
	case WASM_OP_I64LOAD8U:
	case WASM_OP_I64LOAD16S:
	case WASM_OP_I64LOAD16U:
	case WASM_OP_I64LOAD32S:
	case WASM_OP_I64LOAD32U:
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
	case WASM_OP_I64OR:
	case WASM_OP_I32OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case WASM_OP_I64XOR:
	case WASM_OP_I32XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case WASM_OP_I32CONST:
	case WASM_OP_I64CONST:
	case WASM_OP_F32CONST:
	case WASM_OP_F64CONST:
		op->type = R_ANAL_OP_TYPE_MOV;
		{
			ut8 arg = data[1];
			r_strbuf_setf (&op->esil, "4,sp,-=,%d,sp,=[4]", arg);
		}
		break;
	case WASM_OP_I64ADD:
	case WASM_OP_I32ADD:
	case WASM_OP_F32ADD:
	case WASM_OP_F64ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case WASM_OP_I64SUB:
	case WASM_OP_I32SUB:
	case WASM_OP_F32SUB:
	case WASM_OP_F64SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case WASM_OP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		r_strbuf_setf (&op->esil, "");
		break;
	case WASM_OP_CALL:
	case WASM_OP_CALLINDIRECT:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = get_cf_offset (anal, data);
		op->fail = addr + op->size;
		if (op->jump != UT64_MAX) {
			op->ptr = op->jump;
		}
		r_strbuf_setf (&op->esil, "4,sp,-=,0x%"PFMT64x",sp,=[4],0x%"PFMT64x",pc,=", op->fail, op->jump);
		break;
	case WASM_OP_RETURN:
		// should be ret, but if there the analisys is stopped.
		op->type = R_ANAL_OP_TYPE_CRET;
	default:
		break;
	}
	op_old = wop.op;
	free (wop.txt);
	r_anal_hint_free (hint);
	return op->size;
}

static int archinfo(RAnal *a, int q) {
	return 1;
}

static char *get_reg_profile(RAnal *anal) {
	return strdup (
		"=PC	pc\n"
		"=BP	bp\n"
		"=SP	sp\n"
		"gpr	sp	.32	0	0\n" // stack pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	bp	.32	8	0\n" // base pointer // unused
	);
}

RAnalPlugin r_anal_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.op = &wasm_op,
	.esil = true,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_wasm,
	.version = R2_VERSION
};
#endif
