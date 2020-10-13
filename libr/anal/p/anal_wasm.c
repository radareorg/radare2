/* radare2 - LGPL - Copyright 2017-2020 - xvilka, deroad */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#undef R_IPI
#define R_IPI static
#define WASM_NO_ASM // to get rid of a warning
#include "../../bin/format/wasm/wasm.h"
#include "../../asm/arch/wasm/wasm.c"

#define WASM_STACK_SIZE 256

static ut64 scope_hint = UT64_MAX;
static ut64 addr_old = UT64_MAX;

// finds the address of the call function (essentially where to jump to).
static ut64 get_cf_offset(RAnal *anal, const ut8 *data, int len) {
	ut32 fcn_id;

	if (!read_u32_leb128 (&data[1], &data[len - 1], &fcn_id)) {
		return UT64_MAX;
	}
	r_cons_push ();
	// 0xfff.. are bad addresses for wasm
	// cgvwzq: 0xfff... can be external imported JS funcs
	char *s = anal->coreb.cmdstrf (anal->coreb.core, "is~FUNC[2:%u]", fcn_id);
	r_cons_pop ();
	if (s) {
		ut64 n = r_num_get (NULL, s);
		free (s);
		return n;
	}
	return UT64_MAX;
}

static bool advance_till_scope_end(RAnal* anal, RAnalOp *op, ut64 address, ut32 expected_type, ut32 depth, bool use_else) {
	ut8 buffer[16];
	ut8 *ptr = buffer;
	ut8 *end = ptr + sizeof (buffer);
	WasmOp wop = {{0}};
	int size = 0;
	while (anal->iob.read_at (anal->iob.io, address, buffer, sizeof (buffer))) {
		size = wasm_dis (&wop, ptr, end - ptr);
		if (!wop.txt || (wop.type == WASM_TYPE_OP_CORE && wop.op.core == WASM_OP_TRAP)) {
			// if invalid stop here.
			break;
		}
		if (wop.type == WASM_TYPE_OP_CORE) {
			WasmOpCodes wopop = wop.op.core;
			if (wopop == WASM_OP_LOOP || wopop == WASM_OP_BLOCK || wopop == WASM_OP_IF) {
				depth++;
			}
			if (use_else && wopop == WASM_OP_ELSE && !depth) {
				op->type = expected_type;
				op->jump = address + 1; // else size == 1
				return true;
			} else if (wopop == WASM_OP_END && depth > 0) {
				// let's wait till i get the final depth
				depth--;
			} else if (wopop == WASM_OP_END && !depth) {
				op->type = expected_type;
				op->jump = address;
				return true;
			}
		}
		address += size;
	}
	return false;
}

// analyzes the wasm opcode.
static int wasm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	WasmOp wop = {{0}};
	RAnalHint *hint = NULL;
	int ret = wasm_dis (&wop, data, len);
	op->size = ret;
	op->addr = addr;
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		op->id = wop.op.core;
		break;
	case WASM_TYPE_OP_ATOMIC:
		op->id = (0xfe << 8) | wop.op.atomic;
		break;
	case WASM_TYPE_OP_SIMD:
		op->id = 0xfd;
		break;
	}

	if (!wop.txt || !strncmp (wop.txt, "invalid", 7)) {
		op->type = R_ANAL_OP_TYPE_ILL;
		free (wop.txt);
		return -1;
	}

	if (addr_old == addr && (wop.type != WASM_TYPE_OP_CORE || wop.op.core != WASM_OP_END)) {
		goto anal_end;
	}

	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		switch (wop.op.core) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			if (!(hint = r_anal_hint_get (anal, addr))) {
				scope_hint--;
				r_anal_hint_set_opcode (anal, scope_hint, "loop");
				r_anal_hint_set_jump (anal, scope_hint, addr);
			}
			break;
		case WASM_OP_BLOCK:
			op->type = R_ANAL_OP_TYPE_NOP;
			if (!(hint = r_anal_hint_get (anal, addr))) {
				scope_hint--;
				r_anal_hint_set_opcode (anal, scope_hint, "block");
				r_anal_hint_set_jump (anal, scope_hint, addr);
			}
			break;
		case WASM_OP_IF:
			if (!(hint = r_anal_hint_get (anal, addr))) {
				scope_hint--;
				r_anal_hint_set_opcode (anal, scope_hint, "if");
				r_anal_hint_set_jump (anal, scope_hint, addr);
				if (advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_CJMP, 0, true)) {
					op->fail = addr + op->size;
				}
			} else {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = hint->jump;
				op->fail = addr + op->size;
			}
			break;
		case WASM_OP_ELSE:
			// get if and set hint.
			if (!(hint = r_anal_hint_get (anal, addr))) {
				advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_JMP, 0, true);
			} else {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = hint->jump;
			}
			break;
		case WASM_OP_BR:
			{
				RAnalHint *hint2 = NULL;
				ut32 val;
				read_u32_leb128 (data + 1, data + len, &val);
				if ((hint2 = r_anal_hint_get (anal, addr)) && hint2->jump != UT64_MAX) {
					op->type = R_ANAL_OP_TYPE_JMP;
					op->jump = hint2->jump;
				} else if ((hint = r_anal_hint_get (anal, scope_hint))) {
					if (hint->opcode && !strncmp ("loop", hint->opcode, 4)) {
						op->type = R_ANAL_OP_TYPE_JMP;
						op->jump = hint->jump;
						r_anal_hint_set_jump (anal, addr, op->jump);
					} else {
						if (advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_JMP, val, false)) {
							r_anal_hint_set_jump (anal, addr, op->jump);
						}
					}
				} else {
					if (advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_JMP, val, false)) {
						eprintf ("[wasm] cannot find jump type for br (using block type)\n");
						r_anal_hint_set_jump (anal, addr, op->jump);
					} else {
						eprintf ("[wasm] cannot find jump for br\n");
					}
				}
				r_anal_hint_free (hint2);
			}
			break;
		case WASM_OP_BRIF:
			{
				RAnalHint *hint2 = NULL;
				ut32 val;
				read_u32_leb128 (data + 1, data + len, &val);
				if ((hint2 = r_anal_hint_get (anal, addr)) && hint2->jump != UT64_MAX) {
					op->type = R_ANAL_OP_TYPE_CJMP;
					op->jump = hint2->jump;
					op->fail = addr + op->size;
				} else if ((hint = r_anal_hint_get (anal, scope_hint))) {
					if (hint->opcode && !strncmp ("loop", hint->opcode, 4)) {
						op->fail = addr + op->size;
						op->jump = hint->jump;
						r_anal_hint_set_jump (anal, addr, op->jump);
					} else {
						if (advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_CJMP, val, false)) {
							op->fail = addr + op->size;
							r_anal_hint_set_jump (anal, addr, op->jump);
						}
					}
				} else {
					if (advance_till_scope_end (anal, op, addr + op->size, R_ANAL_OP_TYPE_CJMP, val, false)) {
						eprintf ("[wasm] cannot find jump type for br_if (using block type)\n");
						op->fail = addr + op->size;
						r_anal_hint_set_jump (anal, addr, op->jump);
					} else {
						eprintf ("[wasm] cannot find jump for br_if\n");
					}
				}
				r_anal_hint_free (hint2);
			}
			break;
		case WASM_OP_END:
			{
				op->type = R_ANAL_OP_TYPE_NOP;
				if (scope_hint < UT64_MAX) {
					hint = r_anal_hint_get (anal, scope_hint);
					if (hint && !strncmp ("loop", hint->opcode, 4)) {
						r_anal_hint_set_jump (anal, addr, op->jump);
						r_anal_hint_set_jump (anal, op->jump, addr);
					} else if (hint && !strncmp ("block", hint->opcode, 5)) {
						// if/else/block
						r_anal_hint_set_jump (anal, hint->jump, addr);
						r_anal_hint_set_jump (anal, addr, UT64_MAX);
					}
					if (hint) {
						r_anal_hint_set_opcode (anal, scope_hint, "invalid");
						r_anal_hint_set_jump (anal, scope_hint, UT64_MAX);
						r_anal_hint_del (anal, scope_hint, 1);
						scope_hint++;
					} else {
						// all wasm routines ends with an end.
						op->eob = true;
						op->type = R_ANAL_OP_TYPE_RET;
						scope_hint = UT64_MAX;
					}
				} else {
					if (!(hint = r_anal_hint_get (anal, addr))) {
						// all wasm routines ends with an end.
						op->eob = true;
						op->type = R_ANAL_OP_TYPE_RET;
					}
				}
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
			r_strbuf_setf (&op->esil, "%s", "");
			break;
		case WASM_OP_CALL:
		case WASM_OP_CALLINDIRECT:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = get_cf_offset (anal, data, len);
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
		break;
	case WASM_TYPE_OP_ATOMIC:
		switch (wop.op.atomic) {
		case WASM_OP_I32ATOMICLOAD:
		case WASM_OP_I64ATOMICLOAD:
		case WASM_OP_I32ATOMICLOAD8U:
		case WASM_OP_I32ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD8U:
		case WASM_OP_I64ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD32U:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case WASM_OP_I32ATOMICSTORE:
		case WASM_OP_I64ATOMICSTORE:
		case WASM_OP_I32ATOMICSTORE8:
		case WASM_OP_I32ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE8:
		case WASM_OP_I64ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE32:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case WASM_OP_I32ATOMICRMWADD:
		case WASM_OP_I64ATOMICRMWADD:
		case WASM_OP_I32ATOMICRMW8UADD:
		case WASM_OP_I32ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW8UADD:
		case WASM_OP_I64ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW32UADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case WASM_OP_I32ATOMICRMW8USUB:
		case WASM_OP_I32ATOMICRMW16USUB:
		case WASM_OP_I32ATOMICRMWSUB:
		case WASM_OP_I64ATOMICRMW8USUB:
		case WASM_OP_I64ATOMICRMW16USUB:
		case WASM_OP_I64ATOMICRMW32USUB:
		case WASM_OP_I64ATOMICRMWSUB:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case WASM_OP_I32ATOMICRMWAND:
		case WASM_OP_I64ATOMICRMWAND:
		case WASM_OP_I32ATOMICRMW8UAND:
		case WASM_OP_I32ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW8UAND:
		case WASM_OP_I64ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW32UAND:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case WASM_OP_I32ATOMICRMWOR:
		case WASM_OP_I64ATOMICRMWOR:
		case WASM_OP_I32ATOMICRMW8UOR:
		case WASM_OP_I32ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW8UOR:
		case WASM_OP_I64ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW32UOR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case WASM_OP_I32ATOMICRMWXOR:
		case WASM_OP_I64ATOMICRMWXOR:
		case WASM_OP_I32ATOMICRMW8UXOR:
		case WASM_OP_I32ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW8UXOR:
		case WASM_OP_I64ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW32UXOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case WASM_OP_I32ATOMICRMWXCHG:
		case WASM_OP_I64ATOMICRMWXCHG:
		case WASM_OP_I32ATOMICRMW8UXCHG:
		case WASM_OP_I32ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW8UXCHG:
		case WASM_OP_I64ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW32UXCHG:
			op->type = R_ANAL_OP_TYPE_XCHG;
			break;
		default:
			break;
		}
	default:
		break;
	}

anal_end:
	addr_old = addr;
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
		"=A0	r0\n"
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
	.esil = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_wasm,
	.version = R2_VERSION
};
#endif
