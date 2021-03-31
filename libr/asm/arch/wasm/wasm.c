/* radare - LGPL - Copyright 2017-2020 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "wasm.h"
#include "../../../bin/format/wasm/wasm.h"

static WasmOpDef opcodes[256] = {
	[WASM_OP_TRAP] = { "trap", 1, 1 },
	[WASM_OP_NOP] = { "nop", 1, 1 },
	[WASM_OP_BLOCK] = { "block", 2, 2 },
	[WASM_OP_LOOP] = { "loop", 2, 2 },
	[WASM_OP_IF] = { "if", 2, 2 },
	[WASM_OP_ELSE] = { "else", 1, 1 },
	[WASM_OP_END] = { "end", 1, 1 },
	[WASM_OP_BR] = { "br", 2, 2 },
	[WASM_OP_BRIF] = { "br_if", 2, 2 },
	[WASM_OP_BRTABLE] = { "brtable", 3, 0 },
	[WASM_OP_RETURN] = { "return", 1, 1 },
	[WASM_OP_CALL] = { "call" , 2, 2 },
	[WASM_OP_CALLINDIRECT] = { "call_indirect", 3, 3 },
	[WASM_OP_DROP] = { "drop", 1, 1 },
	[WASM_OP_SELECT] = { "select", 1, 1 },
	[WASM_OP_GETLOCAL] = { "get_local", 2, 2 },
	[WASM_OP_SETLOCAL] = { "set_local", 2, 2 },
	[WASM_OP_TEELOCAL] = { "tee_local", 2, 2 },
	[WASM_OP_GETGLOBAL] = { "get_global", 2, 2 },
	[WASM_OP_SETGLOBAL] = { "set_global", 2, 2 },
	[WASM_OP_I32LOAD] = { "i32.load", 3, 3 },
	[WASM_OP_I64LOAD] = { "i64.load", 3, 3 },
	[WASM_OP_F32LOAD] = { "f32.load", 3, 3 },
	[WASM_OP_F64LOAD] = { "f64.load", 3, 3 },
	[WASM_OP_I32LOAD8S] = { "i32.load8_s", 3, 3 },
	[WASM_OP_I32LOAD8U] = { "i32.load8_u", 3, 3 },
	[WASM_OP_I32LOAD16S] = { "i32.load16_s", 3, 3 },
	[WASM_OP_I32LOAD16U] = { "i32.load_16_u", 3, 3 },
	[WASM_OP_I64LOAD8S] = { "i64.load8_s", 3, 3 },
	[WASM_OP_I64LOAD8U] = { "i64.load8_u", 3, 3 },
	[WASM_OP_I64LOAD16S] = { "i64.load16_s", 3, 3 },
	[WASM_OP_I64LOAD16U] = { "i64.load16_u", 3, 3 },
	[WASM_OP_I64LOAD32S] = { "i64.load32_s", 3, 3 },
	[WASM_OP_I64LOAD32U] = { "i64.load32_u", 3, 3 },
	[WASM_OP_I32STORE] = { "i32.store", 3, 3 },
	[WASM_OP_I64STORE] = { "i64.store", 3, 3 },
	[WASM_OP_F32STORE] = { "f32.store", 3, 3 },
	[WASM_OP_F64STORE] = { "f64.store", 3, 3 },
	[WASM_OP_I32STORE8] = { "i32.store8", 3, 3 },
	[WASM_OP_I32STORE16] = { "i32.store16", 3, 3 },
	[WASM_OP_I64STORE8] = { "i64.store8", 3, 3 },
	[WASM_OP_I64STORE16] = { "i64.store16", 3, 3 },
	[WASM_OP_I64STORE32] = { "i64.store32", 3, 3 },
	[WASM_OP_CURRENTMEMORY] = { "current_memory", 2, 2 },
	[WASM_OP_GROWMEMORY] = { "grow_memory", 2, 2 },
	[WASM_OP_I32CONST] = { "i32.const", 2, 2 },
	[WASM_OP_I64CONST] = { "i64.const", 2, 2 },
	[WASM_OP_F32CONST] = { "f32.const", 2, 2 },
	[WASM_OP_F64CONST] = { "f64.const", 2, 2 },
	[WASM_OP_I32EQZ] = { "i32.eqz", 1, 1 },
	[WASM_OP_I32EQ] = { "i32.eq", 1, 1 },
	[WASM_OP_I32NE] = { "i32.ne", 1, 1},
	[WASM_OP_I32LTS] = { "i32.lt_s", 1, 1 },
	[WASM_OP_I32LTU] = { "i32.lt_u", 1, 1 },
	[WASM_OP_I32GTS] = { "i32.gt_s", 1, 1 },
	[WASM_OP_I32GTU] = { "i32.gt_u", 1, 1 },
	[WASM_OP_I32LES] = { "i32.le_s", 1, 1 },
	[WASM_OP_I32LEU] = { "i32.le_u", 1, 1 },
	[WASM_OP_I32GES] = { "i32.ge_s", 1, 1 },
	[WASM_OP_I32GEU] = { "i32.ge_u", 1, 1 },
	[WASM_OP_I64EQZ] = { "i64.eqz", 1, 1 },
	[WASM_OP_I64EQ] = {" i64.eq", 1, 1 },
	[WASM_OP_I64NE] = {" i64.ne", 1, 1 },
	[WASM_OP_I64LTS] = { "i64.lt_s", 1, 1 },
	[WASM_OP_I64LTU] = { "i64.lt_u", 1, 1 },
	[WASM_OP_I64GTS] = { "i64.gt_s", 1, 1 },
	[WASM_OP_I64GTU] = { "i64.gt_u", 1, 1 },
	[WASM_OP_I64LES] = { "i64.le_s", 1, 1 },
	[WASM_OP_I64LEU] = { "i64.le_u", 1, 1 },
	[WASM_OP_I64GES] = { "i64.ge_s", 1, 1 },
	[WASM_OP_I64GEU] = { "i64.ge_u", 1, 1 },
	[WASM_OP_F32EQ] = { "f32.eq", 1, 1 },
	[WASM_OP_F32NE] = { "f32.ne", 1, 1 },
	[WASM_OP_F32LT] = { "f32.lt", 1, 1 },
	[WASM_OP_F32GT] = { "f32.gt", 1, 1 },
	[WASM_OP_F32LE] = { "f32.le", 1, 1 },
	[WASM_OP_F32GE] = { "f32.ge", 1, 1 },
	[WASM_OP_F64EQ] = { "f64.eq", 1, 1 },
	[WASM_OP_F64NE] = { "f64.ne", 1, 1 },
	[WASM_OP_F64LT] = { "f64.lt", 1, 1 },
	[WASM_OP_F64GT] = { "f64.gt", 1, 1 },
	[WASM_OP_F64LE] = { "f64.le", 1, 1 },
	[WASM_OP_F64GE] = { "f64.ge", 1, 1 },
	[WASM_OP_I32CLZ] = { "i32.clz", 1, 1 },
	[WASM_OP_I32CTZ] = { "i32.ctz", 1, 1 },
	[WASM_OP_I32POPCNT] = { "i32.popcnt", 1, 1 },
	[WASM_OP_I32ADD] = { "i32.add", 1, 1 },
	[WASM_OP_I32SUB] = { "i32.sub", 1, 1 },
	[WASM_OP_I32MUL] = { "i32.mul", 1, 1 },
	[WASM_OP_I32DIVS] = { "i32.div_s", 1, 1 },
	[WASM_OP_I32DIVU] = { "i32.div_u", 1, 1 },
	[WASM_OP_I32REMS] = { "i32.rem_s", 1, 1 },
	[WASM_OP_I32REMU] = { "i32.rem_u", 1, 1 },
	[WASM_OP_I32AND] = { "i32.and", 1, 1 },
	[WASM_OP_I32OR] = { "i32.or", 1, 1 },
	[WASM_OP_I32XOR] = { "i32.xor", 1, 1 },
	[WASM_OP_I32SHL] = { "i32.shl", 1, 1 },
	[WASM_OP_I32SHRS] = { "i32.shr_s", 1, 1 },
	[WASM_OP_I32SHRU] = { "i32.shr_u", 1, 1 },
	[WASM_OP_I32ROTL] = { "i32.rotl", 1, 1 },
	[WASM_OP_I32ROTR] = { "i32.rotr", 1, 1 },
	[WASM_OP_I64CLZ] = { "i64.clz", 1, 1 },
	[WASM_OP_I64CTZ] = { "i64.ctz", 1, 1 },
	[WASM_OP_I64POPCNT] = { "i64.popcnt", 1, 1 },
	[WASM_OP_I64ADD] = { "i64.add", 1, 1 },
	[WASM_OP_I64SUB] = { "i64.sub", 1, 1 },
	[WASM_OP_I64MUL] = { "i64.mul", 1, 1 },
	[WASM_OP_I64DIVS] = { "i64.div_s", 1, 1 },
	[WASM_OP_I64DIVU] = { "i64.div_u", 1, 1 },
	[WASM_OP_I64REMS] = { "i64.rem_s", 1, 1 },
	[WASM_OP_I64REMU] = { "i64.rem_u", 1, 1 },
	[WASM_OP_I64AND] = { "i64.and", 1, 1 },
	[WASM_OP_I64OR] = { "i64.or", 1, 1 },
	[WASM_OP_I64XOR] = { "i64.xor", 1, 1 },
	[WASM_OP_I64SHL] = { "i64.shl", 1, 1 },
	[WASM_OP_I64SHRS] = { "i64.shr_s", 1, 1 },
	[WASM_OP_I64SHRU] = { "i64.shr_u", 1, 1 },
	[WASM_OP_I64ROTL] = { "i64.rotl", 1, 1 },
	[WASM_OP_I64ROTR] = { "i64.rotr", 1, 1 },
	[WASM_OP_F32ABS] = { "f32.abs", 1, 1 },
	[WASM_OP_F32NEG] = { "f32.neg", 1, 1 },
	[WASM_OP_F32CEIL] = { "f32.ceil", 1, 1 },
	[WASM_OP_F32FLOOR] = { "f32.floor", 1, 1 },
	[WASM_OP_F32TRUNC] = { "f32.trunc", 1, 1 },
	[WASM_OP_F32NEAREST] = { "f32.nearest", 1, 1 },
	[WASM_OP_F32SQRT] = { "f32.sqrt", 1, 1 },
	[WASM_OP_F32ADD] = { "f32.add", 1, 1 },
	[WASM_OP_F32SUB] =  { "f32.sub", 1, 1 },
	[WASM_OP_F32MUL] = { "f32.mul", 1, 1 },
	[WASM_OP_F32DIV] = { "f32.div", 1, 1 },
	[WASM_OP_F32MIN] = { "f32.min", 1, 1 },
	[WASM_OP_F32MAX] = { "f32.max", 1, 1 },
	[WASM_OP_F32COPYSIGN] = {" f32.copysign", 1, 1 },
	[WASM_OP_F64ABS] = { "f64.abs", 1, 1 },
	[WASM_OP_F64NEG] = { "f64.neg", 1, 1 },
	[WASM_OP_F64CEIL] = { "f64.ceil", 1, 1 },
	[WASM_OP_F64FLOOR] = { "f64.floor", 1, 1 },
	[WASM_OP_F64TRUNC] = { "f64.trunc", 1, 1 },
	[WASM_OP_F64NEAREST] = { "f64.nearest", 1, 1 },
	[WASM_OP_F64SQRT] = { "f64.sqrt", 1, 1 },
	[WASM_OP_F64ADD] = { "f64.add", 1, 1 },
	[WASM_OP_F64SUB] = { "f64.sub", 1, 1 },
	[WASM_OP_F64MUL] = { "f64.mul", 1, 1 },
	[WASM_OP_F64DIV] = { "f64.div", 1, 1 },
	[WASM_OP_F64MIN] = { "f64.min", 1, 1 },
	[WASM_OP_F64MAX] = { "f64.max", 1, 1 },
	[WASM_OP_F64COPYSIGN] = { "f64.copysign", 1, 1 },
	[WASM_OP_I32WRAPI64] = { "i32.wrap/i64", 1, 1 },
	[WASM_OP_I32TRUNCSF32] = { "i32.trunc_s/f32", 1, 1 },
	[WASM_OP_I32TRUNCUF32] = { "i32.trunc_u/f32", 1, 1 },
	[WASM_OP_I32TRUNCSF64] = { "i32.trunc_s/f64", 1, 1 },
	[WASM_OP_I32TRUNCUF64] = { "i32.trunc_u/f64", 1, 1 },
	[WASM_OP_I64EXTENDSI32] = { "i64.extend_s/i32", 1, 1 },
	[WASM_OP_I64EXTENDUI32] = { "i64.extend_u/i32", 1, 1 },
	[WASM_OP_I64TRUNCSF32] = { "i64.trunc_s/f32", 1, 1 },
	[WASM_OP_I64TRUNCUF32] = { "i64.trunc_u/f32", 1, 1 },
	[WASM_OP_I64TRUNCSF64] = { "i64.trunc_s/f64", 1, 1 },
	[WASM_OP_I64TRUNCUF64] = { "i64.trunc_u/f64", 1, 1 },
	[WASM_OP_F32CONVERTSI32] = { "f32.convert_s/i32", 1, 1 },
	[WASM_OP_F32CONVERTUI32] = { "f32.convert_u/i32", 1, 1 },
	[WASM_OP_F32CONVERTSI64] = { "f32.convert_s/i64", 1, 1 },
	[WASM_OP_F32CONVERTUI64] = { "f32.convert_u/i64", 1, 1 },
	[WASM_OP_F32DEMOTEF64] = { "f32.demote/f64", 1, 1 },
	[WASM_OP_F64CONVERTSI32] = { "f64.convert_s/i32", 1, 1 },
	[WASM_OP_F64CONVERTUI32] = { "f64.convert_u/i32", 1, 1 },
	[WASM_OP_F64CONVERTSI64] = { "f64.convert_s/i64", 1, 1 },
	[WASM_OP_F64CONVERTUI64] = { "f64.convert_u/i64", 1, 1 },
	[WASM_OP_F64PROMOTEF32] = { "f64.promote/f32", 1, 1 },
	[WASM_OP_I32REINTERPRETF32] = { "i32.reinterpret/f32", 1, 1 },
	[WASM_OP_I64REINTERPRETF64] = { "i64.reinterpret/f64", 1, 1 },
	[WASM_OP_F32REINTERPRETI32] = { "f32.reinterpret/i32", 1, 1 },
	[WASM_OP_F64REINTERPRETI64] = { "f64.reinterpret/i64", 1, 1 }
};

static WasmOpDef opcodes_threads[256] = {
	[WASM_OP_ATOMICNOTIFY] = { "atomic.notify", 1, 1 },
	[WASM_OP_I32ATOMICWAIT ] = { "i32.atomic.wait", 1, 1 },
	[WASM_OP_I64ATOMICWAIT ] = { "i64.atomic.wait", 1, 1 },
	[WASM_OP_I32ATOMICLOAD] = { "i32.atomic.load", 3, 3 },
	[WASM_OP_I64ATOMICLOAD] = { "i64.atomic.load", 3, 3 },
	[WASM_OP_I32ATOMICLOAD16U] = { "i32.atomic.load16_u" , 3, 3 },
	[WASM_OP_I64ATOMICLOAD8U] = { "i64.atomic.load8_u" , 3, 3 },
	[WASM_OP_I64ATOMICLOAD16U] = { "i64.atomic.load16_u" , 3, 3 },
	[WASM_OP_I64ATOMICLOAD32U] = { "i64.atomic.load32_u" , 3, 3 },
	[WASM_OP_I32ATOMICSTORE] = { "i32.atomic.store" , 3, 3 },
	[WASM_OP_I64ATOMICSTORE] = { "i64.atomic.store" , 3, 3 },
	[WASM_OP_I32ATOMICSTORE8] = { "i32.atomic.store8" , 3, 3 },
	[WASM_OP_I32ATOMICSTORE16] = { "i32.atomic.store16" , 3, 3 },
	[WASM_OP_I64ATOMICSTORE8] = { "i64.atomic.store8" , 3, 3 },
	[WASM_OP_I64ATOMICSTORE16] = { "i64.atomic.store16" , 3, 3 },
	[WASM_OP_I64ATOMICSTORE32] = { "i64.atomic.store32" , 3, 3 },
	[WASM_OP_I32ATOMICRMWADD] = { "i32.atomic.rmw.add" , 3, 3 },
	[WASM_OP_I64ATOMICRMWADD] = { "i64.atomic.rmw.add" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UADD] = { "i32.atomic.rmw8_u.add" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UADD] = { "i32.atomic.rmw16_u.add" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UADD] = { "i64.atomic.rmw8_u.add" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UADD] = { "i64.atomic.rmw16_u.add" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UADD] = { "i64.atomic.rmw32_u.add" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8USUB] = { "i32.atomic.rmw8_u.sub" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16USUB] = { "i32.atomic.rmw16_u.sub" , 3, 3 },
	[WASM_OP_I32ATOMICRMWSUB] = { "i32.atomic.rmw.sub" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8USUB] = { "i64.atomic.rmw8_u.sub" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16USUB] = { "i64.atomic.rmw16_u.sub" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32USUB] = { "i64.atomic.rmw32_u.sub" , 3, 3 },
	[WASM_OP_I64ATOMICRMWSUB] = { "i64.atomic.rmw.sub" , 3, 3 },
	[WASM_OP_I32ATOMICRMWAND] = { "i32.atomic.rmw.and" , 3, 3 },
	[WASM_OP_I64ATOMICRMWAND] = { "i64.atomic.rmw.and" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UAND] = { "i32.atomic.rmw8_u.and" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UAND] = { "i32.atomic.rmw16_u.and" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UAND] = { "i64.atomic.rmw8_u.and" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UAND] = { "i64.atomic.rmw16_u.and" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UAND] = { "i64.atomic.rmw32_u.and" , 3, 3 },
	[WASM_OP_I32ATOMICRMWOR] = { "i32.atomic.rmw.or" , 3, 3 },
	[WASM_OP_I64ATOMICRMWOR] = { "i64.atomic.rmw.or" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UOR] = { "i32.atomic.rmw8_u.or" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UOR] = { "i32.atomic.rmw16_u.or" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UOR] = { "i64.atomic.rmw8_u.or" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UOR] = { "i64.atomic.rmw16_u.or" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UOR] = { "i64.atomic.rmw32_u.or" , 3, 3 },
	[WASM_OP_I32ATOMICRMWXOR] = { "i32.atomic.rmw.xor" , 3, 3 },
	[WASM_OP_I64ATOMICRMWXOR] = { "i64.atomic.rmw.xor" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UXOR] = { "i32.atomic.rmw8_u.xor" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UXOR] = { "i32.atomic.rmw16_u.xor" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UXOR] = { "i64.atomic.rmw8_u.xor" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UXOR] = { "i64.atomic.rmw16_u.xor" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UXOR] = { "i64.atomic.rmw32_u.xor" , 3, 3 },
	[WASM_OP_I32ATOMICRMWXCHG] = { "i32.atomic.rmw.xchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMWXCHG] = { "i64.atomic.rmw.xchg" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UXCHG] = { "i32.atomic.rmw8_u.xchg" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UXCHG] = { "i32.atomic.rmw16_u.xchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UXCHG] = { "i64.atomic.rmw8_u.xchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UXCHG] = { "i64.atomic.rmw16_u.xchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UXCHG] = { "i64.atomic.rmw32_u.xchg" , 3, 3 },
	[WASM_OP_I32ATOMICRMWCMPXCHG] = { "i32.atomic.rmw.cmpxchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMWCMPXCHG] = { "i64.atomic.rmw.cmpxchg" , 3, 3 },
	[WASM_OP_I32ATOMICRMW8UCMPXCHG] = { "i32.atomic.rmw8_u.cmpxchg" , 3, 3 },
	[WASM_OP_I32ATOMICRMW16UCMPXCHG] = { "i32.atomic.rmw16_u.cmpxchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW8UCMPXCHG] = { "i64.atomic.rmw8_u.cmpxchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW16UCMPXCHG] = { "i64.atomic.rmw16_u.cmpxchg" , 3, 3 },
	[WASM_OP_I64ATOMICRMW32UCMPXCHG] = { "i64.atomic.rmw32_u.cmpxchg" , 3, 3 }
};

static WasmOpDef opcodes_simd[256] = {
	[WASM_OP_V128LOAD] = { "v128.load", 6, 6 },
	[WASM_OP_V128STORE] = { "v128.store", 2, 6 },
	[WASM_OP_V128CONST] = { "v128.const", 2, 6 },
	[WASM_OP_I8X16SPLAT] = { "i8x16.splat", 2, 6 },
	[WASM_OP_I8X16EXTRACTLANES] = { "i8x16.extract_lane_s", 2, 6 },
	[WASM_OP_I8X16EXTRACTLANEU] = { "i8x16.extract_lane_u", 2, 6 },
	[WASM_OP_I8X16REPLACELANE] = { "i8x16.replace_lane", 2, 6 },
	[WASM_OP_I16X8SPLAT] = { "i16x8.splat", 2, 6 },
	[WASM_OP_I16X8EXTRACTLANES] = { "i16x8.extract_lane_s", 2, 6 },
	[WASM_OP_I16X8EXTRACTLANEU] = { "i16x8.extract_lane_u", 2, 6 },
	[WASM_OP_I16X8REPLACELANE] = { "i16x8.replace_lane", 2, 6 },
	[WASM_OP_I32X4SPLAT] = { "i32x4.splat", 2, 6 },
	[WASM_OP_I32X4EXTRACTLANE] = { "i32x4.extract_lane", 2, 6 },
	[WASM_OP_I32X4REPLACELANE] = { "i32x4.replace_lane", 2, 6 },
	[WASM_OP_I64X2SPLAT] = { "i64x2.splat", 2, 6 },
	[WASM_OP_I64X2EXTRACTLANE] = { "i64x2.extract_lane", 2, 6 },
	[WASM_OP_I64X2REPLACELANE] = { "i64x2.replace_lane", 2, 6 },
	[WASM_OP_F32X4SPLAT] = { "f32x4.splat", 2, 6 },
	[WASM_OP_F32X4EXTRACTLANE] = { "f32x4.extract_lane", 2, 6 },
	[WASM_OP_F32X4REPLACELANE] = { "f32x4.replace_lane", 2, 6 },
	[WASM_OP_F64X2SPLAT] = { "f64x2.splat", 2, 6 },
	[WASM_OP_F64X2EXTRACTLANE] = { "f64x2.extract_lane", 2, 6 },
	[WASM_OP_F64X2REPLACELANE] = { "f64x2.replace_lane", 2, 6 },
	[WASM_OP_I8X16EQ] = { "i8x16.eq", 2, 6 },
	[WASM_OP_I8X16NE] = { "i8x16.ne", 2, 6 },
	[WASM_OP_I8X16LTS] = { "i8x16.lt_s", 2, 6 },
	[WASM_OP_I8X16LTU] = { "i8x16.lt_u", 2, 6 },
	[WASM_OP_I8X16GTS] = { "i8x16.gt_s", 2, 6 },
	[WASM_OP_I8X16GTU] = { "i8x16.gt_u", 2, 6 },
	[WASM_OP_I8X16LES] = { "i8x16.le_s", 2, 6 },
	[WASM_OP_I8X16LEU] = { "i8x16.le_u", 2, 6 },
	[WASM_OP_I8X16GES] = { "i8x16.ge_s", 2, 6 },
	[WASM_OP_I8X16GEU] = { "i8x16.ge_u", 2, 6 },
	[WASM_OP_I16X8EQ] = { "i16x8.eq", 2, 6 },
	[WASM_OP_I16X8NE] = { "i16x8.ne", 2, 6 },
	[WASM_OP_I16X8LTS] = { "i16x8.lt_s", 2, 6 },
	[WASM_OP_I16X8LTU] = { "i16x8.lt_u", 2, 6 },
	[WASM_OP_I16X8GTS] = { "i16x8.gt_s", 2, 6 },
	[WASM_OP_I16X8GTU] = { "i16x8.gt_u", 2, 6 },
	[WASM_OP_I16X8LES] = { "i16x8.le_s", 2, 6 },
	[WASM_OP_I16X8LEU] = { "i16x8.le_u", 2, 6 },
	[WASM_OP_I16X8GES] = { "i16x8.ge_s", 2, 6 },
	[WASM_OP_I16X8GEU] = { "i16x8.ge_u", 2, 6 },
	[WASM_OP_I32X4EQ] = { "i32x4.eq", 2, 6 },
	[WASM_OP_I32X4NE] = { "i32x4.ne", 2, 6 },
	[WASM_OP_I32X4LTS] = { "i32x4.lt_s", 2, 6 },
	[WASM_OP_I32X4LTU] = { "i32x4.lt_u", 2, 6 },
	[WASM_OP_I32X4GTS] = { "i32x4.gt_s", 2, 6 },
	[WASM_OP_I32X4GTU] = { "i32x4.gt_u", 2, 6 },
	[WASM_OP_I32X4LES] = { "i32x4.le_s", 2, 6 },
	[WASM_OP_I32X4LEU] = { "i32x4.le_u", 2, 6 },
	[WASM_OP_I32X4GES] = { "i32x4.ge_s", 2, 6 },
	[WASM_OP_I32X4GEU] = { "i32x4.ge_u", 2, 6 },
	[WASM_OP_F32X4EQ] = { "f32x4.eq", 2, 6 },
	[WASM_OP_F32X4NE] = { "f32x4.ne", 2, 6 },
	[WASM_OP_F32X4LT] = { "f32x4.lt", 2, 6 },
	[WASM_OP_F32X4GT] = { "f32x4.gt", 2, 6 },
	[WASM_OP_F32X4LE] = { "f32x4.le", 2, 6 },
	[WASM_OP_F32X4GE] = { "f32x4.ge", 2, 6 },
	[WASM_OP_F64X2EQ] = { "f64x2.eq", 2, 6 },
	[WASM_OP_F64X2NE] = { "f64x2.ne", 2, 6 },
	[WASM_OP_F64X2LT] = { "f64x2.lt", 2, 6 },
	[WASM_OP_F64X2GT] = { "f64x2.gt", 2, 6 },
	[WASM_OP_F64X2LE] = { "f64x2.le", 2, 6 },
	[WASM_OP_F64X2GE] = { "f64x2.ge", 2, 6 },
	[WASM_OP_V128NOT] = { "v128.not", 2, 6 },
	[WASM_OP_V128AND] = { "v128.and", 2, 6 },
	[WASM_OP_V128OR] = { "v128.or", 2, 6 },
	[WASM_OP_V128XOR] = { "v128.xor", 2, 6 },
	[WASM_OP_V128BITSELECT] = { "v128.bitselect", 2, 6 },
	[WASM_OP_I8X16NEG] = { "i8x16.neg", 2, 6 },
	[WASM_OP_I8X16ANYTRUE] = { "i8x16.any_true", 2, 6 },
	[WASM_OP_I8X16ALLTRUE] = { "i8x16.all_true", 2, 6 },
	[WASM_OP_I8X16SHL] = { "i8x16.shl", 2, 6 },
	[WASM_OP_I8X16SHRS] = { "i8x16.shr_s", 2, 6 },
	[WASM_OP_I8X16SHRU] = { "i8x16.shr_u", 2, 6 },
	[WASM_OP_I8X16ADD] = { "i8x16.add", 2, 6 },
	[WASM_OP_I8X16ADDSATURATES] = { "i8x16.add_saturate_s", 2, 6 },
	[WASM_OP_I8X16ADDSATURATEU] = { "i8x16.add_saturate_u", 2, 6 },
	[WASM_OP_I8X16SUB] = { "i8x16.sub", 2, 6 },
	[WASM_OP_I8X16SUBSATURATES] = { "i8x16.sub_saturate_s", 2, 6 },
	[WASM_OP_I8X16SUBSATURATEU] = { "i8x16.sub_saturate_u", 2, 6 },
	[WASM_OP_I8X16MINS] = { "i8x16.min_s", 2, 6 },
	[WASM_OP_I8X16MINU] = { "i8x16.min_u", 2, 6 },
	[WASM_OP_I8X16MAXS] = { "i8x16.max_s", 2, 6 },
	[WASM_OP_I8X16MAXU] = { "i8x16.max_u", 2, 6 },
	[WASM_OP_I16X8NEG] = { "i16x8.neg", 2, 6 },
	[WASM_OP_I16X8ANYTRUE] = { "i16x8.any_true", 2, 6 },
	[WASM_OP_I16X8ALLTRUE] = { "i16x8.all_true", 2, 6 },
	[WASM_OP_I16X8SHL] = { "i16x8.shl", 2, 6 },
	[WASM_OP_I16X8SHRS] = { "i16x8.shr_s", 2, 6 },
	[WASM_OP_I16X8SHRU] = { "i16x8.shr_u", 2, 6 },
	[WASM_OP_I16X8ADD] = { "i16x8.add", 2, 6 },
	[WASM_OP_I16X8ADDSATURATES] = { "i16x8.add_saturate_s", 2, 6 },
	[WASM_OP_I16X8ADDSATURATEU] = { "i16x8.add_saturate_u", 2, 6 },
	[WASM_OP_I16X8SUB] = { "i16x8.sub", 2, 6 },
	[WASM_OP_I16X8SUBSATURATES] = { "i16x8.sub_saturate_s", 2, 6 },
	[WASM_OP_I16X8SUBSATURATEU] = { "i16x8.sub_saturate_u", 2, 6 },
	[WASM_OP_I16X8MUL] = { "i16x8.mul", 2, 6 },
	[WASM_OP_I16X8MINS] = { "i16x8.min_s", 2, 6 },
	[WASM_OP_I16X8MINU] = { "i16x8.min_u", 2, 6 },
	[WASM_OP_I16X8MAXS] = { "i16x8.max_s", 2, 6 },
	[WASM_OP_I16X8MAXU] = { "i16x8.max_u", 2, 6 },
	[WASM_OP_I32X4NEG] = { "i32x4.neg", 2, 6 },
	[WASM_OP_I32X4ANYTRUE] = { "i32x4.any_true", 2, 6 },
	[WASM_OP_I32X4ALLTRUE] = { "i32x4.all_true", 2, 6 },
	[WASM_OP_I32X4SHL] = { "i32x4.shl", 2, 6 },
	[WASM_OP_I32X4SHRS] = { "i32x4.shr_s", 2, 6 },
	[WASM_OP_I32X4SHRU] = { "i32x4.shr_u", 2, 6 },
	[WASM_OP_I32X4ADD] = { "i32x4.add", 2, 6 },
	[WASM_OP_I32X4SUB] = { "i32x4.sub", 2, 6 },
	[WASM_OP_I32X4MUL] = { "i32x4.mul", 2, 6 },
	[WASM_OP_I32X4MINS] = { "i32x4.min_s", 2, 6 },
	[WASM_OP_I32X4MINU] = { "i32x4.min_u", 2, 6 },
	[WASM_OP_I32X4MAXS] = { "i32x4.max_s", 2, 6 },
	[WASM_OP_I32X4MAXU] = { "i32x4.max_u", 2, 6 },
	[WASM_OP_I64X2NEG] = { "i64x2.neg", 2, 6 },
	[WASM_OP_I64X2SHL] = { "i64x2.shl", 2, 6 },
	[WASM_OP_I64X2SHRS] = { "i64x2.shr_s", 2, 6 },
	[WASM_OP_I64X2SHRU] = { "i64x2.shr_u", 2, 6 },
	[WASM_OP_I64X2ADD] = { "i64x2.add", 2, 6 },
	[WASM_OP_I64X2SUB] = { "i64x2.sub", 2, 6 },
	[WASM_OP_I64X2MUL] = { "i64x2.mul", 2, 6 },
	[WASM_OP_F32X4ABS] = { "f32x4.abs", 2, 6 },
	[WASM_OP_F32X4NEG] = { "f32x4.neg", 2, 6 },
	[WASM_OP_F32X4SQRT] = { "f32x4.sqrt", 2, 6 },
	[WASM_OP_F32X4ADD] = { "f32x4.add", 2, 6 },
	[WASM_OP_F32X4SUB] = { "f32x4.sub", 2, 6 },
	[WASM_OP_F32X4MUL] = { "f32x4.mul", 2, 6 },
	[WASM_OP_F32X4DIV] = { "f32x4.div", 2, 6 },
	[WASM_OP_F32X4MIN] = { "f32x4.min", 2, 6 },
	[WASM_OP_F32X4MAX] = { "f32x4.max", 2, 6 },
	[WASM_OP_F64X2ABS] = { "f64x2.abs", 2, 6 },
	[WASM_OP_F64X2NEG] = { "f64x2.neg", 2, 6 },
	[WASM_OP_F64X2SQRT] = { "f64x2.sqrt", 2, 6 },
	[WASM_OP_F64X2ADD] = { "f64x2.add", 2, 6 },
	[WASM_OP_F64X2SUB] = { "f64x2.sub", 2, 6 },
	[WASM_OP_F64X2MUL] = { "f64x2.mul", 2, 6 },
	[WASM_OP_F64X2DIV] = { "f64x2.div", 2, 6 },
	[WASM_OP_F64X2MIN] = { "f64x2.min", 2, 6 },
	[WASM_OP_F64X2MAX] = { "f64x2.max", 2, 6 },
	[WASM_OP_I32X4TRUNCSATF32X4S] = { "i32x4.trunc_sat_f32x4_s", 2, 6 },
	[WASM_OP_I32X4TRUNCSATF32X4U] = { "i32x4.trunc_sat_f32x4_u", 2, 6 },
	[WASM_OP_F32X4CONVERTI32X4S] = { "f32x4.convert_i32x4_s", 2, 6 },
	[WASM_OP_F32X4CONVERTI32X4U] = { "f32x4.convert_i32x4_u", 2, 6 },
	[WASM_OP_V8X16SWIZZLE] = { "v8x16.swizzle", 2, 6 },
	[WASM_OP_V8X16SHUFFLE] = { "v8x16.shuffle", 2, 6 },
	[WASM_OP_V8X16LOADSPLAT] = { "v8x16.load_splat", 2, 6 },
	[WASM_OP_V16X8LOADSPLAT] = { "v16x8.load_splat", 2, 6 },
	[WASM_OP_V32X4LOADSPLAT] = { "v32x4.load_splat", 2, 6 },
	[WASM_OP_V64X2LOADSPLAT] = { "v64x2.load_splat", 2, 6 },
	[WASM_OP_I8X16NARROWI16X8S] = { "i8x16.narrow_i16x8_s", 2, 6 },
	[WASM_OP_I8X16NARROWI16X8U] = { "i8x16.narrow_i16x8_u", 2, 6 },
	[WASM_OP_I16X8NARROWI32X4S] = { "i16x8.narrow_i32x4_s", 2, 6 },
	[WASM_OP_I16X8NARROWI32X4U] = { "i16x8.narrow_i32x4_u", 2, 6 },
	[WASM_OP_I16X8WIDENLOWI8X16S] = { "i16x8.widen_low_i8x16_s", 2, 6 },
	[WASM_OP_I16X8WIDENHIGHI8X16S] = { "i16x8.widen_high_i8x16_s", 2, 6 },
	[WASM_OP_I16X8WIDENLOWI8X16U] = { "i16x8.widen_low_i8x16_u", 2, 6 },
	[WASM_OP_I16X8WIDENHIGHI8X16U] = { "i16x8.widen_high_i8x16_u", 2, 6 },
	[WASM_OP_I32X4WIDENLOWI16X8S] = { "i32x4.widen_low_i16x8_s", 2, 6 },
	[WASM_OP_I32X4WIDENHIGHI16X8S] = { "i32x4.widen_high_i16x8_s", 2, 6 },
	[WASM_OP_I32X4WIDENLOWI16X8U] = { "i32x4.widen_low_i16x8_u", 2, 6 },
	[WASM_OP_I32X4WIDENHIGHI16X8U] = { "i32x4.widen_high_i16x8_u", 2, 6 },
	[WASM_OP_I16X8LOAD8X8S] = { "i16x8.load8x8_s", 2, 6 },
	[WASM_OP_I16X8LOAD8X8U] = { "i16x8.load8x8_u", 2, 6 },
	[WASM_OP_I32X4LOAD16X4S] = { "i32x4.load16x4_s", 2, 6 },
	[WASM_OP_I32X4LOAD16X4U] = { "i32x4.load16x4_u", 2, 6 },
	[WASM_OP_I64X2LOAD32X2S] = { "i64x2.load32x2_s", 2, 6 },
	[WASM_OP_I64X2LOAD32X2U] = { "i64x2.load32x2_u", 2, 6 },
	[WASM_OP_V128ANDNOT] = { "v128.andnot", 2, 6 },
	[WASM_OP_I8X16AVGRU] = { "i8x16.avgr_u", 2, 6 },
	[WASM_OP_I16X8AVGRU] = { "i16x8.avgr_u", 2, 6 },
	[WASM_OP_I8X16ABS] = { "i8x16.abs", 2, 6 },
	[WASM_OP_I16X8ABS] = { "i16x8.abs", 2, 6 },
};

#ifndef WASM_NO_ASM
// assembles the given line of wasm assembly.
R_IPI int wasm_asm(const char *str, unsigned char *buf, int buf_len) {
	int i = 0, len = 0;
	char tmp[256];
	WasmOpDef *opdef = NULL;
	while (i < (sizeof (tmp) - 1) && str[i] && str[i] != ' ') {
		tmp[i] = str[i];
		i++;
	}
	tmp[i] = 0;
	// Find opcode
	for (i = 0; i < 0xff; i++) {
		opdef = &opcodes[i];
		if (opdef->txt) {
			if (!strcmp (opdef->txt, tmp)) {
				buf[len++] = i;
				break;
			}
		}
	}
	// Check extensions
	if (len == 0) {
		for (i = 0; i < 0xff; i++) {
			opdef = &opcodes_threads[i];
			if (opdef->txt) {
				if (!strcmp (opdef->txt, tmp)) {
					buf[len++] = 0xfe;
					buf[len++] = i;
					break;
				}
			}
		}
	}
	// Abort
	if (len == 0) goto err;
	// TODO: parse immediates
	return len;
  err:
	return -1;
}
#endif

// disassemble an instruction from the given buffer.
R_IPI int wasm_dis(WasmOp *op, const unsigned char *buf, int buf_len) {
	RStrBuf *sb = r_strbuf_new ("");
	int id = buf[0];
	if (id < 0xc0) {
		op->type = WASM_TYPE_OP_CORE;
		op->op.core = id;
		op->len = 1;
		WasmOpDef *opdef = &opcodes[id];
		switch (id) {
		case WASM_OP_TRAP:
		case WASM_OP_NOP:
		case WASM_OP_ELSE:
		case WASM_OP_RETURN:
		case WASM_OP_DROP:
		case WASM_OP_SELECT:
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
		case WASM_OP_I32CLZ:
		case WASM_OP_I32CTZ:
		case WASM_OP_I32POPCNT:
		case WASM_OP_I32ADD:
		case WASM_OP_I32SUB:
		case WASM_OP_I32MUL:
		case WASM_OP_I32DIVS:
		case WASM_OP_I32DIVU:
		case WASM_OP_I32REMS:
		case WASM_OP_I32REMU:
		case WASM_OP_I32AND:
		case WASM_OP_I32OR:
		case WASM_OP_I32XOR:
		case WASM_OP_I32SHL:
		case WASM_OP_I32SHRS:
		case WASM_OP_I32SHRU:
		case WASM_OP_I32ROTL:
		case WASM_OP_I32ROTR:
		case WASM_OP_I64CLZ:
		case WASM_OP_I64CTZ:
		case WASM_OP_I64POPCNT:
		case WASM_OP_I64ADD:
		case WASM_OP_I64SUB:
		case WASM_OP_I64MUL:
		case WASM_OP_I64DIVS:
		case WASM_OP_I64DIVU:
		case WASM_OP_I64REMS:
		case WASM_OP_I64REMU:
		case WASM_OP_I64AND:
		case WASM_OP_I64OR:
		case WASM_OP_I64XOR:
		case WASM_OP_I64SHL:
		case WASM_OP_I64SHRS:
		case WASM_OP_I64SHRU:
		case WASM_OP_I64ROTL:
		case WASM_OP_I64ROTR:
		case WASM_OP_F32ABS:
		case WASM_OP_F32NEG:
		case WASM_OP_F32CEIL:
		case WASM_OP_F32FLOOR:
		case WASM_OP_F32TRUNC:
		case WASM_OP_F32NEAREST:
		case WASM_OP_F32SQRT:
		case WASM_OP_F32ADD:
		case WASM_OP_F32SUB:
		case WASM_OP_F32MUL:
		case WASM_OP_F32DIV:
		case WASM_OP_F32MIN:
		case WASM_OP_F32MAX:
		case WASM_OP_F32COPYSIGN:
		case WASM_OP_F64ABS:
		case WASM_OP_F64NEG:
		case WASM_OP_F64CEIL:
		case WASM_OP_F64FLOOR:
		case WASM_OP_F64TRUNC:
		case WASM_OP_F64NEAREST:
		case WASM_OP_F64SQRT:
		case WASM_OP_F64ADD:
		case WASM_OP_F64SUB:
		case WASM_OP_F64MUL:
		case WASM_OP_F64DIV:
		case WASM_OP_F64MIN:
		case WASM_OP_F64MAX:
		case WASM_OP_F64COPYSIGN:
		case WASM_OP_I32WRAPI64:
		case WASM_OP_I32TRUNCSF32:
		case WASM_OP_I32TRUNCUF32:
		case WASM_OP_I32TRUNCSF64:
		case WASM_OP_I32TRUNCUF64:
		case WASM_OP_I64EXTENDSI32:
		case WASM_OP_I64EXTENDUI32:
		case WASM_OP_I64TRUNCSF32:
		case WASM_OP_I64TRUNCUF32:
		case WASM_OP_I64TRUNCSF64:
		case WASM_OP_I64TRUNCUF64:
		case WASM_OP_F32CONVERTSI32:
		case WASM_OP_F32CONVERTUI32:
		case WASM_OP_F32CONVERTSI64:
		case WASM_OP_F32CONVERTUI64:
		case WASM_OP_F32DEMOTEF64:
		case WASM_OP_F64CONVERTSI32:
		case WASM_OP_F64CONVERTUI32:
		case WASM_OP_F64CONVERTSI64:
		case WASM_OP_F64CONVERTUI64:
		case WASM_OP_F64PROMOTEF32:
		case WASM_OP_I32REINTERPRETF32:
		case WASM_OP_I64REINTERPRETF64:
		case WASM_OP_F32REINTERPRETI32:
		case WASM_OP_F64REINTERPRETI64:
		case WASM_OP_END:
			{
				r_strbuf_set (sb, opdef->txt);
			}
			break;
		case WASM_OP_BLOCK:
		case WASM_OP_LOOP:
		case WASM_OP_IF:
			{
				st32 val = 0;
				size_t n = read_i32_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				switch (0x80 - val) {
				case R_BIN_WASM_VALUETYPE_EMPTY:
					r_strbuf_set (sb, opdef->txt);
					break;
				case R_BIN_WASM_VALUETYPE_i32:
					r_strbuf_setf (sb, "%s (result i32)", opdef->txt);
					break;
				case R_BIN_WASM_VALUETYPE_i64:
					r_strbuf_setf (sb, "%s (result i64)", opdef->txt);
					break;
				case R_BIN_WASM_VALUETYPE_f32:
					r_strbuf_setf (sb, "%s (result f32)", opdef->txt);
					break;
				case R_BIN_WASM_VALUETYPE_f64:
					r_strbuf_setf (sb, "%s (result f64)", opdef->txt);
					break;
				case R_BIN_WASM_VALUETYPE_v128:
					r_strbuf_setf (sb, "%s (result v128)", opdef->txt);
					break;
				default:
					r_strbuf_setf (sb, "%s (result ?)", opdef->txt);
					break;
				}
				op->len += n;
			}
			break;
		case WASM_OP_BR:
		case WASM_OP_BRIF:
		case WASM_OP_CALL:
			{
				ut32 val = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %d", opdef->txt, val);
				op->len += n;
			}
			break;
		case WASM_OP_BRTABLE:
			{
				ut32 count = 0, *table = NULL, def = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &count);
				if (!(n > 0 && n < buf_len && count < 0xffff)) {
					goto err;
				}
				if (!(table = calloc (count, sizeof (ut32)))) {
					goto err;
				}
				int i = 0;
				op->len += n;
				for (i = 0; i < count; i++) {
					n = read_u32_leb128 (buf + op->len, buf + buf_len, &table[i]);
					if (!(op->len + n <= buf_len)) {
						goto beach;
					}
					if (n < 1) {
						break;
					}
					op->len += n;
				}
				n = read_u32_leb128 (buf + op->len, buf + buf_len, &def);
				if (!(n > 0 && n + op->len < buf_len)) {
					goto beach;
				}
				op->len += n;
				r_strbuf_setf (sb, "%s %d ", opdef->txt, count);
				for (i = 0; i < count; i++) {
					r_strbuf_appendf (sb, "%d ", table[i]);
				}
				r_strbuf_appendf (sb, "%d", def);
				free (table);
				break;
			beach:
				free (table);
				goto err;
			}
			break;
		case WASM_OP_CALLINDIRECT:
			{
				ut32 val = 0, reserved = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				op->len += n;
				n = read_u32_leb128 (buf + op->len, buf + buf_len, &reserved);
				if (!(n == 1 && op->len + n <= buf_len)) {
					goto err;
				}
				reserved &= 0x1;
				r_strbuf_setf (sb, "%s %d %d", opdef->txt, val, reserved);
				op->len += n;
			}
			break;
		case WASM_OP_GETLOCAL:
		case WASM_OP_SETLOCAL:
		case WASM_OP_TEELOCAL:
		case WASM_OP_GETGLOBAL:
		case WASM_OP_SETGLOBAL:
			{
				ut32 val = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %d", opdef->txt, val);
				op->len += n;
			}
			break;
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
		case WASM_OP_I32STORE:
		case WASM_OP_I64STORE:
		case WASM_OP_F32STORE:
		case WASM_OP_F64STORE:
		case WASM_OP_I32STORE8:
		case WASM_OP_I32STORE16:
		case WASM_OP_I64STORE8:
		case WASM_OP_I64STORE16:
		case WASM_OP_I64STORE32:
			{
				ut32 flag = 0, offset = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &flag);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				op->len += n;
				n = read_u32_leb128 (buf + op->len, buf + buf_len, &offset);
				if (!(n > 0 && op->len + n <= buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %d %d", opdef->txt, flag, offset);
				op->len += n;
			}
			break;
		case WASM_OP_CURRENTMEMORY:
		case WASM_OP_GROWMEMORY:
			{
				ut32 reserved = 0;
				size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &reserved);
				if (!(n == 1 && n < buf_len)) {
					goto err;
				}
				reserved &= 0x1;
				r_strbuf_setf (sb, "%s %d", opdef->txt, reserved);
				op->len += n;
			}
			break;
		case WASM_OP_I32CONST:
			{
				st32 val = 0;
				size_t n = read_i32_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %" PFMT32d, opdef->txt, val);
				op->len += n;
			}
			break;
		case WASM_OP_I64CONST:
			{
				st64 val = 0;
				size_t n = read_i64_leb128 (buf + 1, buf + buf_len, &val);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %" PFMT64d, opdef->txt, val);
				op->len += n;
			}
			break;
		case WASM_OP_F32CONST:
			if (buf_len > 4) {
				union fi {
					ut32  v;
					float f;
				} u;
				u.v = r_read_at_le32 (buf, 1);
				r_strbuf_setf (sb, "%s %f", opdef->txt, u.f);
				op->len += 4;
			} else {
				goto err;
			}
			break;
		case WASM_OP_F64CONST:
			if (buf_len > 8) {
				union di {
					ut64   v;
					double f;
				} u;
				u.v = r_read_at_le64 (buf, 1);
				r_strbuf_setf (sb, "%s %f", opdef->txt, u.f);
				op->len += 8;
			} else {
				goto err;
			}
			break;
		default:
			goto err;
		}
	} else if (id == 0xfe) {
		op->type =  WASM_TYPE_OP_ATOMIC;
		if (buf_len < 2) goto err;
		op->len = 2;
		id = buf[1]; // skip 0xfe
		op->op.atomic = id;
		WasmOpDef *opdef = &opcodes_threads[id];
		switch (id) {
		case WASM_OP_I32ATOMICLOAD:
		case WASM_OP_I64ATOMICLOAD:
		case WASM_OP_I32ATOMICLOAD8U:
		case WASM_OP_I32ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD8U:
		case WASM_OP_I64ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD32U:
		case WASM_OP_I32ATOMICSTORE:
		case WASM_OP_I64ATOMICSTORE:
		case WASM_OP_I32ATOMICSTORE8:
		case WASM_OP_I32ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE8:
		case WASM_OP_I64ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE32:
		case WASM_OP_I32ATOMICRMWADD:
		case WASM_OP_I64ATOMICRMWADD:
		case WASM_OP_I32ATOMICRMW8UADD:
		case WASM_OP_I32ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW8UADD:
		case WASM_OP_I64ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW32UADD:
		case WASM_OP_I32ATOMICRMW8USUB:
		case WASM_OP_I32ATOMICRMW16USUB:
		case WASM_OP_I32ATOMICRMWSUB:
		case WASM_OP_I64ATOMICRMW8USUB:
		case WASM_OP_I64ATOMICRMW16USUB:
		case WASM_OP_I64ATOMICRMW32USUB:
		case WASM_OP_I64ATOMICRMWSUB:
		case WASM_OP_I32ATOMICRMWAND:
		case WASM_OP_I64ATOMICRMWAND:
		case WASM_OP_I32ATOMICRMW8UAND:
		case WASM_OP_I32ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW8UAND:
		case WASM_OP_I64ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW32UAND:
		case WASM_OP_I32ATOMICRMWOR:
		case WASM_OP_I64ATOMICRMWOR:
		case WASM_OP_I32ATOMICRMW8UOR:
		case WASM_OP_I32ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW8UOR:
		case WASM_OP_I64ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW32UOR:
		case WASM_OP_I32ATOMICRMWXOR:
		case WASM_OP_I64ATOMICRMWXOR:
		case WASM_OP_I32ATOMICRMW8UXOR:
		case WASM_OP_I32ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW8UXOR:
		case WASM_OP_I64ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW32UXOR:
		case WASM_OP_I32ATOMICRMWXCHG:
		case WASM_OP_I64ATOMICRMWXCHG:
		case WASM_OP_I32ATOMICRMW8UXCHG:
		case WASM_OP_I32ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW8UXCHG:
		case WASM_OP_I64ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW32UXCHG:
			{
				ut32 flag = 0, offset = 0;
				size_t n = read_u32_leb128 (buf + 2, buf + buf_len, &flag);
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				op->len += n;
				n = read_u32_leb128 (buf + op->len, buf + buf_len, &offset);
				if (!(n > 0 && op->len + n <= buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s %d %d", opdef->txt, flag, offset);
				op->len += n;
			}
			break;
		default:
			goto err;
		}
	} else if (id == 0xfd) {
		if (buf_len < 2) {
			goto err;
		}
		ut32 simdop;
		op->type = WASM_TYPE_OP_SIMD;
		size_t simdop_size = read_u32_leb128 (buf + 1, buf + buf_len, &simdop);
		if (simdop_size > buf_len) {
			goto err;
		}
		op->len = 1 + simdop_size;
		op->op.simd = simdop;
		id = simdop; // this isn't great because we're losing the sign
		// but it should never cause problems
		WasmOpDef *opdef = &opcodes_simd[id];
		switch (id) {
		case WASM_OP_I8X16SPLAT:
		case WASM_OP_I16X8SPLAT:
		case WASM_OP_I32X4SPLAT:
		case WASM_OP_I64X2SPLAT:
		case WASM_OP_F32X4SPLAT:
		case WASM_OP_F64X2SPLAT:
		case WASM_OP_I8X16EQ:
		case WASM_OP_I8X16NE:
		case WASM_OP_I8X16LTS:
		case WASM_OP_I8X16LTU:
		case WASM_OP_I8X16GTS:
		case WASM_OP_I8X16GTU:
		case WASM_OP_I8X16LES:
		case WASM_OP_I8X16LEU:
		case WASM_OP_I8X16GES:
		case WASM_OP_I8X16GEU:
		case WASM_OP_I16X8EQ:
		case WASM_OP_I16X8NE:
		case WASM_OP_I16X8LTS:
		case WASM_OP_I16X8LTU:
		case WASM_OP_I16X8GTS:
		case WASM_OP_I16X8GTU:
		case WASM_OP_I16X8LES:
		case WASM_OP_I16X8LEU:
		case WASM_OP_I16X8GES:
		case WASM_OP_I16X8GEU:
		case WASM_OP_I32X4EQ:
		case WASM_OP_I32X4NE:
		case WASM_OP_I32X4LTS:
		case WASM_OP_I32X4LTU:
		case WASM_OP_I32X4GTS:
		case WASM_OP_I32X4GTU:
		case WASM_OP_I32X4LES:
		case WASM_OP_I32X4LEU:
		case WASM_OP_I32X4GES:
		case WASM_OP_I32X4GEU:
		case WASM_OP_F32X4EQ:
		case WASM_OP_F32X4NE:
		case WASM_OP_F32X4LT:
		case WASM_OP_F32X4GT:
		case WASM_OP_F32X4LE:
		case WASM_OP_F32X4GE:
		case WASM_OP_F64X2EQ:
		case WASM_OP_F64X2NE:
		case WASM_OP_F64X2LT:
		case WASM_OP_F64X2GT:
		case WASM_OP_F64X2LE:
		case WASM_OP_F64X2GE:
		case WASM_OP_V128NOT:
		case WASM_OP_V128AND:
		case WASM_OP_V128OR:
		case WASM_OP_V128XOR:
		case WASM_OP_V128BITSELECT:
		case WASM_OP_I8X16NEG:
		case WASM_OP_I8X16ANYTRUE:
		case WASM_OP_I8X16ALLTRUE:
		case WASM_OP_I8X16SHL:
		case WASM_OP_I8X16SHRS:
		case WASM_OP_I8X16SHRU:
		case WASM_OP_I8X16ADD:
		case WASM_OP_I8X16ADDSATURATES:
		case WASM_OP_I8X16ADDSATURATEU:
		case WASM_OP_I8X16SUB:
		case WASM_OP_I8X16SUBSATURATES:
		case WASM_OP_I8X16SUBSATURATEU:
		case WASM_OP_I8X16MINS:
		case WASM_OP_I8X16MINU:
		case WASM_OP_I8X16MAXS:
		case WASM_OP_I8X16MAXU:
		case WASM_OP_I16X8NEG:
		case WASM_OP_I16X8ANYTRUE:
		case WASM_OP_I16X8ALLTRUE:
		case WASM_OP_I16X8SHL:
		case WASM_OP_I16X8SHRS:
		case WASM_OP_I16X8SHRU:
		case WASM_OP_I16X8ADD:
		case WASM_OP_I16X8ADDSATURATES:
		case WASM_OP_I16X8ADDSATURATEU:
		case WASM_OP_I16X8SUB:
		case WASM_OP_I16X8SUBSATURATES:
		case WASM_OP_I16X8SUBSATURATEU:
		case WASM_OP_I16X8MUL:
		case WASM_OP_I16X8MINS:
		case WASM_OP_I16X8MINU:
		case WASM_OP_I16X8MAXS:
		case WASM_OP_I16X8MAXU:
		case WASM_OP_I32X4NEG:
		case WASM_OP_I32X4ANYTRUE:
		case WASM_OP_I32X4ALLTRUE:
		case WASM_OP_I32X4SHL:
		case WASM_OP_I32X4SHRS:
		case WASM_OP_I32X4SHRU:
		case WASM_OP_I32X4ADD:
		case WASM_OP_I32X4SUB:
		case WASM_OP_I32X4MUL:
		case WASM_OP_I32X4MINS:
		case WASM_OP_I32X4MINU:
		case WASM_OP_I32X4MAXS:
		case WASM_OP_I32X4MAXU:
		case WASM_OP_I64X2NEG:
		case WASM_OP_I64X2SHL:
		case WASM_OP_I64X2SHRS:
		case WASM_OP_I64X2SHRU:
		case WASM_OP_I64X2ADD:
		case WASM_OP_I64X2SUB:
		case WASM_OP_I64X2MUL:
		case WASM_OP_F32X4ABS:
		case WASM_OP_F32X4NEG:
		case WASM_OP_F32X4SQRT:
		case WASM_OP_F32X4ADD:
		case WASM_OP_F32X4SUB:
		case WASM_OP_F32X4MUL:
		case WASM_OP_F32X4DIV:
		case WASM_OP_F32X4MIN:
		case WASM_OP_F32X4MAX:
		case WASM_OP_F64X2ABS:
		case WASM_OP_F64X2NEG:
		case WASM_OP_F64X2SQRT:
		case WASM_OP_F64X2ADD:
		case WASM_OP_F64X2SUB:
		case WASM_OP_F64X2MUL:
		case WASM_OP_F64X2DIV:
		case WASM_OP_F64X2MIN:
		case WASM_OP_F64X2MAX:
		case WASM_OP_I32X4TRUNCSATF32X4S:
		case WASM_OP_I32X4TRUNCSATF32X4U:
		case WASM_OP_F32X4CONVERTI32X4S:
		case WASM_OP_F32X4CONVERTI32X4U:
		case WASM_OP_V8X16SWIZZLE:
		case WASM_OP_I8X16NARROWI16X8S:
		case WASM_OP_I8X16NARROWI16X8U:
		case WASM_OP_I16X8NARROWI32X4S:
		case WASM_OP_I16X8NARROWI32X4U:
		case WASM_OP_I16X8WIDENLOWI8X16S:
		case WASM_OP_I16X8WIDENHIGHI8X16S:
		case WASM_OP_I16X8WIDENLOWI8X16U:
		case WASM_OP_I16X8WIDENHIGHI8X16U:
		case WASM_OP_I32X4WIDENLOWI16X8S:
		case WASM_OP_I32X4WIDENHIGHI16X8S:
		case WASM_OP_I32X4WIDENLOWI16X8U:
		case WASM_OP_I32X4WIDENHIGHI16X8U:
		case WASM_OP_V128ANDNOT:
		case WASM_OP_I8X16AVGRU:
		case WASM_OP_I16X8AVGRU:
		case WASM_OP_I8X16ABS:
		case WASM_OP_I16X8ABS:
		case WASM_OP_I32X4ABS:
			{
				r_strbuf_set (sb, opdef->txt);
			}
			break;
		case WASM_OP_V128LOAD:
		case WASM_OP_I16X8LOAD8X8S:
		case WASM_OP_I16X8LOAD8X8U:
		case WASM_OP_I32X4LOAD16X4S:
		case WASM_OP_I32X4LOAD16X4U:
		case WASM_OP_I64X2LOAD32X2S:
		case WASM_OP_I64X2LOAD32X2U:
		case WASM_OP_V8X16LOADSPLAT:
		case WASM_OP_V16X8LOADSPLAT:
		case WASM_OP_V32X4LOADSPLAT:
		case WASM_OP_V64X2LOADSPLAT:
		case WASM_OP_V128STORE:
			{
				ut32 offset = 0, align = 0;
				size_t n = read_u32_leb128 (buf + 1 + simdop_size, buf + buf_len, &offset);
				op->len += n;
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				n = read_u32_leb128 (buf + 1 + simdop_size + n, buf + buf_len, &align);
				op->len += n;
				if (!(n > 0 && n < buf_len)) {
					goto err;
				}
				r_strbuf_setf (sb, "%s o:%d a:2^%d", opdef->txt, offset, align);
			}
			break;
		case WASM_OP_V128CONST:
		case WASM_OP_V8X16SHUFFLE:
			{
				if (buf_len < 18) {
					goto err;
				}
				op->len += 16;
				unsigned char bytes[16] = { 0 };
				int i;
				for (i = 0; i < 16; ++i) {
					bytes[i] = buf[i + 1 + simdop_size];
				}
				r_strbuf_setf (sb, "%s %02x %02x %02x %02x %02x %02x %02x " \
						"%02x %02x %02x %02x %02x %02x %02x %02x %02x",
						opdef->txt, bytes[0], bytes[1], bytes[2], bytes[3],
						bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
						bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
						bytes[14], bytes[15]);
			}
			break;
		case WASM_OP_I8X16EXTRACTLANES:
		case WASM_OP_I8X16EXTRACTLANEU:
		case WASM_OP_I8X16REPLACELANE:
		case WASM_OP_I16X8EXTRACTLANES:
		case WASM_OP_I16X8EXTRACTLANEU:
		case WASM_OP_I16X8REPLACELANE:
		case WASM_OP_I32X4EXTRACTLANE:
		case WASM_OP_I32X4REPLACELANE:
		case WASM_OP_I64X2EXTRACTLANE:
		case WASM_OP_I64X2REPLACELANE:
		case WASM_OP_F32X4EXTRACTLANE:
		case WASM_OP_F32X4REPLACELANE:
		case WASM_OP_F64X2EXTRACTLANE:
		case WASM_OP_F64X2REPLACELANE:
			{
				if (buf_len < 3) {
					goto err;
				}
				unsigned char lane = buf[1 + simdop_size];
				++op->len;
				r_strbuf_setf (sb, "%s %d", opdef->txt, lane);
			}
			break;
		}
	} else {
		goto err;
	}
	op->txt = r_strbuf_drain (sb);
	return op->len;

  err:
	op->len = 1;
	r_strbuf_set (sb, "invalid");
	op->txt = r_strbuf_drain (sb);
	return op->len;
}
