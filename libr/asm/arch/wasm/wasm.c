/* radare - LGPL - Copyright 2017 - pancake, cgvwzq */

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
	[WASM_OP_F64REINTERPRETI64] = { "f64/reinterpret/i64", 1, 1 }
};

int wasm_asm(const char *str, unsigned char *buf, int buf_len) {
	// TODO: add immediates assembly
	int i = 0, len = -1;
	char tmp[R_ASM_BUFSIZE];
	while (str[i] != ' ' && i < buf_len) {
		tmp[i] = str[i];
		i++;
	}
	tmp[i] = 0;
	for (i = 0; i < 0xff; i++) {
		WasmOpDef *opdef = &opcodes[i];
		if (opdef->txt) {
			if (!strcmp (opdef->txt, tmp)) {
				buf[0] = i;
				return 1;
			}
		}
	}
	return len;
}

int wasm_dis(WasmOp *op, const unsigned char *buf, int buf_len) {
	op->len = 1;
	op->op = buf[0];
	if (op->op > 0xbf) {
		return 1;
	}
	// add support for extension opcodes (SIMD + atomics)
	WasmOpDef *opdef = &opcodes[op->op];
	switch (op->op) {
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s", opdef->txt);
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
				snprintf (op->txt, R_ASM_BUFSIZE, "%s", opdef->txt);
				break;
			case R_BIN_WASM_VALUETYPE_i32:
				snprintf (op->txt, R_ASM_BUFSIZE, "%s (result i32)", opdef->txt);
				break;
			case R_BIN_WASM_VALUETYPE_i64:
				snprintf (op->txt, R_ASM_BUFSIZE, "%s (result i64)", opdef->txt);
				break;
			case R_BIN_WASM_VALUETYPE_f32:
				snprintf (op->txt, R_ASM_BUFSIZE, "%s (result f32)", opdef->txt);
				break;
			case R_BIN_WASM_VALUETYPE_f64:
				snprintf (op->txt, R_ASM_BUFSIZE, "%s (result f64)", opdef->txt);
				break;
			default:
				snprintf (op->txt, R_ASM_BUFSIZE, "%s (result ?)", opdef->txt);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d", opdef->txt, val);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d ", opdef->txt, count);
			char *txt = op->txt;
			int txtLen = strlen (op->txt);
			int txtLeft = R_ASM_BUFSIZE - txtLen;
			txt += txtLen;
			for (i = 0; i < count && txtLen + 10 < R_ASM_BUFSIZE; i++) {
				snprintf (txt, txtLeft, "%d ", table[i]);
				txtLen = strlen (txt);
				txt += txtLen;
				txtLeft -= txtLen;
			}
			snprintf (txt, txtLeft - 1, "%d", def);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d %d", opdef->txt, val, reserved);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d", opdef->txt, val);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d %d", opdef->txt, flag, offset);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d", opdef->txt, reserved);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %" PFMT32d, opdef->txt, val);
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
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %" PFMT64d, opdef->txt, val);
			op->len += n;
		}
		break;
	case WASM_OP_F32CONST:
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &val);
			if (!(n > 0 && n < buf_len)) {
				goto err;
			}
			long double d =  (long double)val;
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %" LDBLFMT, opdef->txt, d);
			op->len += n;
		}
		break;
	case WASM_OP_F64CONST:
		{
			ut64 val = 0;
			size_t n = read_u64_leb128 (buf + 1, buf + buf_len, &val);
			if (!(n > 0 && n < buf_len)) {
				goto err;
			}
			long double d =  (long double)val;
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %" LDBLFMT, opdef->txt, d);
			op->len += n;
		}
		break;
	default:
		goto err;
	}

	return op->len;

err:
	op->len = 1;
	snprintf (op->txt, R_ASM_BUFSIZE, "invalid");
	return op->len;
}
