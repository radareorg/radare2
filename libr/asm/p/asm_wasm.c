/* radare - LGPL - Copyright 2017 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int rep = 1;

	switch (buf[0]) {

	// Control flow operators 
	case 0x00:
		// unreachable
		// trap immediately
		sprintf (op->buf_asm, "trap");
		break;
	case 0x01:
		// nop
		// no operation
		sprintf (op->buf_asm, "nop");
		break;
	case 0x02:
		// block sig {block_type}
		// begin a sequence of expressions, yielding 0 or 1 values
		sprintf (op->buf_asm, "block");
		rep = 2;
		break;
	case 0x03:
		// loop sig {block_type}
		// begin a block which can also form control flow loops
		sprintf (op->buf_asm, "loop %d", buf[1]);
		rep = 2;
		break;
	case 0x04:
		// if sig {block_type}
		// begin if expression
		sprintf (op->buf_asm, "if");
		break;
	case 0x05:
		// else sig {block_type}
		// begin else expression of if
		sprintf (op->buf_asm, "else");
		break;
	case 0x0b:
		// end
		// end a block, loop, or if
		sprintf (op->buf_asm, "end");
		break;
	case 0x0c:
		// br @relative_depth {varuint32}
		// break that targets an outer nested block
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "br 0x%04x", val);
			rep += n;
		}
		break;
	case 0x0d:
		// br_if @relative_depth {varuint32}
		// conditional break that targets an outer nested block
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "br_if 0x%04x", val);
			rep += n;
		}
		break;
	case 0x0e:
		// br_table TODO
		// branch table control flow construct
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "br_table 0x%04x", val);
			rep += n;
		}
		break;
	case 0x0f:
		// return
		// return zero or one value from this function
		sprintf (op->buf_asm, "return");
		break;


	// Call operators 
	case 0x10:
		// call @function_index {varuint32}
		// call a function by its index
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "call 0x%04x", val);
			rep += n;
		}
		break;
	case 0x11:
		// call_indirect @type_index {varuint32}, reserved: {varuint1}
		// call a function indirect with an expected signature
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "call_indirect 0x%04x", val);
			rep += n;
		}
		break;


	// Parametric operators
	case 0x1a:
		// drop
		// ignore value
		sprintf (op->buf_asm, "drop");
		break;
	case 0x1b:
		// select
		// select one of two values based on condition
		sprintf (op->buf_asm, "select");
		break;


	// Variable access
	case 0x20:
		// get_local @local_index {varuint32}
		// read a local variable or parameter
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "get_local 0x%04x", val);
			rep += n;
		}
		break;
	case 0x21:
		// set_local @local_index {varuint32}
		// write a local variable or parameter
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "set_local 0x%04x", val);
			rep += n;
		}
		break;
	case 0x22:
		// tee_local @local_index {varuint32}
		// write a local variable or parameter and return the same value
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "tee_local 0x%04x", val);
			rep += n;
		}
		break;
	case 0x23:
		// get_global @global_index {varuint32}
		// read a global variable
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "get_global 0x%04x", val);
			rep += n;
		}
		break;
	case 0x24:
		// set_global @global_index {varuint32}
		// write a global variable
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "set_global 0x%04x", val);
			rep += n;
		}
		break;


	// Memory-related operators
	case 0x28:
		// i32.load memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.load 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x29:
		// i64.load memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2a:
		// f32.load memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "f32.load 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2b:
		// f64.load memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "f64.load 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2c:
		// i32.load8_s memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.load8_s 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2d:
		// i32.load8_u memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.load8_u 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2e:
		// i32.load16_s memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.load16_s 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x2f:
		// i32.load16_u memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load16_u 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x30:
		// i64.load8_s memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load8_s 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x31:
		// i64.load8_u memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load8_u 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x32:
		// i64.load16_s memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load16_s 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x33: 
		// i64.load16_u memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load16_u 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x34: 
		// i64.load32_s memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load32_s 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x35: 
		// i64.load32_u memory_inmediate {varuint32 | varuint32}
		// load from memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.load32_u 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x36: 
		// i32.store memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.store 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x37: 
		// i64.store memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.store 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x38: 
		// f32.store memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "f64.store 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x39: 
		// f64.store memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "f64.store 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3a: 
		// i32.store8 memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.store8 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3b: 
		// i32.store16 memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i32.store16 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3c: 
		// i64.store8 memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.store8 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3d: 
		// i64.store16 memory_inmediate {varuint32 | varuint32}
		// store to memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.store16 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3e: 
		// i64.store32 memory_inmediate {varuint32 | varuint32}
		// store memory
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
			sprintf (op->buf_asm, "i64.store32 0x%04x 0x%04x", flag, offset);
			rep += n + m;
		}
		break;
	case 0x3f: 
		// current_memory {varuint1}
		// query the size of memory
		sprintf (op->buf_asm, "current_memory"); 
		break;
	case 0x40: 
		// grow_memory {varuint1}
		// grow the size of memory
		sprintf (op->buf_asm, "grow_memory"); 
		break;


	// Constants
	case 0x41:
		// i32.const value {varint32}
		// a constant value interpreted as i32
		{
			st32 val = 0;
			size_t n = read_i32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "i32.const 0x%04x", val);
			rep += n;
		}
		break;
	case 0x42:
		// i64.const value {varint64}
		// a constant value interpreted as i64
		{
			st64 val = 0;
			size_t n = read_i64_leb128 (buf + 1, buf + len, &val);
			if (val < 1) {
				sprintf (op->buf_asm, "i64.const %" PFMT64d, val);
			} else {
				sprintf (op->buf_asm, "i64.const 0x%08" PFMT64x, val);
			}
			rep += n;
		}
		break;
	case 0x43:
		// f32.const value {uint32}
		// a constant value interpreted as f32
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "f32.const 0x%04"PFMT32x, val);
			rep += n;
		}
		break;
	case 0x44:
		// f64.const value {uint64}
		// a constant value interpreted as f64
		{
			ut64 val = 0;
			size_t n = read_u64_leb128 (buf + 1, buf + len, &val);
			sprintf (op->buf_asm, "f64.const 0x%08"PFMT64x, val);
			rep += n;
		}
		break;


	// Comparison operators
	case 0x45:
		// i32.eqz
		sprintf (op->buf_asm, "i32.eqz");
		break;
	case 0x46:
		// i32.eq
		sprintf (op->buf_asm, "i32.eq");
		break;
	case 0x47:
		// i32.ne 
		sprintf (op->buf_asm, "i32.ne");
		break;
	case 0x48:
		// i32.lt_s
		sprintf (op->buf_asm, "i32.lt_s");
		break;
	case 0x49:
		// i32.lt_u
		sprintf (op->buf_asm, "i32.lt_u");
		break;
	case 0x4a:
		// i32.gt_s
		sprintf (op->buf_asm, "i32.gt_s");
		break;
	case 0x4b:
		// i32.gt_u
		sprintf (op->buf_asm, "i32.gt_u");
		break;
	case 0x4c:
		// i32.le_s
		sprintf (op->buf_asm, "i32.le_s");
		break;
	case 0x4d:
		// i32.le_u
		sprintf (op->buf_asm, "i32.le_u");
		break;
	case 0x4e:
		// i32.ge_s
		sprintf (op->buf_asm, "i32.ge_s");
		break;
	case 0x4f:
		// i32.ge_u
		sprintf (op->buf_asm, "i32.ge_u");
		break;
	case 0x50:
		// i64.eqz
		sprintf (op->buf_asm, "i64.eqz");
		break;
	case 0x51:
		// i64.eq
		sprintf (op->buf_asm, "i64.eq");
		break;
	case 0x52:
		// i64.ne
		sprintf (op->buf_asm, "i64.ne");
		break;
	case 0x53:
		// i64.lt_s
		sprintf (op->buf_asm, "i64.lt_s");
		break;
	case 0x54:
		// i64.lt_u
		sprintf (op->buf_asm, "i64.lt_u");
		break;
	case 0x55:
		// i64.gt_s
		sprintf (op->buf_asm, "i64.gt_s");
		break;
	case 0x56:
		// i64.gt_u
		sprintf (op->buf_asm, "i64.gt_u");
		break;
	case 0x57:
		// i64.le_s
		sprintf (op->buf_asm, "i64.le_s");
		break;
	case 0x58:
		// i64.le_u
		sprintf (op->buf_asm, "i64.le_u");
		break;
	case 0x59:
		// i64.ge_s
		sprintf (op->buf_asm, "i64.ge_s");
		break;
	case 0x5a:
		// i64.ge_u
		sprintf (op->buf_asm, "i64.ge_u");
		break;
	case 0x5b:
		// f32.eq
		sprintf (op->buf_asm, "f32.eq");
		break;
	case 0x5c:
		// f32.ne
		sprintf (op->buf_asm, "f32.ne");
		break;
	case 0x5d:
		// f32.lt
		sprintf (op->buf_asm, "f32.lt");
		break;
	case 0x5e:
		// f32.gt
		sprintf (op->buf_asm, "f32.gt");
		break;
	case 0x5f:
		// f32.le
		sprintf (op->buf_asm, "f32.le");
		break;
	case 0x60:
		// f32.ge
		sprintf (op->buf_asm, "f32.ge");
		break;
	case 0x61:
		// f64.eq
		sprintf (op->buf_asm, "f64.eq");
		break;
	case 0x62:
		// f64.ne
		sprintf (op->buf_asm, "f64.ne");
		break;
	case 0x63:
		// f64.lt
		sprintf (op->buf_asm, "f64.lt");
		break;
	case 0x64:
		// f64.gt
		sprintf (op->buf_asm, "f64.gt");
		break;
	case 0x65:
		// f64.le
		sprintf (op->buf_asm, "f64.le");
		break;
	case 0x66:
		// f64.ge
		sprintf (op->buf_asm, "f64.ge");
		break;


	// Numeric operators
	case 0x67:
		// i32.clz
		sprintf (op->buf_asm, "i32.clz");
		break;
	case 0x68:
		// i32.ctz
		sprintf (op->buf_asm, "i32.ctz");
		break;
	case 0x69:
		// i32.popcnt
		sprintf (op->buf_asm, "i32.popcnt");
		break;
	case 0x6a:
		// i32.add
		sprintf (op->buf_asm, "i32.add");
		break;
	case 0x6b:
		// i32.sub
		sprintf (op->buf_asm, "i32.sub");
		break;
	case 0x6c:
		// i32.mul
		sprintf (op->buf_asm, "i32.mul");
		break;
	case 0x6d:
		// i32.div_s
		sprintf (op->buf_asm, "i32.div_s");
		break;
	case 0x6e:
		// i32.div_u
		sprintf (op->buf_asm, "i32.div_u");
		break;
	case 0x6f:
		// i32.rem_s
		sprintf (op->buf_asm, "i32.rem_s");
		break;
	case 0x70:
		// i32.rem_u
		sprintf (op->buf_asm, "i32.rem_u");
		break;
	case 0x71:
		// i32.and
		sprintf (op->buf_asm, "i32.and");
		break;
	case 0x72:
		// i32.or
		sprintf (op->buf_asm, "i32.or");
		break;
	case 0x73:
		// i32.xor
		sprintf (op->buf_asm, "i32.xor");
		break;
	case 0x74:
		// i32.shl
		sprintf (op->buf_asm, "i32.shl");
		break;
	case 0x75:
		// i32.shr_s
		sprintf (op->buf_asm, "i32.shr_s");
		break;
	case 0x76:
		// i32.shr_u
		sprintf (op->buf_asm, "i32.shr_u");
		break;
	case 0x77:
		// i32.rotl
		sprintf (op->buf_asm, "i32.rotl");
		break;
	case 0x78:
		// i32.rotr
		sprintf (op->buf_asm, "i32.rotr");
		break;
	case 0x79:
		// i64.clz
		sprintf (op->buf_asm, "i64.clz");
		break;
	case 0x7a:
		// i64.ctz
		sprintf (op->buf_asm, "i64.ctz");
		break;
	case 0x7b:
		// i64.popcnt
		sprintf (op->buf_asm, "i64.popcnt");
		break;
	case 0x7c:
		// i64.add
		sprintf (op->buf_asm, "i64.add");
		break;
	case 0x7d:
		// i64.sub
		sprintf (op->buf_asm, "i64.sub");
		break;
	case 0x7e:
		// i64.mul
		sprintf (op->buf_asm, "i64.mul");
		break;
	case 0x7f:
		// i64.div_s
		sprintf (op->buf_asm, "i64.div_s");
		break;
	case 0x80:
		// i64.div_u
		sprintf (op->buf_asm, "i64.div_u");
		break;
	case 0x81:
		// i64.rem_s
		sprintf (op->buf_asm, "i64.rem_s");
		break;
	case 0x82:
		// i64.rem_u
		sprintf (op->buf_asm, "i64.rem_u");
		break;
	case 0x83:
		// i64.and
		sprintf (op->buf_asm, "i64.and");
		break;
	case 0x84:
		// i64.or
		sprintf (op->buf_asm, "i64.or");
		break;
	case 0x85:
		// i64.xor
		sprintf (op->buf_asm, "i64.xor");
		break;
	case 0x86:
		// i64.shl
		sprintf (op->buf_asm, "i64.shl");
		break;
	case 0x87:
		// i64.shr_s
		sprintf (op->buf_asm, "i64.shr_s");
		break;
	case 0x88:
		// i64.shr_u
		sprintf (op->buf_asm, "i64.shr_u");
		break;
	case 0x89:
		// i64.rotl
		sprintf (op->buf_asm, "i64.rotl");
		break;
	case 0x8a:
		// i64.rotr
		sprintf (op->buf_asm, "i64.rotr");
		break;
	case 0x8b:
		// f32.abs
		sprintf (op->buf_asm, "f32.abs");
		break;
	case 0x8c:
		// f32.neg
		sprintf (op->buf_asm, "f32.neg");
		break;
	case 0x8d:
		// f32.ceil
		sprintf (op->buf_asm, "f32.ceil");
		break;
	case 0x8e:
		// f32.floor
		sprintf (op->buf_asm, "f32.floor");
		break;
	case 0x8f:
		// f32.trunc
		sprintf (op->buf_asm, "f32.trunc");
		break;
	case 0x90:
		// f32.nearest
		sprintf (op->buf_asm, "f32.nearest");
		break;
	case 0x91:
		// f32.sqrt
		sprintf (op->buf_asm, "f32.sqrt");
		break;
	case 0x92:
		// f32.add
		sprintf (op->buf_asm, "f32.add");
		break;
	case 0x93:
		// f32.sub
		sprintf (op->buf_asm, "f32.sub");
		break;
	case 0x94:
		// f32.mul
		sprintf (op->buf_asm, "f32.mul");
		break;
	case 0x95:
		// f32.div
		sprintf (op->buf_asm, "f32.div");
		break;
	case 0x96:
		// f32.min
		sprintf (op->buf_asm, "f32.min");
		break;
	case 0x97:
		// f32.max
		sprintf (op->buf_asm, "f32.max");
		break;
	case 0x98:
		// f32.copysign
		sprintf (op->buf_asm, "f32.copysign");
		break;
	case 0x99:
		// f64.abs
		sprintf (op->buf_asm, "f64.abs");
		break;
	case 0x9a:
		// f64.neg
		sprintf (op->buf_asm, "f64.neg");
		break;
	case 0x9b:
		// f64.ceil
		sprintf (op->buf_asm, "f64.ceil");
		break;
	case 0x9c:
		// f64.floor
		sprintf (op->buf_asm, "f64.floor");
		break;
	case 0x9d:
		// f64.trunc
		sprintf (op->buf_asm, "f64.trunc");
		break;
	case 0x9e:
		// f64.nearest
		sprintf (op->buf_asm, "f64.nearest");
		break;
	case 0x9f:
		// f64.sqrt
		sprintf (op->buf_asm, "f64.sqrt");
		break;
	case 0xa0:
		// f64.add
		sprintf (op->buf_asm, "f64.add");
		break;
	case 0xa1:
		// f64.sub
		sprintf (op->buf_asm, "f64.sub");
		break;
	case 0xa2:
		// f64.mul
		sprintf (op->buf_asm, "f64.mul");
		break;
	case 0xa3:
		// f64.div
		sprintf (op->buf_asm, "f64.div");
		break;
	case 0xa4:
		// f64.min
		sprintf (op->buf_asm, "f64.min");
		break;
	case 0xa5:
		// f64.max
		sprintf (op->buf_asm, "f64.max");
		break;
	case 0xa6:
		// f64.copysign
		sprintf (op->buf_asm, "f64.copysign");
		break;


	// Conversions
	case 0xa7:
		// i32.wrap/i64
		sprintf (op->buf_asm, "i32.wrap/i64");
		break;
	case 0xa8:
		// i32.trunc_s/f32
		sprintf (op->buf_asm, "i32.trunc_s/f32");
		break;
	case 0xa9:
		// i32.trunc_u/f32
		sprintf (op->buf_asm, "i32.trunc_u/f32");
		break;
	case 0xaa:
		// i32.trunc_s/f64
		sprintf (op->buf_asm, "i32.trunc_s/f64");
		break;
	case 0xab:
		// i32.trunc_u/f64
		sprintf (op->buf_asm, "i32.trunc_u/f64");
		break;
	case 0xac:
		// i64.extend_s/i32
		sprintf (op->buf_asm, "i64.extend_s/i32");
		break;
	case 0xad:
		// i64.extend_u/i32
		sprintf (op->buf_asm, "i64.extend_u/i32");
		break;
	case 0xae:
		// i64.trunc_s/f32
		sprintf (op->buf_asm, "i64.trunc_s/f32");
		break;
	case 0xaf:
		// i64.trunc_u/f32
		sprintf (op->buf_asm, "i64.trunc_u/f32");
		break;
	case 0xb0:
		// i64.trunc_s/f64
		sprintf (op->buf_asm, "i64.trunc_s/f64");
		break;
	case 0xb1:
		// i64.trunc_u/f64
		sprintf (op->buf_asm, "i64.trunc_u/f64");
		break;
	case 0xb2:
		// f32.convert_s/i32
		sprintf (op->buf_asm, "f32.convert_s/i32");
		break;
	case 0xb3:
		// f32.convert_u/i32
		sprintf (op->buf_asm, "f32.convert_u/i32");
		break;
	case 0xb4:
		// f32.convert_s/i64
		sprintf (op->buf_asm, "f32.convert_s/i64");
		break;
	case 0xb5:
		// f32.convert_u/i64
		sprintf (op->buf_asm, "f32.convert_u/i64");
		break;
	case 0xb6:
		// f32.demote/f64
		sprintf (op->buf_asm, "f32.demote/f64");
		break;
	case 0xb7:
		// f64.convert_s/i32
		sprintf (op->buf_asm, "f64.convert_s/i32");
		break;
	case 0xb8:
		// f64.convert_u/i32
		sprintf (op->buf_asm, "f64.convert_u/i32");
		break;
	case 0xb9:
		// f64.convert_s/i64
		sprintf (op->buf_asm, "f64.convert_s/i64");
		break;
	case 0xba:
		// f64.convert_u/i64
		sprintf (op->buf_asm, "f64.convert_u/i64");
		break;
	case 0xbb:
		// f64.promote/f32
		sprintf (op->buf_asm, "f64.promote/f32");
		break;


	// Reinterpretations
	case 0xbc:
		// i32.reinterpret/f32
		sprintf (op->buf_asm, "i32.reinterpret/f32");
		break;
	case 0xbd:
		// i64.reinterpret/f64
		sprintf (op->buf_asm, "i64.reinterpret/f64");
		break;
	case 0xbe:
		// f32.reinterpret/i32
		sprintf (op->buf_asm, "f32.reinterpret/i32");
		break;
	case 0xbf:
		// f64.reinterpret/i64
		sprintf (op->buf_asm, "f64.reinterpret/i64");
		break;


	// moar...
	default:
		break;

	}

	op->size = rep;
	return rep;
}

RAsmPlugin r_asm_plugin_wasm = {
	.name = "wasm",
	.author = "pancake",
	.version = "0.1.0",
	.arch = "wasm",
	.license = "MIT",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "WebAssembly",
	.disassemble = &disassemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_wasm,
	.version = R2_VERSION
};
#endif
