/* radare - LGPL - Copyright 2017 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static const char * const opcodes[] = {
	// Control flow operators
	"trap",				// 0x00
	"nop",				// 0x01
	"block",			// 0x02
	"loop",				// 0x03
	"if",				// 0x04
	"else",				// 0x05
	NULL,NULL,NULL,NULL,NULL,
	"end",				// 0x0b
	"br",				// 0x0c
	"br_if",			// 0x0d
	"br_table",			// 0x0e
	"return",			// 0x0f
	// Call Operators
	"call",				// 0x10
	"call_indirect", 	// 0x11
	NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
	// Parametric operators
	"drop",				// 0x1a
	"select",			// 0x1b
	NULL,NULL,NULL,NULL,
	// Variable access
	"get_local",		// 0x20
	"set_local",		// 0x21
	"tee_local",		// 0x22
	"get_global",		// 0x23
	"set_global",		// 0x24
	NULL,NULL,NULL,
	// Memory-related operators
	"i32.load",			// 0x28
	"i64.load",			// 0x29
	"f32.load",			// 0x2a
	"f64.load",			// 0x2b
	"i32.load8_s",		// 0x2c
	"i32.load8_u",		// 0x2d
	"i32.load16_s",		// 0x2e
	"i64.load_16_u",	// 0x2f
	"i64.load8_s",		// 0x30
	"i64.load8_u",		// 0x31
	"i64.load16_s",		// 0x32
	"i64.load16_u",		// 0x33
	"i64.load32_s",		// 0x34
	"i64.load32_u",		// 0x35
	"i32.store",		// 0x36
	"i64.store",		// 0x37
	"f32.store",		// 0x38
	"f64.store",		// 0x39
	"i32.store8",		// 0x3a
	"i32.store16",		// 0x3b
	"i64.store8",		// 0x3c
	"i64.store16",		// 0x3d
	"i64.store32",		// 0x3e
	"current_memory",	// 0x3f
	"grow_memory",		// 0x40
	// Constants
	"i32.const",		// 0x41
	"i64.const",		// 0x42
	"f32.const",		// 0x43
	"f64.const",		// 0x44
	// Comparison operators
	"i32.eqz",			// 0x45
	"i32.eq",			// 0x46
	"i32.ne",			// 0x47
	"i32.lt_s",			// 0x48
	"i32.lt_u",			// 0x49
	"i32.gt_s",			// 0x4a
	"i32.gt_u",			// 0x4b
	"i32.le_s",			// 0x4c
	"i32.le_u",			// 0x4d
	"i32.ge_s",			// 0x4e
	"i32.ge_u",			// 0x4f
	"i64.eqz",			// 0x50
	"i64.eq",			// 0x51
	"i64.ne",			// 0x52
	"i64.lt_s",			// 0x53
	"i64.lt_u",			// 0x54
	"i64.gt_s",			// 0x55
	"i64.gt_u",			// 0x56
	"i64.le_s",			// 0x57
	"i64.le_u",			// 0x58
	"i64.ge_s",			// 0x59
	"i64.ge_u",			// 0x5a
	"f32.eq",			// 0x5b
	"f32.ne",			// 0x5c
	"f32.lt",			// 0x5d
	"f32.gt",			// 0x5e
	"f32.le",			// 0x5f
	"f32.ge",			// 0x60
	"f64.eq",			// 0x61
	"f64.ne",			// 0x62
	"f64.lt",			// 0x63
	"f64.gt",			// 0x64
	"f64.le",			// 0x65
	"f64.ge",			// 0x66
	// Numeric operators
	"i32.clz",			// 0x67
	"i32.ctz",			// 0x68
	"i32.popcnt",		// 0x69
	"i32.add",			// 0x6a
	"i32.sub",			// 0x6b
	"i32.mul",			// 0x6c
	"i32.div_s",		// 0x6d
	"i32.div_u",		// 0x6e
	"i32.rem_s",		// 0x6f
	"i32.rem_u",		// 0x7f
	"i32.and",			// 0x71
	"i32.or",			// 0x72
	"i32.xor",			// 0x73
	"i32.shl",			// 0x74
	"i32.shr_s",		// 0x75
	"i32.shr_u",		// 0x76
	"i32.rotl",			// 0x77
	"i32.rotr",			// 0x78
	"i64.clz",			// 0x79
	"i64.ctz",			// 0x7a
	"i64.popcnt",		// 0x7b
	"i64.add",			// 0x7c
	"i64.sub",			// 0x7d
	"i64.mul",			// 0x7e
	"i64.div_s",		// 0x7f
	"i64.div_u",		// 0x80
	"i64.rem_s",		// 0x81
	"i64.rem_u",		// 0x82
	"i64.and",			// 0x83
	"i64.or",			// 0x84
	"i64.xor",			// 0x85
	"i64.shl",			// 0x86
	"i64.shr_s",		// 0x87
	"i64.shr_u",		// 0x88
	"i64.rotl",			// 0x89
	"i64.rotr",			// 0x8a
	"f32.abs",			// 0x8b
	"f32.neg",			// 0x8c
	"f32.ceil",			// 0x8d
	"f32.floor",		// 0x8e
	"f32.trunc",		// 0x8f
	"f32.nearest",		// 0x90
	"f32.sqrt",			// 0x91
	"f32.add",			// 0x92
	"f32.sub",			// 0x93	
	"f32.mul",			// 0x94
	"f32.div",			// 0x95
	"f32.min",			// 0x96
	"f32.max",			// 0x97
	"f32.copysing",		// 0x98
	"f64.abs",			// 0x99
	"f64.neg",			// 0x9a
	"f64.ceil",			// 0x9b
	"f64.floor",		// 0x9c
	"f64.trunc",		// 0x9d
	"f64.nearest",		// 0x9e
	"f64.sqrt",			// 0x9f
	"f64.add",			// 0xa0
	"f64.sub",			// 0xa1
	"f64.mul",			// 0xa2
	"f64.div",			// 0xa3
	"f64.min",			// 0xa4
	"f64.max",			// 0xa5
	"f64.copysing",		// 0xa6
	// Conversions
	"i32.wrap/i64",		// 0xa7
	"i32.trunc_s/f32",	// 0xa8
	"i32.trunc_u/f32",	// 0xa9
	"i32.trunc_s/f64",	// 0xaa
	"i32.trunc_u/f64",	// 0xab
	"i64.extend_s/i32",	// 0xac
	"i64.extend_u/i32",	// 0xad
	"i64.trunc_s/f32",	// 0xae
	"i64.trunc_u/f32",	// 0xaf
	"i64.trunc_s/f64",	// 0xb0
	"i64.trunc_u/f64",	// 0xb1
	"f32.convert_s/i32",// 0xb2
	"f32.convert_u/i32",// 0xb3
	"f32.convert_s/i64",// 0xb4
	"f32.convert_u/i64",// 0xb5
	"f32.demote/f64",	// 0xb6
	"f64.convert_s/i32",// 0xb7
	"f64.convert_u/i32",// 0xb8
	"f64.convert_s/i64",// 0xb9
	"f64.convert_u/i64",// 0xba
	"f64.promote/f32",	// 0xbb
	// Reuinterpretations
	"i32.reinterpret/f32", // 0xbc
	"i64.reinterpret/f64", // 0xbd
	"f32.reinterpret/i32", // 0xbe
	"f64/reinterpret/i64", // 0xbf
	// moar...
};

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int rep = 1;

	if (len < 1) goto err;

	ut8 o = buf[0];

	switch (o) {
	case 0x00:
	case 0x01:
	case 0x05:
	case 0x0b:
	case 0x0f:
	case 0x1a:
	case 0x1b:
	case 0x45:
	case 0x46:
	case 0x47:
	case 0x48:
	case 0x49:
	case 0x4a:
	case 0x4b:
	case 0x4c:
	case 0x4d:
	case 0x4e:
	case 0x4f:
	case 0x50:
	case 0x51:
	case 0x52:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x58:
	case 0x59:
	case 0x5a:
	case 0x5b:
	case 0x5c:
	case 0x5d:
	case 0x5e:
	case 0x5f:
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0x68:
	case 0x69:
	case 0x6a:
	case 0x6b:
	case 0x6c:
	case 0x6d:
	case 0x6e:
	case 0x6f:
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7a:
	case 0x7b:
	case 0x7c:
	case 0x7d:
	case 0x7e:
	case 0x7f:
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8a:
	case 0x8b:
	case 0x8c:
	case 0x8d:
	case 0x8e:
	case 0x8f:
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x96:
	case 0x97:
	case 0x98:
	case 0x99:
	case 0x9a:
	case 0x9b:
	case 0x9c:
	case 0x9d:
	case 0x9e:
	case 0x9f:
	case 0xa0:
	case 0xa1:
	case 0xa2:
	case 0xa3:
	case 0xa4:
	case 0xa5:
	case 0xa6:
	case 0xa7:
	case 0xa8:
	case 0xa9:
	case 0xaa:
	case 0xab:
	case 0xac:
	case 0xad:
	case 0xae:
	case 0xaf:
	case 0xb0:
	case 0xb1:
	case 0xb2:
	case 0xb3:
	case 0xb4:
	case 0xb5:
	case 0xb6:
	case 0xb7:
	case 0xb8:
	case 0xb9:
	case 0xba:
	case 0xbb:
	case 0xbc:
	case 0xbd:
	case 0xbe:
	case 0xbf:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", opcodes[o]);
		break;
	case 0x02:
	case 0x03:
	case 0x04:
		{
			if (len >= 2) {
				if (buf[1] == 0x40) {
					snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", opcodes[o]);
				} else {
					// TODO: block_type (value_type)
					snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s ...", opcodes[o]);
				}
				rep = 2;
			}
		}
		break;
	case 0x0c:
	case 0x0d:
	case 0x10:
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d", opcodes[o], val);
				rep += n;
			}
		}
		break;
	case 0x0e:
		{
			// TODO: br_table
			ut32 count = 0, table = 0, def = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &count);
			if (n > 0 && n < len) {
				rep += n;
				int i;
				for (i = 0; i < count; i++) {
						n = read_u32_leb128 (buf + n + 1, buf + len, &table);
						if (!n || len < rep + n) break;
						rep += n;
				}
				n = read_u32_leb128 (buf + n + 1, buf + len, &count);
				if (n > 0 && n + rep < len) {
					snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d ... %d", opcodes[o], count, def);
					rep += n;
				}
			}
		}
		break;
	case 0x11:
		{
			ut32 val = 0, reserved = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len)  {
				rep += n;
				n = read_u32_leb128 (buf + n + 1, buf + len, &reserved);
				if (n == 1 || n + rep < len)  {
					reserved &= 0x1;
					snprintf (op->buf_asm, R_ASM_BUFSIZE, "call_indirect %d %d", val, reserved);
				}
			}
		}
		break;
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d", opcodes[o], val);
				rep += n;
			}
		}
		break;
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37:
	case 0x38:
	case 0x39:
	case 0x3a:
	case 0x3b:
	case 0x3c:
	case 0x3d:
	case 0x3e:
		{
			ut32 flag = 0, offset = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &flag);
			if (n > 0 && n < len) {
				rep += n;
				size_t m = read_u32_leb128 (buf + 1 + n, buf + len, &offset);
				if (m > 0 && rep + m < len) {
					snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d %d", opcodes[o], flag, offset);
					rep += m;
				}
			}
		}
		break;
	case 0x3f: 
	case 0x40: 
		{
			ut32 reserved = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &reserved);
			if (n == 1 && n < len) {
				reserved &= 0x1;
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d", opcodes[o], reserved); 
				rep += n;
			}
		}
		break;

	case 0x41:
		{
			st32 val = 0;
			size_t n = read_i32_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %" PRId32, opcodes[o], val);
				rep += n;
			}
		}
		break;
	case 0x42:
		{
			st64 val = 0;
			size_t n = read_i64_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %" PRId64, opcodes[o], val);
				rep += n;
			}
		}
		break;
	case 0x43:
		{
			ut32 val = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %" PFMT32d, opcodes[o], val);
				rep += n;
			}
		}
		break;
	case 0x44:
		{
			ut64 val = 0;
			size_t n = read_u64_leb128 (buf + 1, buf + len, &val);
			if (n > 0 && n < len) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %" PFMT64d, opcodes[o], val);
				rep += n;
			}
		}
		break;
	default:
		break;

	}

err:
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
