/* radare - LGPL - Copyright 2017 - pancake */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int rep = 1;

	switch (buf[0]) {
	case 0x00:
		sprintf (op->buf_asm, "trap");
		break;
	case 0x01:
		sprintf (op->buf_asm, "nop");
		break;
	case 0x03:
		sprintf (op->buf_asm, "loop %d", buf[1]);
		rep = 2;
		break;
	case 0x05:
		sprintf (op->buf_asm, "else");
		break;
	case 0x0b:
		sprintf (op->buf_asm, "end");
		break;
	case 0x0f:
		sprintf (op->buf_asm, "return");
		break;
	case 0x10:
		{
			ut64 res = 0;
			const ut8 *afterBuf = r_uleb128 (buf, 8, &res);
			sprintf (op->buf_asm, "call %d", (int)res);
			rep = afterBuf - buf;
		}
		break;
	case 0x11:
		{
			ut64 res = 0;
			const ut8 *afterBuf = r_uleb128 (buf, 8, &res);
			sprintf (op->buf_asm, "call_indirect %d", (int)res);
			rep = afterBuf - buf;
		}
		break;
	case 0x20:
		sprintf (op->buf_asm, "get_local %d", buf[1]);
		rep = 2;
		break;
	case 0x21:
		sprintf (op->buf_asm, "set_local %d", buf[1]);
		rep = 2;
		break;
	case 0x22:
		sprintf (op->buf_asm, "tee_local %d", buf[1]);
		rep = 2;
		break;
	case 0x6a:
		sprintf (op->buf_asm, "i32.add");
		break;
	case 0x1a:
		sprintf (op->buf_asm, "drop");
		break;
	case 0x1b:
		sprintf (op->buf_asm, "select");
		break;
	case 0x41:
		{
			ut64 val = 0;
			const ut8 *nxt = r_uleb128 (buf + 1, len - 1, &val);
			sprintf (op->buf_asm, "i32.const 0x%08x", (st32)(val&UT32_MAX));
			rep = (size_t) (nxt - buf + 1);
		}
		break;
	case 0x42:
		{
			ut64 val = 0;
			const ut8 *nxt = r_uleb128 (buf + 1, len - 1, &val);
			sprintf (op->buf_asm, "i64.const 0x%08"PFMT64x, (st64)val);
			rep = (size_t) (nxt - buf + 1);
		}
		break;
	case 0x43:
		{
			ut32 val = r_read_le32 (buf + 1);
			sprintf (op->buf_asm, "f32.const 0x%08x", val);
		}
		break;
	case 0x44:
		{
			ut64 val = r_read_le64 (buf + 1);
			sprintf (op->buf_asm, "f64.const 0x%08"PFMT64x, val);
		}
		break;
	case 0x45:
		sprintf (op->buf_asm, "i32.eqz");
		break;
	case 0x46:
		sprintf (op->buf_asm, "i32.eq");
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
