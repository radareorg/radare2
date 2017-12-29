/* radare - LGPL - Copyright 2017 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/wasm/wasm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	WasmOp wop = {0};
	int ret = wasm_dis (&wop, buf, len);
	strncpy (op->buf_asm, wop.txt, sizeof (op->buf_asm));
	op->buf_asm[sizeof (op->buf_asm) - 1] = 0;
	op->size = ret;
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	op->size = wasm_asm (buf, op->buf, sizeof (op->buf));
	return op->size;
}

RAsmPlugin r_asm_plugin_wasm = {
	.name = "wasm",
	.author = "cgvwzq",
	.version = "0.1.0",
	.arch = "wasm",
	.license = "MIT",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "WebAssembly",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_wasm,
	.version = R2_VERSION
};
#endif
