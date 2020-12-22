/* radare - LGPL - Copyright 2017-2018 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/wasm/wasm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	WasmOp wop = {{0}};
	int ret = wasm_dis (&wop, buf, len);
	r_asm_op_set_asm (op, wop.txt);
	free (wop.txt);
	op->size = ret;
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	ut8 *opbuf = (ut8*)r_strbuf_get (&op->buf);
	op->size = wasm_asm (buf, opbuf, 32); // XXX hardcoded opsize
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_wasm,
	.version = R2_VERSION
};
#endif
