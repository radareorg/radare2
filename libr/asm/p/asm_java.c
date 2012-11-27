/* radare - LGPL - Copyright 2009-2012 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../../shlr/java/code.h"
#include <r_core.h>

static const char *lastfile = NULL;
static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
	// XXX: crossmodule dependency
// TODO: get class info from rbin if loaded
#if 0
	RCore *core = (RCore*)a->user;
	if (core && core->file && lastfile != core->file->filename) {
		lastfile = core->file->filename;
		java_classdump (lastfile, 0);
	} else javasm_init ();
#endif
	return op->inst_len = r_java_disasm (buf, op->buf_asm, sizeof (op->buf_asm));
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	// TODO: get class info from bin if possible
	return op->inst_len = r_java_assemble (op->buf, buf);
}

RAsmPlugin r_asm_plugin_java = {
	.name = "java",
	.desc = "Java CLASS assembler/disassembler",
	.arch = "java",
	.bits = (int[]){ 8, 32, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_java
};
#endif
