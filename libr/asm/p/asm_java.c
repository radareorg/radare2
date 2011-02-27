/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <java/javasm/javasm.h>

#include <r_core.h>
static const char *lastfile = NULL;
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {
	// XXX: crossmodule dependency
	RCore *core = (RCore*)a->user;
	if (core && core->file && lastfile != core->file->filename) {
		lastfile = core->file->filename;
		java_classdump (lastfile, 0);
	} else javasm_init ();
	return op->inst_len = java_disasm (buf, op->buf_asm);
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->inst_len = java_assemble (op->buf, buf);
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
