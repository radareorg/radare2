/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"
#include <r_core.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	//void *cp;
	RBinJavaObj *obj = NULL;
	RBin *b = a->binb.bin;
	if (b->cur.curplugin) {
		if (!strcmp (b->cur.curplugin->name, "java")) { // XXX slow
			obj = b->cur.bin_obj; //o; 
			if (obj) r_java_set_obj (obj);
		}
	}
	return op->inst_len = r_java_disasm (a->pc, buf,
		op->buf_asm, sizeof (op->buf_asm));
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	// TODO: get class info from bin if possible
	return op->inst_len = r_java_assemble (op->buf, buf);
}

RAsmPlugin r_asm_plugin_java = {
	.name = "java",
	.desc = "Java CLASS assembler/disassembler",
	.arch = "java",
	.license = "LGPL3",
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
