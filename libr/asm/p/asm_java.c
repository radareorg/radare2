/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

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
	if (b->cur->curplugin) {
		if (!strcmp (b->cur->curplugin->name, "java")) { // XXX slow
			obj = b->cur->o->bin_obj; //o;
			//eprintf("Handling: %s disasm.\n", b->cur.file);
		}
	}
	return op->size = r_java_disasm (obj, a->pc, buf,
		op->buf_asm, sizeof (op->buf_asm));
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	// TODO: get class info from bin if possible
	return op->size = r_java_assemble (op->buf, buf);
}

RAsmPlugin r_asm_plugin_java = {
	.name = "java",
	.desc = "Java bytecode",
	.arch = "java",
	.license = "Apache",
	.bits = 32,
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
