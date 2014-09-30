/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_core.h>

#include "../../shlr/java/code.h"
#include "../../shlr/java/class.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	//void *cp;
	RBinJavaObj *obj = NULL;
	RBin *bin = a->binb.bin;
	RBinPlugin *plugin = bin && bin->cur && bin->cur->o ?
		bin->cur->o->plugin : NULL;
	if (plugin) {
		if (!strcmp (plugin->name, "java")) { // XXX slow
			obj = bin->cur->o->bin_obj; //o;
			//eprintf("Handling: %s disasm.\n", b->cur.file);
		}
	}

	op->size = r_java_disasm (obj, a->pc, buf,
		op->buf_asm, sizeof (op->buf_asm));
	a->pc += op->size;
	return  op->size;
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
