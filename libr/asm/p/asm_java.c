/* radare - LGPL - Copyright 2009-2019 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_core.h>

#include "../../shlr/java/code.h"
#include "../../shlr/java/class.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	RBinJavaObj *obj = NULL;
	RBin *bin = a->binb.bin;
	RBinPlugin *plugin = bin && bin->cur && bin->cur->o ?
		bin->cur->o->plugin : NULL;
	if (plugin && plugin->name) {
		if (!strcmp (plugin->name, "java")) { // XXX slow
			obj = bin->cur->o->bin_obj; //o;
			//eprintf("Handling: %s disasm.\n", b->cur.file);
		}
	}
	char buf_asm[256];
	op->size = r_java_disasm (obj, a->pc, buf, len, buf_asm, sizeof (buf_asm));
	r_strbuf_set (&op->buf_asm, buf_asm);
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *input) {
	// TODO: get class info from bin if possible
	// XXX wrong usage of strbuf_get here
	return op->size = r_java_assemble (a->pc, (ut8*)r_strbuf_get (&op->buf), input);
}

RAsmPlugin r_asm_plugin_java = {
	.name = "java",
	.desc = "Java bytecode",
	.arch = "java",
	.license = "Apache",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_java,
	.version = R2_VERSION
};
#endif
