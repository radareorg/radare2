/* radare - LGPL3 - Copyright 2016-2021 - c0riolis, x0urc3 */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "../arch/pyc/pyc_dis.h"

static pyc_opcodes *opcodes_cache = NULL;

static int disassemble(RAsm *a, RAsmOp *opstruct, const ut8 *buf, int len) {
	RList *shared = NULL;

	RBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RBinPlugin *plugin = bin && bin->cur && bin->cur->o? bin->cur->o->plugin: NULL;

	if (plugin) {
		if (!strcmp (plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	RList *cobjs = NULL;
	RList *interned_table = NULL;
	if (shared) {
		cobjs = r_list_get_n (shared, 0);
		interned_table = r_list_get_n (shared, 1);
	}
	if (!opcodes_cache || !pyc_opcodes_equal (opcodes_cache, a->config->cpu)) {
		opcodes_cache = get_opcode_by_version (a->config->cpu);
		if (!opcodes_cache) {
			opcodes_cache = get_opcode_by_version ("v3.9.0");
		}
		if (opcodes_cache) {
			opcodes_cache->bits = a->config->bits;
		} else {
			return 0;
		}
	}
	int r = r_pyc_disasm (opstruct, buf, cobjs, interned_table, pc, opcodes_cache);
	opstruct->size = r;
	return r;
}

static bool finish(void *user) {
	if (opcodes_cache) {
		free_opcode (opcodes_cache);
		opcodes_cache = NULL;
	}
	return true;
}

RAsmPlugin r_asm_plugin_pyc = {
	.name = "pyc",
	.arch = "pyc",
	.license = "LGPL3",
	.bits = 16 | 8,
	.desc = "PYC disassemble plugin",
	.disassemble = &disassemble,
	.fini = &finish,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pyc,
	.version = R2_VERSION
};

#endif
