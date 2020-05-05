/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "../arch/pyc/pyc_dis.h"
#include "../arch/pyc/opcode.h"

static pyc_opcodes *opcodes_cache = NULL;

static int disassemble (RAsm *a, RAsmOp *opstruct, const ut8 *buf, int len) {
	RList *interned_table = NULL;
	RList *shared = NULL;
	RList *cobjs = NULL;

	RBin *bin = a->binb.bin;
	ut64 pc = a->pc;

	RBinPlugin *plugin = bin && bin->cur && bin->cur->o ? bin->cur->o->plugin : NULL;

	if (plugin) {
		if (!strcmp (plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	cobjs = r_list_get_n (shared, 0);
	interned_table = r_list_get_n (shared, 1);
	if (!opcodes_cache || !pyc_opcodes_equal (opcodes_cache, a->cpu)) {
		opcodes_cache = get_opcode_by_version (a->cpu);
		opcodes_cache->bits = a->bits;
	}
	int r = r_pyc_disasm (opstruct, buf, cobjs, interned_table, pc, opcodes_cache);
	opstruct->size = r;
	return r;
}

static bool finish (void *user) {
	if (opcodes_cache) {
		free_opcode (opcodes_cache);
		opcodes_cache = NULL;
	}
    return true;
}

/*
static int dis(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    const char *buf_asm = "invalid";
    int size = -1;

    if (op_name[buf[0]]) {
        if (HAS_ARG(buf[0])) {
            if (a->bits == 16) {
                ut16 operand = (buf[2] << 8) | buf[1];
                buf_asm = sdb_fmt ("%s %d",op_name[buf[0]], operand);
                size = 3; // < 3.6
            } else {
                buf_asm = sdb_fmt ("%s %d",op_name[buf[0]], buf[1]);
                size = 2; // >= 3.6
            }
        } else {
            buf_asm = sdb_fmt (op_name[buf[0]]);
            if (buf[1] == STOP_CODE) {
                size = 2;
            } else {
                size = 1;
            }
        }
    }
//    eprintf("kmbs: f:%s\tbuf_asm:%s\n",__func__,buf_asm);

    r_strbuf_set (&op->buf_asm, buf_asm);
    op->size = size;
    return size;
}
*/

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
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pyc,
	.version = R2_VERSION
};

#endif
