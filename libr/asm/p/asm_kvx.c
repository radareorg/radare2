#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "kvx.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char strasm[64];
	static bundle_t bundle = { };
	insn_t *insn;
	ut64 addr = a->pc;

	if (op == NULL) {
		return 0;
	}

	if (addr % 4) {
		goto unaligned;
	}

	insn = kvx_next_insn (&bundle, addr, buf, len);
	if (insn == NULL) {
		goto invalid;
	}
	op->size = insn->len * sizeof (ut32);

	if (insn->opc) {
		kvx_instr_print (insn, addr, strasm, sizeof (strasm));
		r_asm_op_set_asm (op, strasm);
	} else {
		r_asm_op_set_asm (op, "unknown");
	}

	return op->size;

invalid:
	r_asm_op_set_asm (op, "invalid");
	op->size = 4;
	return op->size;

unaligned:
	r_asm_op_set_asm (op, "unaligned");
	op->size = 4 - (addr % 4);
	return op->size;
}

RAsmPlugin r_asm_plugin_kvx = {
	.name = "kvx",
	.desc = "Kalray VLIW core disassembly plugin",
	.arch = "kvx",
	.license = "GPL",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_kvx,
	.version = R2_VERSION
};
#endif
