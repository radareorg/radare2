/* radare2, Sharp LH5801 disassembler.
 * (C) Copyright 2014-2015 jn, published under the LGPLv3 */

#include "../../arch/lh5801/lh5801.c"
#include <r_asm.h>
#include <r_types.h>

static int disassemble(RAsm *as, RAsmOp *op, const ut8 *buf, int len)
{
	struct lh5801_insn insn;
	int consumed;

	if (!op)
		return 0;

	consumed = lh5801_decode (&insn, buf, len);
	if (consumed == -1 || consumed == 0) {
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "invalid");
		op->size = 1;
		return 0;
	} else {
		lh5801_print_insn (op->buf_asm, R_ASM_BUFSIZE, &insn);
		op->size = consumed;
		//op->payload = lh5801_insn_descs[insn.type].format & 3;
		// ^ MAYBE?
		return op->size;
	}
}

RAsmPlugin r_asm_plugin_lh5801 = {
	.name = "lh5801",
	.arch = "LH5801",
	.license = "LGPL3",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "SHARP LH5801 disassembler",
	.disassemble = &disassemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_lh5801,
	.version = R2_VERSION
};
#endif
