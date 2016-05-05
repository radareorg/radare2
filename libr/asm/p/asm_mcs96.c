/* radare - LGPL - Copyrigth - 2015 - condret	*/

#include <r_types.h>
#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/mcs96/mcs96.h"

static int mcs96_len (const ut8 buf) {
	if (mcs96_op[buf].type & MCS96_6B)
		return 6;
	if (mcs96_op[buf].type & MCS96_5B)
		return 5;
	if (mcs96_op[buf].type & MCS96_4B)
		return 4;
	if (mcs96_op[buf].type & MCS96_3B)
		return 3;
	if (mcs96_op[buf].type & MCS96_2B)
		return 2;
	return 1;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (len>1 && !memcmp (buf, "\xff\xff", 2))
		return -1;
	strncpy (op->buf_asm, mcs96_op[buf[0]].ins, sizeof (op->buf_asm)-1);
	op->size = mcs96_len (buf[0]);
	return op->size;
}

RAsmPlugin r_asm_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "condrets car",
	.arch = "mcs96",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mcs96,
	.version = R2_VERSION
};
#endif
