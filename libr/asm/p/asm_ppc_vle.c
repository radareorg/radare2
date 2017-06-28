/* radare2 - LGPL - Copyright 2017 - wargio */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_anal.h>
#include "../arch/ppc/libvle/vle.h"

static vle_handle handle = {0};

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut32 i;
	vle_t* instr = NULL;
	ut64 addr = a->pc;
	if(len > 1 && !vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		int bufsize = R_ASM_BUFSIZE, add = 0;
		char* str = op->buf_asm;
		op->size = instr->size;

		add = snprintf (str, bufsize, "%s", instr->name);
		for (i = 0; add > 0 && i < instr->n && add < bufsize; ++i) {
			if (instr->fields[i].type == TYPE_REG) {
				add += snprintf (str + add, bufsize - add, " r%u", instr->fields[i].value);
			} else if (instr->fields[i].type == TYPE_IMM) {
				add += snprintf (str + add, bufsize - add, " 0x%x", instr->fields[i].value);
			} else if (instr->fields[i].type == TYPE_MEM)  {
				add += snprintf (str + add, bufsize - add, " 0x%x(r%d)", instr->fields[i + 1].value, instr->fields[i].value);
				i++;
			} else if (instr->fields[i].type == TYPE_JMP) {
				add += snprintf (str + add, bufsize - add, " 0x%llx", addr + instr->fields[i].value);
			} else if (instr->fields[i].type == TYPE_CR) {
				add += snprintf (str + add, bufsize - add, " cr%u", instr->fields[i].value);
			}
		}
		vle_free(instr);
	} else {
		strcpy (op->buf_asm, "invalid");
		op->size = 2;
		return -1;
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_ppc_vle = {
	.desc = "PowerPC VLE",
	.name = "ppc.vle",
	.arch = "ppc",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.license = "LGPL3",
	.disassemble = &disassemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_vle,
	.version = R2_VERSION
};
#endif
