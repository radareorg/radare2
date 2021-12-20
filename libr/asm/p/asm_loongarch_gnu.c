/* radare - LGPL - Copyright 2009-2018 - zhaojunchao love lhy */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "disas-asm.h"

int la_assemble(const char *str, ut64 pc, ut8 *out);

#define INSNLEN 4
static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[4];
static char *pre_cpu = NULL;
static char *pre_features = NULL;

static int la_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//TODO
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, int len) {

	static struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 4);

	if ((a->cpu != pre_cpu) && (a->features != pre_features)) {
		free (disasm_obj.disassembler_options);
		memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	}

	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.read_memory_func = &la_buffer_read_memory;
	disasm_obj.stream = stdout;

	op->size = print_insn_loongarch((bfd_vma)Offset, &disasm_obj);

	return op->size;
}

RAsmPlugin r_asm_plugin_loongarch_gnu = {
	.name = "loongarch",
	.arch = "loongarch",
	.license = "GPL3",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "LOONGARCH GNU disassemble",
	.disassemble = &disassemble,
	//.assemble = &assemble		//TODO
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_loongarch_gnu,
	.version = R2_VERSION
};
#endif
