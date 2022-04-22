/* radare - LGPL - Copyright 2021 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "disas-asm.h"


static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[8];

static int s390_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 6) {
		return -1;
	}
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char options[64];
	struct disassemble_info disasm_obj;
	if (len < 6) {
		r_asm_op_set_asm (op, "truncated");
		return 4;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 6); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	if (!R_STR_ISEMPTY (a->config->cpu)) {
		r_str_ncpy (options, a->config->cpu, sizeof (options));
	} else {
		*options = 0;
	}
	r_asm_op_set_asm (op, "");
	disasm_obj.disassembler_options = options;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &s390_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = 0; // !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	disassemble_init_s390 (&disasm_obj);
	op->size = print_insn_s390 ((bfd_vma)Offset, &disasm_obj);
	if (op->size < 1) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 4;
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_s390_gnu = {
	.name = "s390.gnu",
	.desc = "s390/SystemZ CPU disassembler",
	.arch = "s390",
	.license = "GPL3",
	.cpus = "esa,zarch",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_s390_gnu,
	.version = R2_VERSION
};
#endif
