/* radare2 - LGPL - Copyright 2016-2018 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "disas-asm.h"

#define INSN_BUFFER_SIZE 4

static ut64 offset = 0;
static RStrBuf *buf_global = NULL;
static ut8 bytes[INSN_BUFFER_SIZE];

static int xtensa_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	if (length > INSN_BUFFER_SIZE) {
		length = INSN_BUFFER_SIZE;
	}
	memcpy (myaddr, bytes, length);
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
	struct disassemble_info disasm_obj;
	buf_global = &op->buf_asm;
	offset = a->pc;
	if (len > INSN_BUFFER_SIZE) {
		len = INSN_BUFFER_SIZE;
	}
	memcpy (bytes, buf, len); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = (a->config->bits == 64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_length = len;
	disasm_obj.read_memory_func = &xtensa_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	op->size = print_insn_xtensa ((bfd_vma)offset, &disasm_obj);
	if (op->size == -1) {
		r_asm_op_set_asm (op, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_xtensa = {
	.name = "xtensa",
	.arch = "xtensa",
	.license = "GPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "XTensa CPU",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_xtensa,
	.version = R2_VERSION
};
#endif
