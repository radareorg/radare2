/* radare - LGPL - Copyright 2010-2011 eloi<limited-entropy.com> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "disas-asm.h"

static R_TH_LOCAL unsigned long Offset = 0;
static R_TH_LOCAL RStrBuf *buf_global = NULL;
static R_TH_LOCAL unsigned char bytes[4];

static int sh_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	//this is obviously wrong. but how can we read arbitrary data @ memaddr from here?
	memcpy (myaddr, bytes, length);
	return 0;
}

int print_insn_shl(bfd_vma memaddr, struct disassemble_info *info);
int print_insn_shb(bfd_vma memaddr, struct disassemble_info *info);

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static struct disassemble_info disasm_obj;
	if (len < 2) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 2);

	/* prepare disassembler */
	memset (&disasm_obj,'\0', sizeof (struct disassemble_info));
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &sh_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	if (disasm_obj.endian == BFD_ENDIAN_BIG) {
		op->size = print_insn_shb ((bfd_vma)Offset, &disasm_obj);
	} else {
		op->size = print_insn_shl ((bfd_vma)Offset, &disasm_obj);
	}
	if (op->size == -1) {
		r_asm_op_set_asm (op, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.license = "GPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "SuperH-4 CPU",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sh,
	.version = R2_VERSION
};
#endif
