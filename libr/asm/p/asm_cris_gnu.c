/* radare - LGPL - Copyright 2014-2018 - pancake */

#if 0

Documentation
-------------
http://developer.axis.com/old/documentation/hw/etraxfs/des_ref/des_ref.pdf
http://developer.axis.com/old/documentation/hw/etraxfs/iop_howto/iop_howto.pdf

#endif

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

static int cris_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	memcpy (myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

//static int print_insn_crisv10_v32_with_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_crisv10_v32_without_register_prefix (bfd_vma vma, disassemble_info *info);
bfd_boolean cris_parse_disassembler_options (disassemble_info *info, int distype);
int print_insn_crisv10_v32_with_register_prefix (bfd_vma vma, disassemble_info *info);

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	int mode = 2;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, R_MIN (len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options=(a->bits==64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &cris_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	if (a->cpu && *a->cpu) {
		if (!strcmp (a->cpu, "v10+v32")) {
			mode = 1;
		} else if (!strcmp (a->cpu, "v10")) {
			mode = 0;
		} else {
			mode = 2;
		}
	} else {
		mode = 2;
	}
	(void)cris_parse_disassembler_options (&disasm_obj, mode);
	if (a->syntax == R_ASM_SYNTAX_ATT) {
		op->size = print_insn_crisv10_v32_with_register_prefix (
			(bfd_vma)Offset, &disasm_obj);
	} else {
		op->size = print_insn_crisv10_v32_without_register_prefix (
			(bfd_vma)Offset, &disasm_obj);
	}
	if (op->size == -1) {
		r_strbuf_set (&op->buf_asm, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_cris_gnu = {
	.name = "cris",
	.arch = "cris",
	.cpus = "v10,v32,v10+v32",
	.license = "GPL3",
	.author = "pancake",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "Axis Communications 32-bit embedded processor",
	.disassemble = &disassemble
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_cris_gnu,
	.version = R2_VERSION
};
#endif
