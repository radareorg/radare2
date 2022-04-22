/* radare - LGPL - Copyright 2014-2022 - pancake */

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

static int cris_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 8) {
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

bfd_boolean cris_parse_disassembler_options (disassemble_info *info, int distype);

// TODO: refactor the gnu code to have a getter instead of exposing so many disasm entrypoints
int print_insn_crisv10_v32_with_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_crisv10_v32_without_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_cris_with_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_cris_without_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_crisv32_with_register_prefix (bfd_vma vma, disassemble_info *info);
int print_insn_crisv32_without_register_prefix (bfd_vma vma, disassemble_info *info);

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
	disasm_obj.disassembler_options = (a->config->bits == 64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &cris_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	const char *cpu = a->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		// enum cris_disass_family { cris_dis_v0_v10, cris_dis_common_v10_v32, cris_dis_v32 };
		// 0: v0-v10
		// 1: v10-v32
		// 2: v32
		mode = 0;
		if (strstr (cpu,  "v10")) {
			mode = 1;
		}
		if (strstr (cpu,  "v32")) {
			mode = 2;
		}
	} else {
		mode = 2;
	}
	(void)cris_parse_disassembler_options (&disasm_obj, mode);
	if (a->config->syntax == R_ASM_SYNTAX_ATT) {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_with_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_with_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		default:
			op->size = print_insn_crisv32_with_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		}
	} else {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_without_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_without_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		default:
			op->size = print_insn_crisv32_without_register_prefix ((bfd_vma)Offset, &disasm_obj);
			break;
		}
	}
	if (op->size == -1) {
		r_strbuf_set (&op->buf_asm, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_cris_gnu = {
	.name = "cris",
	.arch = "cris",
	.cpus = "v0,v10,v32",
	.license = "GPL3",
	.author = "pancake",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "Axis Communications 32-bit embedded processor",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_cris_gnu,
	.version = R2_VERSION
};
#endif
