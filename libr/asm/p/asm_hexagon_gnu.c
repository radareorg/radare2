/* radare - LGPL - Copyright 2017 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "dis-asm.h"
#include <mybfd.h>

disassembler_ftype
hexagon_get_disassembler_from_mach(
  unsigned long machine,
  unsigned long big_p
);
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[4];

static int hexagon_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	memcpy (myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void print_address(bfd_vma address, struct disassemble_info *info) {
	char tmp[32];
	if (!buf_global)
		return;
	sprintf (tmp, "0x%08"PFMT64x"", (ut64)address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	va_list ap;
	char tmp[1024];
	if (!buf_global)
		return 0;
	va_start (ap, format);
	vsnprintf (tmp, sizeof (tmp), format, ap);
	strcat (buf_global, tmp);
	va_end (ap);
	return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int (*print_insn_hexagon)(bfd_vma, struct disassemble_info *);
	static struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = op->buf_asm;
	Offset = a->pc;
	// disasm inverted
	r_mem_swapendian (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj,'\0', sizeof (struct disassemble_info));
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &hexagon_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.endian = a->big_endian;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;
	disasm_obj.mach = 0;

	op->buf_asm[0] = '\0';
print_insn_hexagon = hexagon_get_disassembler_from_mach(0,0);
	op->size = print_insn_hexagon ((bfd_vma)Offset, &disasm_obj);

	if (!strncmp (op->buf_asm, "unknown", 7)) {
		strncpy (op->buf_asm, "invalid", R_ASM_BUFSIZE);
	}

	if (op->size == -1) {
		strncpy (op->buf_asm, " (data)", R_ASM_BUFSIZE);
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_hexagon_gnu = {
	.name = "hexagon",
	.arch = "hexagon",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG | R_SYS_ENDIAN_LITTLE,
	.license = "GPL3",
	.desc = "Qualcomm DSPv5",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_hexagon_gnu,
	.version = R2_VERSION
};
#endif
