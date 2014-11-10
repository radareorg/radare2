/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "dis-asm.h"
#include "opcode/mips.h"
int mips_assemble(const char *str, ut64 pc, ut8 *out);

static int mips_mode = 0;
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[4];

static int mips_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
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
	if (buf_global == NULL)
		return;
	sprintf (tmp, "0x%08"PFMT64x, (ut64)address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	va_list ap;
	char *tmp;
	if (buf_global == NULL || format == NULL)
		return R_FALSE;
	va_start (ap, format);
 	tmp = malloc (strlen (format)+strlen (buf_global)+2);
	if (tmp == NULL) {
		va_end (ap);
		return R_FALSE;
	}
	sprintf (tmp, "%s%s", buf_global, format);
	vsprintf (buf_global, tmp, ap);
	va_end (ap);
	free (tmp);
	return R_TRUE;
}

static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	static struct disassemble_info disasm_obj;
	if (len<4) return -1;
	buf_global = op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj,'\0', sizeof (struct disassemble_info));
	mips_mode = a->bits;
	disasm_obj.arch = CPU_LOONGSON_2F;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &mips_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.buffer_vma = Offset;
	disasm_obj.buffer_length = 4;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;

	op->buf_asm[0] = '\0';
	if (a->big_endian)
		op->size = print_insn_big_mips ((bfd_vma)Offset, &disasm_obj);
	else op->size = print_insn_little_mips ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1)
		strncpy (op->buf_asm, " (data)", R_ASM_BUFSIZE);
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	int ret = mips_assemble (str, a->pc, op->buf);
	r_mem_copyendian (op->buf, op->buf, 4, !a->big_endian);
	return ret;
}

RAsmPlugin r_asm_plugin_mips_gnu = {
	.name = "mips.gnu",
	.arch = "mips",
	.license = "GPL3",
	.bits = 32|64,
	.desc = "MIPS CPU",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_gnu
};
#endif
