/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "dis-asm.h"
#include "../arch/arm/arm.h"

static int arm_mode = 0;
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[8];

static int arm_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr,
		unsigned int length, struct disassemble_info *info) {
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
	sprintf (tmp, "0x%08"PFMT64x"", (ut64)address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	va_list ap;
	char *tmp;
	if (buf_global == NULL || format == NULL)
		return R_FALSE;
	va_start (ap, format);
 	tmp = malloc (strlen (format)+strlen (buf_global)+2);
	if (tmp == NULL)
		return R_FALSE;
	sprintf (tmp, "%s%s", buf_global, format);
	vsprintf (buf_global, tmp, ap);
	va_end (ap);
	free (tmp);
	return R_TRUE;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct disassemble_info obj;

	if (len<(a->bits/8)) return -1;
	buf_global = op->buf_asm;
	Offset = a->pc;
////	if (a->bits==64)
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&obj,'\0', sizeof (struct disassemble_info));
	arm_mode = a->bits;
	//obj.arch = ARM_EXT_V1|ARM_EXT_V4T|ARM_EXT_V5;
	/* TODO: set arch */
	obj.arch = UT32_MAX;
	obj.mach = UT32_MAX;
	obj.arch = 0;
	obj.mach = 0;

	obj.buffer = bytes;
	obj.read_memory_func = &arm_buffer_read_memory;
	obj.symbol_at_address_func = &symbol_at_address;
	obj.memory_error_func = &memory_error_func;
	obj.print_address_func = &print_address;
	obj.endian = (a->bits==16)? 0:!a->big_endian;
	obj.fprintf_func = &buf_fprintf;
	obj.stream = stdout;
	obj.bytes_per_chunk =
	obj.bytes_per_line = (a->bits/8);

	op->buf_asm[0]='\0';
	if (a->bits==64) {
		/* endianness is ignored on 64bits */
		r_mem_copyendian (bytes, buf, 4, !a->big_endian);
		op->inst_len = print_insn_aarch64 ((bfd_vma)Offset, &obj);
	} else {
		op->inst_len = obj.endian?
			print_insn_little_arm ((bfd_vma)Offset, &obj):
			print_insn_big_arm ((bfd_vma)Offset, &obj);
	}
	if (op->inst_len == -1)
		strncpy (op->buf_asm, " (data)", R_ASM_BUFSIZE);
	return op->inst_len; //(a->bits/8); //op->inst_len;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int is_thumb = a->bits==16? 1: 0;
	int opcode = armass_assemble (buf, a->pc, is_thumb);
	if (opcode==-1)
		return -1;
	if (a->bits>=32)
		r_mem_copyendian (op->buf, (void *)&opcode, 4, a->big_endian);
	else r_mem_copyendian (op->buf, (void *)&opcode, 2, !a->big_endian);
// XXX. thumb endian assembler needs no swap
	return (a->bits/8);
}

RAsmPlugin r_asm_plugin_arm = {
	.name = "arm",
	.arch = "arm",
	.bits = (int[]){ 16, 32, 64, 0 },
	.desc = "ARM disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm
};
#endif
