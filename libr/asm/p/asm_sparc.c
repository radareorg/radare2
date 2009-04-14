/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "dis-asm.h"


static int sparc_mode = 0;
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[4];

static int sparc_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info)
{
	memcpy (myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info)
{
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info)
{
	//--
}

static void print_address(bfd_vma address, struct disassemble_info *info)
{
	char tmp[32];
	if (buf_global == NULL)
		return;
	sprintf(tmp, "0x%08llx", (u64)address);
	strcat(buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...)
{
	va_list ap;
	char *tmp;
	if (buf_global == NULL)
		return 0;
	va_start(ap, format);
 	tmp = alloca(strlen(format)+strlen(buf_global)+2);
	sprintf(tmp, "%s%s", buf_global, format);
	vsprintf(buf_global, tmp, ap);
	va_end(ap);
	return 0;
}

static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	static struct disassemble_info disasm_obj;

	buf_global = aop->buf_asm;
	Offset = a->pc;
	memcpy(bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset(&disasm_obj,'\0', sizeof(struct disassemble_info));
	sparc_mode = a->bits;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &sparc_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;

	aop->buf_asm[0]='\0';
	aop->inst_len = print_insn_sparc((bfd_vma)Offset, &disasm_obj);
	aop->disasm_obj = &disasm_obj;

	if (aop->inst_len == -1)
		strcpy(aop->buf_asm, " (data)");

	return aop->inst_len;
}

struct r_asm_handle_t r_asm_plugin_sparc = {
	.name = "asm_sparc",
	.arch = "sparc",
	.bits = (int[]){ 32, 0 },
	.desc = "SPARC disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sparc
};
#endif
