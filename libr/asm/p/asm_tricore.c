/* radare2 - LGPL - Copyright 2016 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "dis-asm.h"


static unsigned long Offset = 0;
static char *buf_global = NULL;
static ut8 bytes[128];

static int tricore_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = memaddr - Offset;
	if (delta > 0 && length > delta) {
		memcpy (myaddr, bytes + delta, length - delta);
	}
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void print_address(bfd_vma address, struct disassemble_info *info) {
	char tmp[64];
	if (!buf_global) {
		return;
	}
	sprintf (tmp, "0x%08" PFMT64x, (ut64) address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	int flen, glen;
	char *escaped = NULL;
	va_list ap;
	char *tmp = NULL;
	va_start (ap, format);
	if (!buf_global) {
		return 0;
	}
	flen = strlen (format);
	glen = strlen (buf_global);
	tmp = malloc (flen + glen + 2);
	if (!tmp) return 0;

	if (strchr (buf_global, '%')) {
		char *buf_local = strdup (buf_global);
		if (!buf_local) {
			free (tmp);
			return 0;
		}
		escaped = r_str_replace (buf_local, "%", "%%", true);
	} else {
		escaped = strdup (buf_global);
		if (!escaped) {
			free (tmp);
			return 0;
		}
	}

	if (escaped) {
		glen = strlen (escaped);
		memcpy (tmp, escaped, glen);
		memcpy (tmp+glen, format, flen);
		tmp[flen+glen] = 0;
		free (escaped);
		/* this code can produce a buffer overflow or a format string */
#define IN_CASE_OF_SEGFAULT 0
#if IN_CASE_OF_SEGFAULT
		strcpy (buf_global, tmp);
#else
		vsprintf (buf_global, tmp, ap);
#endif
		free (tmp);
		va_end (ap);
		return 0;
	}
	free (tmp);
	va_end (ap);
	return -1;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	buf_global = op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, R_MIN (len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options=(a->bits==64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &tricore_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;

	disasm_obj.mach = 2; // select CPU TYPE

	op->size = print_insn_tricore ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1)
		strncpy (op->buf_asm, " (data)", R_ASM_BUFSIZE);

	return op->size;
}

RAsmPlugin r_asm_plugin_tricore = {
	.name = "tricore",
	.arch = "tricore",
	.license = "GPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tricore,
	.version = R2_VERSION
};
#endif
