/* radare - LGPL - Copyright 2009-2021 - nibble, pancake */

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
static unsigned char bytes[4];

static int ppc_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 4) {
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
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	*options = 0;
	const int bits = a->config->bits;
	if (!R_STR_ISEMPTY (a->config->cpu)) {
		snprintf (options, sizeof (options), "%s,%s",
			(bits == 64)? "64": "", a->config->cpu);
	} else if (bits == 64) {
		r_str_ncpy (options, "64", sizeof (options));
	}
	disasm_obj.disassembler_options = options;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &ppc_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	if (a->config->big_endian) {
		op->size = print_insn_big_powerpc ((bfd_vma)Offset, &disasm_obj);
	} else {
		op->size = print_insn_little_powerpc ((bfd_vma)Offset, &disasm_obj);
	}
	if (op->size == -1) {
		r_asm_op_set_asm (op, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_ppc_gnu = {
	.name = "ppc.gnu",
	.arch = "ppc",
	.license = "GPL3",
	.cpus = "booke,e300,e500,e500x2,e500mc,e440,e464,efs,ppcps,power4,power5,power6,power7,vsx",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "PowerPC",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_gnu,
	.version = R2_VERSION
};
#endif
