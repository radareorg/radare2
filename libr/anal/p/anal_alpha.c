/* radare - LGPL - Copyright 2015-2022 - pancake */

// TODO: no assembler support

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "disas-asm.h"
#include "../../asm/arch/include/opcode/alpha.h"

static R_TH_LOCAL unsigned long Offset = 0;
static R_TH_LOCAL RStrBuf *buf_global = NULL;
static R_TH_LOCAL const ut8 *bytes = NULL;
static R_TH_LOCAL int bytes_size = 0;

static int alpha_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	memcpy (myaddr, bytes + delta, R_MIN (length, bytes_size));
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

static int alpha_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	struct disassemble_info disasm_obj = {};
	if (len < 4) {
		return -1;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		buf_global = r_strbuf_new (NULL);
	}
	bytes = buf;
	bytes_size = len;
	Offset = addr;

	/* prepare disassembler */
	disasm_obj.buffer = (ut8*)bytes;
	disasm_obj.read_memory_func = &alpha_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	op->size = print_insn_alpha ((bfd_vma)Offset, &disasm_obj);

	if (mask & R_ANAL_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = r_strbuf_drain (buf_global);
			for (char *c = op->mnemonic; *c != 0; c++) {
				if (*c == '\t') {
					*c = ' ';
				}
			}
		} else {
			op->mnemonic = strdup ("(data)");
		}
		buf_global = NULL;
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_alpha = {
	.name = "alpha",
	.arch = "alpha",
	.license = "GPL",
	.bits = 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "ALPHA architecture disassembler",
	.op = &alpha_op
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_alpha,
	.version = R2_VERSION
};
#endif
