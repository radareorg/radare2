/* radare - LGPL - Copyright 2015-2022 - pancake */

#include <r_lib.h>
#include <r_asm.h>

#define BUFSZ 8
#include "disas-asm.h"
#include "../../asm/arch/include/opcode/alpha.h"

static int alpha_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	ut8 *bytes = info->buffer;
	int nlen = R_MIN (length, BUFSZ - delta);
	if (nlen > 0) {
		memcpy (myaddr, bytes + delta, nlen);
	}
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

static int alpha_op(RAnal *a, RArchOp *op, ut64 addr, const ut8 *buf, int len, RArchOpMask mask) {
	ut8 bytes[BUFSZ] = {0};
	RStrBuf *sb = NULL;
	struct disassemble_info disasm_obj = {0};
	if (len < 4) {
		return -1;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}

	memcpy (bytes, buf, R_MIN (len, BUFSZ));
	/* prepare disassembler */
	disasm_obj.buffer = (ut8*)bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &alpha_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_alpha ((bfd_vma)addr, &disasm_obj);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = r_strbuf_drain (sb);
			sb = NULL;
			r_str_replace_char (op->mnemonic, '\t', ' ');
		} else {
			op->mnemonic = strdup ("(data)");
		}
		r_strbuf_free (sb);
		sb = NULL;
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
