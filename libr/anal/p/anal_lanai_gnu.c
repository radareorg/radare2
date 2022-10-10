/* radare - LGPL - Copyright 2016-2022 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include "disas-asm.h"

static int lanai_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, length);
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

static int lanai_op(RAnal *a, RArchOp *op, ut64 addr, const ut8 *buf, int len, RArchOpMask mask) {
	ut8 bytes[8] = {0};
	struct disassemble_info disasm_obj = {0};
	RStrBuf *sb = NULL;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}
	memcpy (bytes, buf, R_MIN (sizeof (bytes), len)); // TODO handle thumb

	/* prepare disassembler */
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &lanai_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_lanai ((bfd_vma)addr, &disasm_obj);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
		sb = NULL;
	}
	r_strbuf_free (sb);

	return op->size;
}

RAnalPlugin r_anal_plugin_lanai_gnu = {
	.name = "lanai",
	.arch = "lanai",
	.license = "GPL3",
	.cpus = "",
	.bits = 16,
	.endian = R_SYS_ENDIAN_BIG,
	.desc = "HP PA-RISC",
	.op = &lanai_op
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_lanai_gnu,
	.version = R2_VERSION
};
#endif
