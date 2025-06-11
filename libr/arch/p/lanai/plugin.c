/* radare - LGPL - Copyright 2016-2024 - pancake */

#include <r_arch.h>
#include "../../include/disas-asm.h"

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

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	const int len = op->size;
	const ut8 *buf = op->bytes;
	const ut64 addr = op->addr;
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

	return op->size > 0;
}

// 32 registers, most of them general purpose, with special treatment for R0 (all zeroes), R1 (all ones), R2 (the program counter), R3 (status register), and some registers allocated for mode/context switching.

static char *regs(RArchSession *as) {
	const char *const p =
		"=PC	r2\n"
		"=SP	sp\n"
		"=A0	r2\n"
		"=A1	r3\n"
		"gpr	r0	.32	?0	0\n" // all zeros
		"gpr	r1	.32	?1	0\n" // all ones

		"gpr	r2	.32	0	0\n" // pc
		"gpr	r3	.32	4	0\n" // status register
		"gpr	r4	.32	8	0\n"
		"gpr	r5	.32	12	0\n"
		"gpr	r6	.32	16	0\n"
		"gpr	r7	.32	20	0\n"
		"gpr	r8	.32	24	0\n"
		"gpr	r9	.32	28	0\n"
		"gpr	r10	.32	32	0\n"
		"gpr	r11	.32	36	0\n"
		"gpr	r12	.32	40	0\n"
		"gpr	r13	.32	44	0\n"
		"gpr	r14	.32	48	0\n"
		"gpr	r15	.32	52	0\n"
		"gpr	r16	.32	56	0\n"
		"gpr	r17	.32	60	0\n"
		"gpr	r18	.32	64	0\n"
		"gpr	r19	.32	68	0\n";
	return strdup (p);
}

static int info(RArchSession *as, ut32 q) {
	return 0;
}

const RArchPlugin r_arch_plugin_lanai = {
	.meta = {
		.name = "lanai",
		.author = "pancake",
		.license = "GPL-3.0-only",
		.desc = "Myricom's LANAI (based on GNU binutils",
	},
	.arch = "lanai",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_BIG,
	.regs = regs,
	.info = info,
	.decode = &decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_lanai_gnu,
	.version = R2_VERSION
};
#endif
