/* radare - LGPL - Copyright 2021-2023 - pancake */

#include <r_arch.h>
#include "../../include/disas-asm.h"

static int pdp11_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	const ut8 *bytes = info->buffer;
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

static bool pdp11_op(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	ut8 bytes[4] = {0};
	struct disassemble_info disasm_obj = {0};
	RStrBuf *sb = NULL;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}
	size_t left = R_MIN (sizeof (bytes), op->size);
	memcpy (bytes, op->bytes, left);
	op->size = sizeof (bytes);

	/* prepare disassembler */
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = op->addr;
	disasm_obj.read_memory_func = &pdp11_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_pdp11 ((bfd_vma)op->addr, &disasm_obj);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		free (op->mnemonic);
		op->mnemonic = r_strbuf_drain (sb);
		r_str_replace_ch (op->mnemonic, '\t', ' ', true);
		sb = NULL;
		const char *text = op->mnemonic;
		if (strstr (text, ".word")) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else if (r_str_startswith (text, "mov")) {
			op->type = R_ANAL_OP_TYPE_MOV;
		} else if (r_str_startswith (text, "j")) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else if (r_str_startswith (text, "cmp")) {
			op->type = R_ANAL_OP_TYPE_CMP;
		} else if (r_str_startswith (text, "ld")) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else if (r_str_startswith (text, "br")) {
			op->type = R_ANAL_OP_TYPE_RJMP;
		} else if (r_str_startswith (text, "b")) {
			op->type = R_ANAL_OP_TYPE_CJMP;
		}
	}
	r_strbuf_free (sb);
	return op->size > 0;
}

static int info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 4;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

static char *regs(RArchSession *as) {
	const char *const p =
		"=PC    r7\n"
		"=SP    r30\n"
		"=BP    r5\n"
		"=A0    r1\n"
		"=A1    r2\n"
		"=A2    r3\n"
		"=A3    r4\n"
		"=SN    r1\n"
		"=R0    r1\n"
		"=R1    r2\n"
		"gpr	r0	.16	0	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r7	.16	14	0\n"
		;
	return strdup (p);
}

const RArchPlugin r_arch_plugin_pdp11 = {
	.meta = {
		.name = "pdp11",
		.author = "pancake",
		.license = "GPL-3.0-only",
		.desc = "DEC PDP-11 16 bit micro-computer",
	},
	.arch = "pdp11",
	.bits = R_SYS_BITS_PACK1 (16),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = info,
	.regs = regs,
	.decode = &pdp11_op
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_pdp11,
	.version = R2_VERSION
};
#endif
