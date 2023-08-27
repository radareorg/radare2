#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>

#define _GNU_SOURCE
#include <stdio.h>
#include "nds32-opc.h"
#include "nds32-dis.h"

static CpuKv cpus[] = {
	{ "nds32", nds32 },
	{ NULL, 0 }
};

static int info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 2;
	}
	return 0;
}

static int nds32_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, length);
	return 0;
}


static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	const ut8 *buf = op->bytes;
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
	disasm_obj.read_memory_func = &nds32_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	disasm_obj.mach = detect_cpu (as->config->cpu);
	op->size = print_insn_nds32((bfd_vma)addr, &disasm_obj);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
		sb = NULL;
		r_str_replace_ch (op->mnemonic, '\t', ' ', true);
	}
	int left = R_MIN (len, op->size);
	if (left < 1 || (left > 0 && !memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", left))) {
		op->mnemonic = strdup ("breakpoint");
		r_strbuf_free (sb);
		return true;
	}
	r_strbuf_free (sb);
	return op->size > 0;
}

const RArchPlugin r_arch_plugin_nds32 = {
	.meta = {
		.name = "nds32",
		.author = "Edoardo Mantovani",
		.license = "GPL3",
		.desc = "Binutils based nds32 disassembler",
	},
	.arch = "nds32",
	.cpus = "nds32",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode,
	.info = &info,
};

#ifndef R2_CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_arch_plugin_nds32,
};
#endif
