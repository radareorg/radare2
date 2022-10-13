/* radare - LGPL - Copyright 2016-2022 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include "../../asm/arch/include/opcode/m68k.h"
#include <r_asm.h>
#include "disas-asm.h"

typedef struct {
	const char *name;
	int v;
} CpuKv;

static CpuKv cpus[] = {
	{ "m68000", 1 },
	{ "m68010", 2 },
	{ "m68020", 4 },
	{ "m68030", 8 },
	{ "m68040", 0x10 },
	{ "m68060", 0x20 },
	{ "m68881", 0x40 },
	{ "m68851", 0x80 },

	{ "m68000up", m68010up },
	{ "m68010up", m68010up },
	{ "m68020up", m68020up },
	{ "m68030up", m68030up },
	{ "m68040up", m68040up },
	{ NULL, 0 }
};
static int detect_cpu(const char *cpu) {
	int i;
	const int isa = mcfisa_b | mcfisa_a | mcfisa_c;
	const int default_cpu = 0; // m68040up;
	if (cpu) {
		for (i = 0; cpus[i].name; i++) {
			if (!strcmp (cpus[i].name, cpu)) {
				return cpus[i].v | isa;
			}
		}
	}
	return default_cpu | isa;
}

static int m68k_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
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

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

static int m68k_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	ut8 bytes[8] = {0};
	struct disassemble_info disasm_obj = {0};
	RStrBuf *sb = NULL;
	if (mask & R_ANAL_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}
	memcpy (bytes, buf, R_MIN (sizeof (bytes), len)); // TODO handle thumb
	/* prepare disassembler */
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &m68k_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	disasm_obj.mach = detect_cpu (a->config->cpu);
	op->size = print_insn_m68k ((bfd_vma)addr, &disasm_obj);

	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
		sb = NULL;
		r_str_replace_ch (op->mnemonic, '\t', ' ', true);
	}
	int left = R_MIN (len, op->size);
	if (left < 1 || (left > 0 && !memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", left))) {
		op->mnemonic = strdup ("breakpoint");
		return 4;
	}
	r_strbuf_free (sb);
	return op->size;
}

RAnalPlugin r_anal_plugin_m68k_gnu = {
	.name = "m68k.gnu",
	.author = "pancake",
	.arch = "m68k",
	.license = "GPL3",
	.cpus = "m68000,m68010,m68020,m68030,m68040,m68060,m68881,m68851"
		"m68000up,m68010up,m68020up,m68030up,m68040up",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.desc = "Binutils 2.36 based m68k disassembler",
	.op = &m68k_op
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m68k_gnu,
	.version = R2_VERSION
};
#endif
