/* radare - LGPL - Copyright 2021-2022 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include "../arch/include/opcode/m68k.h"
#include <mybfd.h>
#include "disas-asm.h"

static R_TH_LOCAL unsigned long Offset = 0;
static R_TH_LOCAL RStrBuf *buf_global = NULL;
static R_TH_LOCAL ut8 bytes[8];

static int m68k_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 8) {
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

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, R_MIN (len, 8));

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &m68k_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_BIG;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	disasm_obj.mach = detect_cpu (a->config->cpu);

	op->size = print_insn_m68k ((bfd_vma)Offset, &disasm_obj);
	if (op->size == -1) {
		r_strbuf_set (&op->buf_asm, "(data)");
	}
	int left = R_MIN (len, op->size);
	if (left < 1 || !memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", left)) {
		r_strbuf_set (&op->buf_asm, "breakpoint");
		return 4;
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_m68k_gnu = {
	.name = "m68k.gnu",
	.arch = "m68k",
	.cpus = "m68000,m68010,m68020,m68030,m68040,m68060,m68881,m68851"
		"m68000up,m68010up,m68020up,m68030up,m68040up",
	.license = "GPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.desc = "Binutils 2.36 based m68k disassembler",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k_gnu,
	.version = R2_VERSION
};
#endif
