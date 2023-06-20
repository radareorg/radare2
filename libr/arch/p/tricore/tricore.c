/* radare - LGPL - Copyright 2020-2023 - curly */

#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>

#include "../../include/disas-asm.h"

#define BUFSZ 8
enum {
	TRICORE_GENERIC = 0x00000000,
	TRICORE_RIDER_A = 0x00000001,
	TRICORE_RIDER_B = 0x00000002,
	TRICORE_RIDER_D = TRICORE_RIDER_B,
	TRICORE_V2      = 0x00000004,
	TRICORE_PCP     = 0x00000010,
	TRICORE_PCP2    = 0x00000020
};

static int cpu_to_mach(char *cpu_type) {
	if (R_STR_ISNOTEMPTY (cpu_type)) {
		if (!strcmp (cpu_type, "generic")) {
			return TRICORE_GENERIC;
		}
		if (!strcmp (cpu_type, "rider-a")) {
			return TRICORE_RIDER_A;
		}
		if ((!strcmp (cpu_type, "rider-b")) || (!strcmp (cpu_type, "rider-d"))) {
			return TRICORE_RIDER_B;
		}
		if (!strcmp (cpu_type, "v2")) {
			return TRICORE_V2;
		}
		if (!strcmp (cpu_type, "pcp")) {
			return TRICORE_PCP;
		}
		if (!strcmp (cpu_type, "pcp2")) {
			return TRICORE_PCP2;
		}
	}
	return TRICORE_RIDER_B;
}

static int tricore_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = memaddr - info->buffer_vma;
	if (delta >= 0 && length + delta < BUFSZ) {
		ut8 *bytes = info->buffer;
		memcpy (myaddr, bytes + delta, length);
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

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const int len = op->size;
	const ut8 *buf = op->bytes;
	const ut64 addr = op->addr;
	ut8 bytes[BUFSZ] = {0};
	struct disassemble_info disasm_obj;
	RStrBuf *sb = r_strbuf_new ("");
	memcpy (bytes, buf, R_MIN (len, sizeof (bytes)));

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = (as->config->bits == 64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &tricore_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;

	// cpu type
	disasm_obj.mach = cpu_to_mach (as->config->cpu);

	int ret = print_insn_tricore ((bfd_vma)addr, &disasm_obj);
	op->size = ret;
	if (op->size == -1) {
		r_strbuf_set (sb, "(data)");
		op->size = 2;
	}
	op->mnemonic = r_strbuf_drain (sb);
	return op->size;
}

static char *get_reg_profile(RArchSession *as) {
	const char *p =
		"=PC	pc\n"
		"=SP	a10\n"
		"=A0	a0\n"
		"gpr	p0	.64	0	0\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	p2	.64	8	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	12	0\n"
		"gpr	p4	.64	16	0\n"
		"gpr	a4	.32	16	0\n"
		"gpr	a5	.32	20	0\n"
		"gpr	p6	.64	24	0\n"
		"gpr	a6	.32	24	0\n"
		"gpr	a7	.32	28	0\n"
		"gpr	p8	.64	32	0\n"
		"gpr	a8	.32	32	0\n"
		"gpr	a9	.32	36	0\n"
		"gpr	p10	.64	40	0\n"
		"gpr	a10	.32	40	0\n"
		"gpr	a11	.32	44	0\n"
		"gpr	p12	.64	48	0\n"
		"gpr	a12	.32	48	0\n"
		"gpr	a13	.32	52	0\n"
		"gpr	p14	.64	56	0\n"
		"gpr	a14	.32	56	0\n"
		"gpr	a15	.32	60	0\n"
		"gpr	e0	.64	64	0\n"
		"gpr	d0	.32	64	0\n"
		"gpr	d1	.32	68	0\n"
		"gpr	e2	.64	72	0\n"
		"gpr	d2	.32	72	0\n"
		"gpr	d3	.32	76	0\n"
		"gpr	e4	.64	80	0\n"
		"gpr	d4	.32	80	0\n"
		"gpr	d5	.32	84	0\n"
		"gpr	e6	.64	88	0\n"
		"gpr	d6	.32	88	0\n"
		"gpr	d7	.32	92	0\n"
		"gpr	e8	.64	96	0\n"
		"gpr	d8	.32	96	0\n"
		"gpr	d9	.32	100	0\n"
		"gpr	e10	.64	104	0\n"
		"gpr	d10	.32	104	0\n"
		"gpr	d11	.32	108	0\n"
		"gpr	e12	.64	112	0\n"
		"gpr	d12	.32	112	0\n"
		"gpr	d13	.32	114	0\n"
		"gpr	e14	.64	118	0\n"
		"gpr	d14	.32	118	0\n"
		"gpr	d15	.32	120	0\n"
		"gpr	PSW	.32	124	0\n"
		"gpr	PCXI	.32	128	0\n"
		"gpr	FCX	.32	132	0\n"
		"gpr	LCX	.32	136	0\n"
		"gpr	ISP	.32	140	0\n"
		"gpr	ICR	.32	144	0\n"
		"gpr	PIPN	.32	148	0\n"
		"gpr	BIV	.32	152	0\n"
		"gpr	BTV	.32	156	0\n"
		"gpr	pc	.32	160	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_INV_OP_SIZE) {
		return 2;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		return 2;
	}
	return 4; // XXX
}

const RArchPlugin r_arch_plugin_tricore = {
	.meta = {
		.name = "tricore",
		.desc = "TRICORE analysis plugin",
		.license = "LGPL3",
	},
	.arch = "tricore",
	.bits = R_SYS_BITS_PACK1 (32),
	.info = &archinfo,
	.decode = &decode,
	.endian = R_SYS_ENDIAN_LITTLE,
	.regs = get_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_tricore,
	.version = R2_VERSION
};
#endif
