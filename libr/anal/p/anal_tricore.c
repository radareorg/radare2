/* radare - LGPL - Copyright 2020-2022 - curly */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
// DISASM BEGIN

#include "disas-asm.h"

static R_TH_LOCAL unsigned long Offset = 0;
static R_TH_LOCAL RStrBuf *buf_global = NULL;
static R_TH_LOCAL ut8 bytes[128];
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
	if (cpu_type && *cpu_type) {
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
	int delta = memaddr - Offset;
	if (delta >= 0 && length + delta < sizeof(bytes)) {
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

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	RStrBuf *sb = r_strbuf_new ("");
	buf_global = sb;
	Offset = addr;
	memcpy (bytes, buf, R_MIN (len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = (a->config->bits == 64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &tricore_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;

	// cpu type
	disasm_obj.mach = cpu_to_mach (a->config->cpu);

	int ret = print_insn_tricore ((bfd_vma)Offset, &disasm_obj);
	op->size = ret;
	if (op->size == -1) {
		r_strbuf_set (sb, "(data)");
		op->size = 2;
	}
	op->mnemonic = r_strbuf_drain (sb);
	return op->size;
}

// DISASM END
static bool set_reg_profile(RAnal *anal) {
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
	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
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

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	return disassemble (a, op, addr, buf, len);
}

RAnalPlugin r_anal_plugin_tricore = {
	.name = "tricore",
	.desc = "TRICORE analysis plugin",
	.license = "LGPL3",
	.arch = "tricore",
	.bits = 32,
	.archinfo = archinfo,
	.op = &analop,
	.endian = R_SYS_ENDIAN_LITTLE,
	.set_reg_profile = set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tricore,
	.version = R2_VERSION
};
#endif
