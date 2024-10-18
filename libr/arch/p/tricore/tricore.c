/* radare - LGPL - Copyright 2020-2024 - curly */

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

static ut64 addrfrom(const char *s) {
	const char *ox = strstr (s, "0x");
	if (ox) {
		return r_num_get (NULL, ox);
	}
	return UT64_MAX;
}

static bool analop(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const char *text = op->mnemonic;
	if (*text == '.') {
		free (op->mnemonic);
		op->mnemonic = strdup ("invalid");
		op->size = 2;
		op->type = R_ANAL_OP_TYPE_ILL;
	} else if (r_str_startswith (text, "nop")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (r_str_startswith (text, "ld")) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptr = addrfrom (text);
	} else if (r_str_startswith (text, "st")) {
		op->type = R_ANAL_OP_TYPE_STORE;
		op->ptr = addrfrom (text);
	} else if (r_str_startswith (text, "loop")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addrfrom (text);
		op->fail = op->addr + op->size;
	} else if (r_str_startswith (text, "j ")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addrfrom (text);
	} else if (r_str_startswith (text, "ji")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
	} else if (r_str_startswith (text, "j")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addrfrom (text);
		op->fail = op->addr + op->size;
	} else if (r_str_startswith (text, "mov")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (r_str_startswith (text, "lea")) {
		op->type = R_ANAL_OP_TYPE_LEA;
	} else if (r_str_startswith (text, "add")) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if (r_str_startswith (text, "calli")) {
		op->type = R_ANAL_OP_TYPE_RCALL;
	} else if (r_str_startswith (text, "call")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = addrfrom (text);
		op->fail = op->addr + op->size;
	} else if (r_str_startswith (text, "rfe")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (r_str_startswith (text, "ret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	}
	return true;
}

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
	analop (as, op, mask);
	return op->size;
}

static char *get_reg_profile(RArchSession *as) {
	const char *p =
		"=PC     pc\n"
		"=SP     a10\n"
		"=BP     a11\n"
		"=A0     a4\n"
		"=A1     a5\n"
		"=A2     a6\n"
		"=A3     a7\n"
		"=SN     a0\n"
		"# General-Purpose Address Registers (A0 - A15)\n"
		"gpr     a0      .32     0       0\n"
		"gpr     a1      .32     4       0\n"
		"gpr     a2      .32     8       0\n"
		"gpr     a3      .32     12      0\n"
		"gpr     a4      .32     16      0\n"
		"gpr     a5      .32     20      0\n"
		"gpr     a6      .32     24      0\n"
		"gpr     a7      .32     28      0\n"
		"gpr     a8      .32     32      0\n"
		"gpr     a9      .32     36      0\n"
		"gpr     sp      .32     40      0\n"
		"gpr     a10     .32     40      0\n"
		"gpr     a11     .32     44      0\n"
		"gpr     a12     .32     48      0\n"
		"gpr     a13     .32     52      0\n"
		"gpr     a14     .32     56      0\n"
		"gpr     a15     .32     60      0\n"
		"# General-Purpose Data Registers (D0 - D15)\n"
		"gpr     e0      .64     64      0\n"
		"gpr     d0      .32     64      0\n"
		"gpr     d1      .32     68      0\n"
		"gpr     e2      .64     72      0\n"
		"gpr     d2      .32     72      0\n"
		"gpr     d3      .32     76      0\n"
		"gpr     e4      .64     80      0\n"
		"gpr     d4      .32     80      0\n"
		"gpr     d5      .32     84      0\n"
		"gpr     e6      .64     88      0\n"
		"gpr     d6      .32     88      0\n"
		"gpr     d7      .32     92      0\n"
		"gpr     e8      .64     96      0\n"
		"gpr     d8      .32     96      0\n"
		"gpr     d9      .32     100     0\n"
		"gpr     e10     .64     104     0\n"
		"gpr     d10     .32     104     0\n"
		"gpr     d11     .32     108     0\n"
		"gpr     e12     .64     112     0\n"
		"gpr     d12     .32     112     0\n"
		"gpr     d13     .32     116     0\n"
		"gpr     e14     .64     120     0\n"
		"gpr     d14     .32     120     0\n"
		"gpr     d15     .32     124     0\n"
		"# Special-Purpose Registers\n"
		"gpr     PSW     .32     128     0   # Program Status Word\n"
		"gpr     PCXI    .32     132     0   # Previous Context Information\n"
		"gpr     FCX     .32     136     0   # Free Context List Pointer\n"
		"gpr     LCX     .32     140     0   # Last Context Save Pointer\n"
		"gpr     ISP     .32     144     0   # Interrupt Stack Pointer\n"
		"gpr     ICR     .32     148     0   # Interrupt Control Register\n"
		"gpr     PIPN    .32     152     0   # Pending Interrupt Priority Number\n"
		"gpr     BIV     .32     156     0   # Base Interrupt Vector\n"
		"gpr     BTV     .32     160     0   # Base Trap Vector\n"
		"gpr     pc      .32     164     0   # Program Counter\n"
		"# System Control and Configuration Registers\n"
		"gpr     SYSCON  .32     168     0   # System Configuration Register\n"
		"gpr     DCON2   .32     172     0   # Debug Control Register 2\n"
		"gpr     CSP     .32     176     0   # Context Save Pointer\n"
		"gpr     MMUCON  .32     180     0   # Memory Management Unit Control\n"
		"gpr     CPU_ID  .32     184     0   # CPU Identification Register\n"
		"gpr     PSWEN   .32     188     0   # Program Status Word Enable Register\n"
		"gpr     CCUDR   .32     192     0   # Cache Control Unit Debug Register\n"
		"gpr     IECON   .32     196     0   # Interrupt Enable Configuration Register\n"
		"gpr     TRAPV   .32     200     0   # Trap Vector Register\n"
		"gpr     BBR     .32     204     0   # Base Boundary Register (Optional, depending on use)\n"
		"gpr     DBGSR   .32     208     0   # Debug Status Register (Optional, depending on use)\n"
		"gpr     PCON    .32     212     0   # Peripheral Control Register (Optional, depending on use)\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_DATA_ALIGN) {
		return 2;
	}
	if (q == R_ARCH_INFO_CODE_ALIGN) {
		return 2;
	}
	if (q == R_ARCH_INFO_INVOP_SIZE) {
		return 2;
	}
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 4;
	}
	if (q == R_ARCH_INFO_MINOP_SIZE) {
		return 2;
	}
	return 4; // XXX
}

const RArchPlugin r_arch_plugin_tricore = {
	.meta = {
		.name = "tricore",
		.author = "curly",
		.desc = "TRICORE analysis plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "tricore",
	.cpus = "generic,rider-a,rider-b,v2,pcp,pcp2",
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
