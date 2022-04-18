/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "disas-asm.h"
#include "../arch/arm/gnu/opcode-arm.h"

#if 0
#define ARM_ARCH_OPT(N, V, DF) { N, sizeof (N) - 1, V, DF }
struct arm_arch_option_table {
	const char name;
	int namelen;
	int arch;
	int fpu;
};
static const struct arm_arch_option_table arm_archs[] = {
	ARM_ARCH_OPT ("all", ARM_ANY, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv1", ARM_ARCH_V1, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2", ARM_ARCH_V2, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2a", ARM_ARCH_V2S, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2s", ARM_ARCH_V2S, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv3", ARM_ARCH_V3, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv3m", ARM_ARCH_V3M, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4", ARM_ARCH_V4, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4xm", ARM_ARCH_V4xM, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4t", ARM_ARCH_V4T, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4txm", ARM_ARCH_V4TxM, FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv5", ARM_ARCH_V5, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5t", ARM_ARCH_V5T, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5txm", ARM_ARCH_V5TxM, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5te", ARM_ARCH_V5TE, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5texp", ARM_ARCH_V5TExP, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5tej", ARM_ARCH_V5TEJ, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6", ARM_ARCH_V6, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6j", ARM_ARCH_V6, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6k", ARM_ARCH_V6K, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6z", ARM_ARCH_V6Z, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zk", ARM_ARCH_V6ZK, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6t2", ARM_ARCH_V6T2, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6kt2", ARM_ARCH_V6KT2, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zt2", ARM_ARCH_V6ZT2, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zkt2", ARM_ARCH_V6ZKT2, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6-m", ARM_ARCH_V6M, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6s-m", ARM_ARCH_V6SM, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7", ARM_ARCH_V7, FPU_ARCH_VFP),
	/* The official spelling of the ARMv7 profile variants is the dashed form.
	   Accept the non-dashed form for compatibility with old toolchains.  */
	ARM_ARCH_OPT ("armv7a", ARM_ARCH_V7A, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7r", ARM_ARCH_V7R, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7m", ARM_ARCH_V7M, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-a", ARM_ARCH_V7A, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-r", ARM_ARCH_V7R, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-m", ARM_ARCH_V7M, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7e-m", ARM_ARCH_V7EM, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv8-a", ARM_ARCH_V8A, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("xscale", ARM_ARCH_XSCALE, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("iwmmxt", ARM_ARCH_IWMMXT, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("iwmmxt2", ARM_ARCH_IWMMXT2, FPU_ARCH_VFP),
	{ NULL, 0, ARM_ARCH_NONE, ARM_ARCH_NONE }
};
#endif

static int arm_mode = 0;
static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[8];

static int arm_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	// --
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const int bits = a->config->bits;
	static char *oldcpu = NULL;
	static int oldcpucode = 0;
	int opsize;
	struct disassemble_info obj;
	char *options = (bits == 16)? "force-thumb": "no-force-thumb";

	if (len < 2) {
		return -1;
	}
	memset (bytes, 0, sizeof (bytes));
	memcpy (bytes, buf, R_MIN (len, 4));
	if (bits < 64 && len < (bits / 8)) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;

	/* prepare disassembler */
	memset (&obj, '\0', sizeof (struct disassemble_info));
	arm_mode = bits;
#if 0
typedef struct {
  unsigned long core[2];
  unsigned long coproc;
} arm_feature_set;
#endif
#if 0
arm_feature_set afs = ARM_ARCH_V7EM;
arm_feature_set afp = FPU_ARCH_VFP_V4D16;
printf ("v7em = core { 0x%x, 0x%x } copro 0x%x\n", afs.core[0], afs.core[1], afs.coproc);
cpucode = afs.core[0];
cpucode = 66471;
#endif
// printf ("fpu- = 0x%x\n", FPU_ARCH_VFP_V4D16);

	struct {
		const char name[32];
		int cpucode;
	} arm_cpucodes[] = {
		{ "v2", bfd_mach_arm_2 },
		{ "v2a", bfd_mach_arm_2a },
		{ "v3M", bfd_mach_arm_3M },
		{ "v4", bfd_mach_arm_4 },
		{ "v4t", bfd_mach_arm_4T },
		{ "v5", bfd_mach_arm_5 },
		{ "v5t", bfd_mach_arm_5T },
		{ "v5te", bfd_mach_arm_5TE },
		{ "v5j", bfd_mach_arm_5TE },
		{ "XScale", bfd_mach_arm_XScale },
		{ "ep9312", bfd_mach_arm_ep9312 },
		{ "iWMMXt", bfd_mach_arm_iWMMXt },
		{ "iWMMXt2", bfd_mach_arm_iWMMXt2 },
	};

	/* select cpu */
	// XXX oldcpu leaks
	char *cpu = a->config->cpu;
	if (oldcpu != cpu) {
		int cpucode = 0;
		if (cpu) {
 			int i;
			cpucode = atoi (cpu);
			for (i = 0; i < (sizeof(arm_cpucodes) / sizeof(arm_cpucodes[0])); i++) {
				if (!strcmp (arm_cpucodes[i].name, cpu)) {
					cpucode = arm_cpucodes[i].cpucode;
					break;
				}
			}
		}
		oldcpu = cpu;
		oldcpucode = cpucode;
	}

	obj.arch = 0;
	obj.mach = oldcpucode;

	if (obj.mach)
		obj.flags |= USER_SPECIFIED_MACHINE_TYPE;

	obj.buffer = bytes;
	obj.read_memory_func = &arm_buffer_read_memory;
	obj.symbol_at_address_func = &symbol_at_address;
	obj.memory_error_func = &memory_error_func;
	obj.print_address_func = &generic_print_address_func;
	obj.endian = !a->config->big_endian;
	obj.fprintf_func = &generic_fprintf_func;
	obj.stream = stdout;
	obj.bytes_per_chunk =
		obj.bytes_per_line = (bits / 8);

	r_strbuf_set (&op->buf_asm, "");
	if (bits == 64) {
		obj.disassembler_options = NULL;
		memcpy (bytes, buf, 4);
		op->size = print_insn_aarch64 ((bfd_vma) Offset, &obj);
	} else {
		obj.disassembler_options = options;
		op->size = (obj.endian == BFD_ENDIAN_LITTLE)
			? print_insn_little_arm ((bfd_vma) Offset, &obj)
			: print_insn_big_arm ((bfd_vma) Offset, &obj);
	}
	opsize = op->size;
	if (op->size == -1) {
		r_strbuf_set (&op->buf_asm, "(data)");
		op->size = 4;
	} else if (strstr (r_strbuf_get (buf_global), "UNDEF")) {
		r_strbuf_set (&op->buf_asm, "undefined");
		op->size = 2;
		opsize = 2;
	}
	return opsize;
}

RAsmPlugin r_asm_plugin_arm_gnu = {
	.name = "arm.gnu",
	.arch = "arm",
	.cpus = "v2,v2a,v3M,v4,v5,v5t,v5te,v5j,XScale,ep9312,iWMMXt,iWMMXt2",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "GNU Disassembler for ARM, Thumb and Aarch64",
	.disassemble = &disassemble,
	.license = "GPL3"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_gnu,
	.version = R2_VERSION
};
#endif
