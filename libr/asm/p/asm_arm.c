/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "dis-asm.h"
#include "../arch/arm/arm.h"
#include "../arch/arm/gnu/arm.h"

#if 0
#define ARM_ARCH_OPT(N, V, DF) { N, sizeof (N) - 1, V, DF }
struct arm_arch_option_table {
	const char name;
	int namelen;
	int arch;
	int fpu;
};
static const struct arm_arch_option_table arm_archs[] = {
	ARM_ARCH_OPT ("all",          ARM_ANY,         FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv1",        ARM_ARCH_V1,     FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2",        ARM_ARCH_V2,     FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2a",       ARM_ARCH_V2S,    FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv2s",       ARM_ARCH_V2S,    FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv3",        ARM_ARCH_V3,     FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv3m",       ARM_ARCH_V3M,    FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4",        ARM_ARCH_V4,     FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4xm",      ARM_ARCH_V4xM,   FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4t",       ARM_ARCH_V4T,    FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv4txm",     ARM_ARCH_V4TxM,  FPU_ARCH_FPA),
	ARM_ARCH_OPT ("armv5",        ARM_ARCH_V5,     FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5t",       ARM_ARCH_V5T,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5txm",     ARM_ARCH_V5TxM,  FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5te",      ARM_ARCH_V5TE,   FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5texp",    ARM_ARCH_V5TExP, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv5tej",     ARM_ARCH_V5TEJ,  FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6",        ARM_ARCH_V6,     FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6j",       ARM_ARCH_V6,     FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6k",       ARM_ARCH_V6K,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6z",       ARM_ARCH_V6Z,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zk",      ARM_ARCH_V6ZK,   FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6t2",      ARM_ARCH_V6T2,   FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6kt2",     ARM_ARCH_V6KT2,  FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zt2",     ARM_ARCH_V6ZT2,  FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6zkt2",    ARM_ARCH_V6ZKT2, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6-m",      ARM_ARCH_V6M,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv6s-m",     ARM_ARCH_V6SM,   FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7",        ARM_ARCH_V7,     FPU_ARCH_VFP),
	/* The official spelling of the ARMv7 profile variants is the dashed form.
	   Accept the non-dashed form for compatibility with old toolchains.  */
	ARM_ARCH_OPT ("armv7a",       ARM_ARCH_V7A,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7r",       ARM_ARCH_V7R,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7m",       ARM_ARCH_V7M,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-a",      ARM_ARCH_V7A,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-r",      ARM_ARCH_V7R,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7-m",      ARM_ARCH_V7M,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv7e-m",     ARM_ARCH_V7EM,   FPU_ARCH_VFP),
	ARM_ARCH_OPT ("armv8-a",      ARM_ARCH_V8A,    FPU_ARCH_VFP),
	ARM_ARCH_OPT ("xscale",       ARM_ARCH_XSCALE, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("iwmmxt",       ARM_ARCH_IWMMXT, FPU_ARCH_VFP),
	ARM_ARCH_OPT ("iwmmxt2",      ARM_ARCH_IWMMXT2,FPU_ARCH_VFP),
	{ NULL, 0, ARM_ARCH_NONE, ARM_ARCH_NONE }
};
#endif

static int arm_mode = 0;
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[8];

static int arm_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr,
		unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta<0) return -1; // disable backward reads
	if ((delta+length)>4) return -1;
	memcpy (myaddr, bytes+delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void print_address(bfd_vma address, struct disassemble_info *info) {
	char tmp[32];
	if (buf_global == NULL)
		return;
	sprintf (tmp, "0x%08"PFMT64x"", (ut64)address);
	strcat (buf_global, tmp);
}

static int buf_fprintf(void *stream, const char *format, ...) {
	va_list ap;
	char *tmp;
	if (buf_global == NULL || format == NULL)
		return R_FALSE;
	va_start (ap, format);
 	tmp = malloc (strlen (format)+strlen (buf_global)+2);
	if (tmp == NULL)
		return R_FALSE;
	sprintf (tmp, "%s%s", buf_global, format);
	vsprintf (buf_global, tmp, ap);
	va_end (ap);
	free (tmp);
	return R_TRUE;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static char *oldcpu = NULL;
	static int oldcpucode = 0;
	int cpucode = 0;
	struct disassemble_info obj;
	char *options = (a->bits==16)? "force-thumb": "no-force-thumb";

	if (len<(a->bits/8)) return -1;
	buf_global = op->buf_asm;
	Offset = a->pc;
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&obj,'\0', sizeof (struct disassemble_info));
	arm_mode = a->bits;

cpucode = oldcpucode;
/* select cpu */
if (a->cpu) {
	if (oldcpu != a->cpu) {
		cpucode = atoi (a->cpu);
		if (!strcmp ("v5j", a->cpu)) 
			cpucode = 9;
	}
}
obj.arch = 0;
obj.mach = cpucode;
oldcpucode = cpucode;

	obj.buffer = bytes;
	obj.read_memory_func = &arm_buffer_read_memory;
	obj.symbol_at_address_func = &symbol_at_address;
	obj.memory_error_func = &memory_error_func;
	obj.print_address_func = &print_address;
	obj.endian = !a->big_endian;
	obj.fprintf_func = &buf_fprintf;
	obj.stream = stdout;
	obj.bytes_per_chunk =
	obj.bytes_per_line = (a->bits/8);

	op->buf_asm[0]='\0';
	if (a->bits==64) {
		obj.disassembler_options = NULL;
		/* is endianness ignored on 64bits? */
		//r_mem_copyendian (bytes, buf, 4, !a->big_endian);
		op->inst_len = print_insn_aarch64 ((bfd_vma)Offset, &obj);
	} else {
		obj.disassembler_options = options;
		op->inst_len = obj.endian?
			print_insn_little_arm ((bfd_vma)Offset, &obj):
			print_insn_big_arm ((bfd_vma)Offset, &obj);
	}
	if (op->inst_len == -1)
		strncpy (op->buf_asm, " (data)", R_ASM_BUFSIZE);
	return op->inst_len;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int is_thumb = a->bits==16? 1: 0;
	int opcode = armass_assemble (buf, a->pc, is_thumb);
	if (opcode==-1)
		return -1;
	if (a->bits>=32)
		r_mem_copyendian (op->buf, (void *)&opcode, 4, a->big_endian);
	else r_mem_copyendian (op->buf, (void *)&opcode, 2, !a->big_endian);
// XXX. thumb endian assembler needs no swap
	return (a->bits/8);
}

RAsmPlugin r_asm_plugin_arm = {
	.name = "arm",
	.arch = "arm",
	.bits = (int[]){ 16, 32, 64, 0 },
	.desc = "ARM disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm
};
#endif
