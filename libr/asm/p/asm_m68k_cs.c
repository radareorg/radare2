/* radare2 - LGPL - Copyright 2015-2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#warning Cannot find capstone-m68k support
#endif

#if CAPSTONE_HAS_M68K

static bool check_features(RAsm *a, cs_insn *insn);
static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn = NULL;
	int ret, n = 0;
	cs_mode mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || a->bits != obits) {
		cs_close (&cd);
		cd = 0; // unnecessary
		omode = mode;
		obits = a->bits;
	}

	// replace this with the asm.features?
	if (a->cpu && strstr (a->cpu, "68000"))
		mode |= CS_MODE_M68K_000;
	if (a->cpu && strstr (a->cpu, "68010"))
		mode |= CS_MODE_M68K_010;
	if (a->cpu && strstr (a->cpu, "68020"))
		mode |= CS_MODE_M68K_020;
	if (a->cpu && strstr (a->cpu, "68030"))
		mode |= CS_MODE_M68K_030;
	if (a->cpu && strstr (a->cpu, "68040"))
		mode |= CS_MODE_M68K_040;
	if (a->cpu && strstr (a->cpu, "68060"))
		mode |= CS_MODE_M68K_060;
	op->size = 4;
	op->buf_asm[0] = 0;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_M68K, mode, &cd);
		if (ret) {
			ret = -1;
			goto beach;
		}
	}
	if (a->features && *a->features) {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm (cd, buf, R_MIN (8, len),
		a->pc, 1, &insn);
	if (n<1) {
		ret = -1;
		goto beach;
	}
	op->size = 0;
	if (insn->size<1) {
		ret = -1;
		goto beach;
	}
	if (a->features && *a->features) {
		if (!check_features (a, insn)) {
			op->size = insn->size;
			strcpy (op->buf_asm, "illegal");
		}
	}
	if (!op->size) {
		op->size = insn->size;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
			insn->mnemonic,
			insn->op_str[0]?" ":"",
			insn->op_str);
	}
	{
		char *p = r_str_replace (strdup (op->buf_asm),
			"$", "0x", true);
		if (p) {
			strncpy (op->buf_asm, p, R_ASM_BUFSIZE-1);
			free (p);
		}
	}
	cs_free (insn, n);
	beach:
	//cs_close (&cd);
	if (!strncmp (op->buf_asm, "dc.w", 4)) {
		strcpy (op->buf_asm, "invalid");
	}
	r_str_rmch (op->buf_asm, '#');
	return op->size;
}

RAsmPlugin r_asm_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Capstone M68K disassembler",
	.cpus = "68000,68010,68020,68030,68040,68060",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = &mnemonics,
};

static bool check_features(RAsm *a, cs_insn *insn) {
	/* TODO: Implement support for m68k */
	return true;
}

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k_cs,
	.version = R2_VERSION
};
#endif

#else
RAsmPlugin r_asm_plugin_m68k_cs = {
	.name = "m68k.cs (unsupported)",
	.desc = "Capstone M68K disassembler (unsupported)",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k_cs,
	.version = R2_VERSION
};
#endif

#endif
