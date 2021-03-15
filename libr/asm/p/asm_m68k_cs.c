/* radare2 - LGPL - Copyright 2015-2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#ifdef _MSC_VER
#pragma message ("Cannot find capstone-m68k support")
#else
#warning Cannot find capstone-m68k support
#endif
#endif

#if CAPSTONE_HAS_M68K

// Size of the longest instruction in bytes
#define M68K_LONGEST_INSTRUCTION 10

static bool check_features(RAsm *a, cs_insn *insn);
static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const char *buf_asm = NULL;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn = NULL;
	int ret = 0, n = 0;
	cs_mode mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || a->bits != obits) {
		cs_close (&cd);
		cd = 0; // unnecessary
		omode = mode;
		obits = a->bits;
	}

	// replace this with the asm.features?
	if (a->cpu && strstr (a->cpu, "68000")) {
		mode |= CS_MODE_M68K_000;
	}
	if (a->cpu && strstr (a->cpu, "68010")) {
		mode |= CS_MODE_M68K_010;
	}
	if (a->cpu && strstr (a->cpu, "68020")) {
		mode |= CS_MODE_M68K_020;
	}
	if (a->cpu && strstr (a->cpu, "68030")) {
		mode |= CS_MODE_M68K_030;
	}
	if (a->cpu && strstr (a->cpu, "68040")) {
		mode |= CS_MODE_M68K_040;
	}
	if (a->cpu && strstr (a->cpu, "68060")) {
		mode |= CS_MODE_M68K_060;
	}
	if (op) {
		op->size = 4;
	}
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
	if (!buf) {
		goto beach;
	}

	ut8 mybuf[M68K_LONGEST_INSTRUCTION] = {0};
	int mylen = R_MIN (M68K_LONGEST_INSTRUCTION, len);
	memcpy (mybuf, buf, mylen);

	n = cs_disasm (cd, mybuf, mylen, a->pc, 1, &insn);
	if (n < 1) {
		ret = -1;
		goto beach;
	}
	if (op) {
		op->size = 0;
	}
	if (insn->size<1) {
		ret = -1;
		goto beach;
	}
	if (a->features && *a->features) {
		if (!check_features (a, insn)) {
			if (op) {
				op->size = insn->size;
				buf_asm = "illegal";
			}
		}
	}
	if (op && !op->size) {
		op->size = insn->size;
		buf_asm = sdb_fmt ("%s%s%s", insn->mnemonic, insn->op_str[0]?" ":"", insn->op_str);
	}
	if (op && buf_asm) {
		char *p = r_str_replace (strdup (buf_asm), "$", "0x", true);
		if (p) {
			r_str_replace_char (p, '#', 0);
			r_asm_op_set_asm (op, p);
			free (p);
		}
	}
	cs_free (insn, n);
beach:
	//cs_close (&cd);
	if (op && buf_asm) {
		if (!strncmp (buf_asm, "dc.w", 4)) {
			r_asm_op_set_asm (op, "invalid");
		}
		return op->size;
	}
	return ret;
}

RAsmPlugin r_asm_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Capstone M68K disassembler",
	.cpus = "68000,68010,68020,68030,68040,68060",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = &mnemonics,
};

static bool check_features(RAsm *a, cs_insn *insn) {
	/* TODO: Implement support for m68k */
	return true;
}

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
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
	.author = "pancake",
	.arch = "m68k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m68k_cs,
	.version = R2_VERSION
};
#endif

#endif
