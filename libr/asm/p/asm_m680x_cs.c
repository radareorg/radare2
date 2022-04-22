/* radare2 - LGPL - Copyright 2018-2021 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cs_version.h"

#if CS_API_MAJOR >= 4 && CS_API_MINOR >= 0
#define CAPSTONE_HAS_M680X 1
#else
#define CAPSTONE_HAS_M680X 0
#endif

#if CAPSTONE_HAS_M680X

static csh cd = 0;

static int m680xmode(const char *str) {
	if (!str) {
		return CS_MODE_M680X_6800;
	}
	// replace this with the asm.features?
	if (strstr (str, "6800")) {
		return CS_MODE_M680X_6800;
	}
	if (strstr (str, "6801")) {
		return CS_MODE_M680X_6801;
	} else if (strstr (str, "6805")) {
		return CS_MODE_M680X_6805;
	} else if (strstr (str, "6808")) {
		return CS_MODE_M680X_6808;
	} else if (strstr (str, "6809")) {
		return CS_MODE_M680X_6809;
	} else if (strstr (str, "6811")) {
		return CS_MODE_M680X_6811;
	} else if (strstr (str, "cpu12")) {
		return CS_MODE_M680X_CPU12;
	} else if (strstr (str, "6301")) {
		return CS_MODE_M680X_6301;
	}
	if (strstr (str, "6309")) {
		return CS_MODE_M680X_6309;
	}
	if (strstr (str, "hcs08")) {
		return CS_MODE_M680X_HCS08;
	}
	return CS_MODE_M680X_6800;
}

static bool the_end(void *p) {
	if (cd) {
		cs_close (&cd);
		cd = 0;
	}
	return true;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, n, ret;
	ut64 off = a->pc;
	cs_insn* insn = NULL;
	mode = m680xmode (a->config->cpu);
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_M680X, mode, &cd);
		if (ret) {
			return 0;
		}
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
	if (n > 0) {
		if (insn->size > 0) {
			op->size = insn->size;
			r_strf_var (buf_asm, 256, "%s%s%s",
					insn->mnemonic, insn->op_str[0]?" ": "",
					insn->op_str);
			char *ptrstr = strstr (buf_asm, "ptr ");
			if (ptrstr) {
				memmove (ptrstr, ptrstr + 4, strlen (ptrstr + 4) + 1);
			}
			r_asm_op_set_asm (op, buf_asm);
		}
		cs_free (insn, n);
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_m680x_cs = {
	.name = "m680x",
	.cpus = "6800,6801,6805,6808,6809,6811,cpu12,6301,6309,hcs08",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" M680X Disassembler",
	.license = "BSD",
	.arch = "m680x",
	.bits = 8 | 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.fini = the_end,
	.disassemble = &disassemble,
};

#else
RAsmPlugin r_asm_plugin_m680x_cs = {
	.name = "m680x",
	.desc = "Capstone M680X Disassembler (Not supported)",
	.license = "BSD",
	.arch = "m680x",
	.bits = 8 | 32,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m680x_cs,
	.version = R2_VERSION
};
#endif
