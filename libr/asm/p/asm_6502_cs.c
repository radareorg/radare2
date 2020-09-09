/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

#if CS_API_MAJOR >= 4 && CS_API_MINOR >= 1
#define CAPSTONE_HAS_MOS65XX 1
#else
#define CAPSTONE_HAS_MOS65XX 0
#endif

#if CAPSTONE_HAS_MOS65XX

static csh cd = 0;

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
	mode = CS_MODE_LITTLE_ENDIAN;
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_MOS65XX, mode, &cd);
		if (ret) {
			return 0;
		}
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
	if (n>0) {
		if (insn->size > 0) {
			op->size = insn->size;
			char *buf_asm = sdb_fmt ("%s%s%s",
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

RAsmPlugin r_asm_plugin_6502_cs = {
	.name = "6502.cs",
	.desc = "Capstone mos65xx CPU disassembler",
	.license = "BSD",
	.arch = "6502",
	.bits = 8|32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.fini = the_end,
	.disassemble = &disassemble,
};

#else
RAsmPlugin r_asm_plugin_6502_cs = {
	.name = "6502.cs",
	.desc = "Capstone mos65xx CPU disassembler (not supported)",
	.license = "BSD",
	.arch = "6502",
	.bits = 8|32,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_6502_cs,
	.version = R2_VERSION
};
#endif
