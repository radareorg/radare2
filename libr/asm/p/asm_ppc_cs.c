/* radare2 - LGPL - Copyright 2014-2015 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>

static csh handle = 0;

static bool the_end(void *p) {
	if (handle) {
		cs_close (&handle);
		handle = 0;
	}
	return true;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int n, ret;
	ut64 off = a->pc;
	cs_insn* insn;
	
	int mode = (a->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	if (handle && mode != omode) {
		cs_close (&handle);
		handle = 0;
	}
	op->size = 0;
	omode = mode;
	op->buf_asm[0] = 0;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_PPC, mode, &handle);
		if (ret) return 0;
	}
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm (handle, (const ut8*)buf, len, off, 1, &insn);
	op->size = 4;
	if (n > 0 && insn->size > 0) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
			insn->mnemonic, insn->op_str[0]?" ":"",
			insn->op_str);
		cs_free (insn, n);
		return op->size;
	}
	//op->size = -1;
	cs_free (insn, n);
	return 4;
}

RAsmPlugin r_asm_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC disassembler",
	.license = "BSD",
	.arch = "ppc",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.fini = the_end,
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif
