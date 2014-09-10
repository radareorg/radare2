/* radare2 - LGPL - Copyright 2013-2014 - pancake */

// instruction set : http://www.tachyonsoft.com/inst390m.htm

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static csh cd = 0;

static int the_end(void *p) {
	if (cd) {
		cs_close (&cd);
		cd = 0;
	}
	return R_TRUE;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, n, ret;
	ut64 off = a->pc;
	cs_insn* insn = NULL;
	mode = CS_MODE_BIG_ENDIAN;
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_SYSZ, mode, &cd);
		if (ret) return 0;
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
	if (n>0) {
		if (insn->size>0) {
			op->size = insn->size;
			char *ptrstr;
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
					insn->mnemonic, insn->op_str[0]?" ":"",
					insn->op_str);
			ptrstr = strstr (op->buf_asm, "ptr ");
			if (ptrstr) {
				memmove (ptrstr, ptrstr+4, strlen (ptrstr+4)+1);
			}
		}
		cs_free (insn, n);
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_sysz = {
	.name = "sysz",
	.desc = "SystemZ CPU disassembler",
	.license = "BSD",
	.arch = "sysz",
	.bits = 32,
	.init = NULL,
	.fini = the_end,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sysz
};
#endif
