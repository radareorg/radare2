/* radare2 - LGPL - Copyright 2013-2021 - pancake */

// instruction set : http://www.tachyonsoft.com/inst390m.htm

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

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
	mode = CS_MODE_BIG_ENDIAN;
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	op->size = 4;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_SYSZ, mode, &cd);
		if (ret) {
			return -1;
		}
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	r_asm_op_set_asm (op, "invalid");
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
	if (n > 0) {
		if (insn->size > 0) {
			op->size = insn->size;
			char *buf_asm = r_str_newf ("%s%s%s",
					insn->mnemonic, insn->op_str[0]?" ": "",
					insn->op_str);
			char *ptrstr = strstr (buf_asm, "ptr ");
			if (ptrstr) {
				memmove (ptrstr, ptrstr + 4, strlen (ptrstr + 4) + 1);
			}
			r_asm_op_set_asm (op, buf_asm);
			free (buf_asm);
		}
		cs_free (insn, n);
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_s390_cs = {
	.name = "s390",
	.desc = "s390/SystemZ CPU disassembler",
	.license = "BSD",
	.arch = "s390",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_BIG,
	.fini = the_end,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_s390_cs,
	.version = R2_VERSION
};
#endif
