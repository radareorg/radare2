/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

#define USE_ITER_API 0

static csh cd = 0;
static int n = 0;
static cs_insn *insn = NULL;

static int the_end(void *p) {
#if !USE_ITER_API
	if (insn) {
		cs_free (insn, n);
		insn = NULL;
	}
#endif
	if (cd) {
		cs_close (&cd);
		cd = 0;
	}
	return R_TRUE;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, ret;
	ut64 off = a->pc;

	mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_X86, mode, &cd);
		if (ret) return 0;
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	if (a->syntax == R_ASM_SYNTAX_ATT)
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	op->size = 1;
#if USE_ITER_API
	{
		size_t size = len;
		if (insn == NULL)
			insn = cs_malloc (cd);
		insn->size = 1;
		memset (insn, 0, insn->size);
		n = cs_disasm_iter (cd, (const uint8_t**)&buf, &size, (uint64_t*)&off, insn);
	}
#else
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
#endif
	if (n>0 && insn->size>0) {
		char *ptrstr;
		op->size = insn->size;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
				insn->mnemonic, insn->op_str[0]?" ":"",
				insn->op_str);
		ptrstr = strstr (op->buf_asm, "ptr ");
		if (ptrstr) {
			memmove (ptrstr, ptrstr+4, strlen (ptrstr+4)+1);
		}
	}
#if USE_ITER_API
	/* do nothing because it should be allocated once and freed in the_end */
#else
	cs_free (insn, n);
	insn = NULL;
#endif
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone X86 disassembler",
	.license = "BSD",
	.arch = "x86",
	.bits = 16|32|64,
	.init = NULL,
	.fini = the_end,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_cs
};
#endif
