/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

#define USE_CUSTOM_ALLOC 0

#if USE_CUSTOM_ALLOC
static int bufi = 0;
static char buf[65535];

#define D if(0)

static void *my_malloc(size_t s) {
	char *ret;
	D printf ("MALLOC %d / %d\n", (int)s, bufi);
	ret = buf+bufi;
	bufi += (s*3);
	if (bufi>sizeof (buf)) {
		eprintf ("MALLOC FAIL\n");
		return NULL;
	}
	return ret;
}

static void *my_calloc(size_t c, size_t s) {
	ut8 *p = my_malloc (c*s);
	memset (p, 0, c*s);
	return p;
}

static void *my_realloc(void *p, size_t s) {
	if (!p) return my_malloc (s);
	D eprintf ("REALLOC %p %d\n", p, (int)s);
	return p;
}

static void my_free(void *p) {
	D eprintf ("FREE %d bytes\n", bufi);
	D printf ("FREE %p\n", p);
}
#endif

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

	mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	if (cd && mode != omode) {
	//if (cd) {
#if USE_CUSTOM_ALLOC
		bufi = 0;
		cs_opt_mem mem = {
			.malloc = &malloc,
			.calloc = &calloc,
			.realloc = &realloc,
			.free = &free
		};
		cs_option (cd, CS_OPT_MEM, (size_t)&mem);
#endif
		cs_close (&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_X86, mode, &cd);
		if (ret) return 0;
#if USE_CUSTOM_ALLOC
		bufi = 0;
		cs_opt_mem mem = {
			.malloc = &my_malloc,
			.calloc = &my_calloc,
			.realloc = &my_realloc,
			.free = &my_free
		};
		cs_option (cd, CS_OPT_MEM, (size_t)&mem);
#endif
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm_ex (cd, (const ut8*)buf, len, off, 1, &insn);
	if (n>0) {
		if (insn->size>0) {
			op->size = insn->size;
			if (insn->op_str) {
				char *ptrstr;
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
					insn->mnemonic, insn->op_str[0]?" ":"",
					insn->op_str);
				ptrstr = strstr (op->buf_asm, "ptr ");
				if (ptrstr) {
					memmove (ptrstr, ptrstr+4, strlen (ptrstr+4)+1);
				}
			} else {
				eprintf ("op_str is null wtf\n");
			}
		}
	}
	cs_free (insn, n);
#if USE_CUSTOM_ALLOC
	bufi = 0;
#endif
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86.cs",
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
