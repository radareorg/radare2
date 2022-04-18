/* radare2 - LGPL - Copyright 2013-2022 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cs_version.h"

#define USE_ITER_API 1

static R_TH_LOCAL csh cd = 0;
static R_TH_LOCAL int n = 0;

static bool the_end(void *p) {
#if 0
#if !USE_ITER_API
	if (insn) {
		cs_free (insn, n);
		insn = NULL;
	}
#endif
#endif
	if (cd) {
		cs_close (&cd);
		cd = 0;
	}
	return true;
}

#include "cs_mnemonics.c"

#include "asm_x86_vm.c"

static bool check_features(const char *features, cs_insn *insn) {
	if (!features || !*features) {
		return false;
	}
	if (!insn || !insn->detail) {
		return false;
	}
	int i;
	for (i = 0; i < insn->detail->groups_count; i++) {
		int id = insn->detail->groups[i];
		if (id < 128) {
			continue;
		}
		if (id == X86_GRP_MODE32) {
			continue;
		}
		if (id == X86_GRP_MODE64) {
			continue;
		}
		const char *name = cs_group_name (cd, id);
		if (!name) {
			return true;
		}
		if (!strstr (features, name)) {
			return false;
		}
	}
	return true;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static R_TH_LOCAL int omode = 0;
	int ret;
	ut64 off = a->pc;

	const int bits = a->config->bits;
	int mode = (bits == 64)? CS_MODE_64:
		(bits == 32)? CS_MODE_32:
		(bits == 16)? CS_MODE_16: 0;
	if (cd && mode != omode) {
		cs_close (&cd);
		cd = 0;
	}
	if (op) {
		op->size = 0;
	}
	omode = mode;
	if (cd == 0) {
		ret = cs_open (CS_ARCH_X86, mode, &cd);
		if (ret) {
			return 0;
		}
	}
	const char *features = a->config->features;
	if (R_STR_ISNOTEMPTY (features)) {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_ON);
	} else {
		cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	// always unsigned immediates (kernel addresses)
	// maybe r2 should have an option for this too?
#if CS_API_MAJOR >= 4
	cs_option (cd, CS_OPT_UNSIGNED, CS_OPT_ON);
#endif
	if (a->config->syntax == R_ASM_SYNTAX_MASM) {
#if CS_API_MAJOR >= 4
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
#endif
	} else if (a->config->syntax == R_ASM_SYNTAX_ATT) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	} else {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	}
	if (!op) {
		return true;
	}
	op->size = 1;
	cs_insn *insn = NULL;
#if USE_ITER_API
	cs_insn insnack = {0};
	cs_detail insnack_detail = {0};
	insnack.detail = &insnack_detail;
	size_t size = len;
	insn = &insnack;
	n = cs_disasm_iter (cd, (const uint8_t**)&buf, &size, (uint64_t*)&off, insn);
#else
	n = cs_disasm (cd, (const ut8*)buf, len, off, 1, &insn);
#endif
        //XXX: capstone lcall seg:off workaround, remove when capstone will be fixed
	if (n >= 1 && mode == CS_MODE_16 && !strncmp (insn->mnemonic, "lcall", 5)) {
		(void) r_str_replace (insn->op_str, ", ", ":", 0);
	}
	if (op) {
		op->size = 0;
	}
	if (!check_features (features, insn)) {
		op->size = insn->size;
		r_asm_op_set_asm (op, "illegal");
	}
	if (op->size == 0 && n > 0 && insn->size > 0) {
		op->size = insn->size;
		char *buf_asm = r_str_newf ("%s%s%s",
				insn->mnemonic, insn->op_str[0]?" ":"",
				insn->op_str);
		if (a->config->syntax != R_ASM_SYNTAX_MASM) {
			char *ptrstr = strstr (buf_asm, "ptr ");
			if (ptrstr) {
				memmove (ptrstr, ptrstr + 4, strlen (ptrstr + 4) + 1);
			}
		}
		r_asm_op_set_asm (op, buf_asm);
		free (buf_asm);
	} else {
		decompile_vm (a, op, buf, len);
	}
	if (a->config->syntax == R_ASM_SYNTAX_JZ) {
		char *buf_asm = r_strbuf_get (&op->buf_asm);
		if (!strncmp (buf_asm, "je ", 3)) {
			memcpy (buf_asm, "jz", 2);
		} else if (!strncmp (buf_asm, "jne ", 4)) {
			memcpy (buf_asm, "jnz", 3);
		}
	}
#if USE_ITER_API
	/* do nothing because it should be allocated once and freed in the_end */
#else
	if (insn) {
		cs_free (insn, n);
	}
#endif
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" X86 disassembler",
	.license = "BSD",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.fini = the_end,
	.mnemonics = mnemonics,
	.disassemble = &disassemble,
	.features = "vm,3dnow,aes,adx,avx,avx2,avx512,bmi,bmi2,cmov,"
		"f16c,fma,fma4,fsgsbase,hle,mmx,rtm,sha,sse1,sse2,"
		"sse3,sse41,sse42,sse4a,ssse3,pclmul,xop"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct *radare_plugin_function(void) {
	RLibStruct *rp = R_NEW0 (RLibStruct);
	if (rp) {
		rp->type = R_LIB_TYPE_ASM;
		rp->data = &r_asm_plugin_x86_cs;
		rp->version = R2_VERSION;
	}
	return rp;
}
#endif
