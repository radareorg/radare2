/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

int r_asm_init(struct r_asm_t *a)
{
	memset(a, '\0', sizeof(struct r_asm_t));
	r_asm_set_arch(a, R_ASM_ARCH_X86);
	r_asm_set_bits(a, 32);
	r_asm_set_big_endian(a, 0);
	r_asm_set_syntax(a, R_ASM_SYN_INTEL);
	r_asm_set_parser(a, R_ASM_PAR_NULL, NULL, NULL);
	r_asm_set_pc(a, 0);
	return R_TRUE;
}

struct r_asm_t *r_asm_new()
{
	struct r_asm_t *a = MALLOC_STRUCT(struct r_asm_t);
	r_asm_init(a);
	return a;
}

void r_asm_free(struct r_asm_t *a)
{
	free(a);
}

int r_asm_set_arch(struct r_asm_t *a, int arch)
{
	switch (arch) {
	case R_ASM_ARCH_X86:
		a->r_asm_disasm = &r_asm_x86_disasm;
		a->r_asm_asm = &r_asm_x86_asm;
		break;
	case R_ASM_ARCH_ARM:
		a->r_asm_disasm = &r_asm_arm_disasm;
		a->r_asm_asm = NULL;
		break;
	case R_ASM_ARCH_MIPS:
		a->r_asm_disasm = &r_asm_mips_disasm;
		a->r_asm_asm = NULL;
		break;
	case R_ASM_ARCH_SPARC:
		a->r_asm_disasm = &r_asm_sparc_disasm;
		a->r_asm_asm = NULL;
		break;
	case R_ASM_ARCH_PPC:
		a->r_asm_disasm = &r_asm_ppc_disasm;
		a->r_asm_asm = NULL;
		break;
	case R_ASM_ARCH_BF:
		a->r_asm_disasm = &r_asm_bf_disasm;
		a->r_asm_asm = NULL;
		break;
	default:
		a->r_asm_disasm = NULL;
		a->r_asm_asm = NULL;
		return R_FALSE;
	}
	a->arch = arch;
	return R_TRUE;
}

int r_asm_set_bits(struct r_asm_t *a, int bits)
{
	switch (bits) {
	case 16:
	case 32:
	case 64:
		a->bits = bits;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_asm_set_big_endian(struct r_asm_t *a, int boolean)
{
	a->big_endian = boolean;
	return R_TRUE;
}

int r_asm_set_syntax(struct r_asm_t *a, int syntax)
{
	switch (syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
	case R_ASM_SYN_OLLY:
		a->syntax = syntax;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_asm_set_parser(struct r_asm_t *a,
		int parser, int (*cb)(struct r_asm_t *a), void *aux)
{
	switch (parser) {
	case R_ASM_PAR_NULL:
		a->r_asm_parse = NULL;
		break;
	case R_ASM_PAR_PSEUDO:
		if (a->arch == R_ASM_ARCH_X86 && a->syntax == R_ASM_SYN_INTEL) {
			a->r_asm_parse = &r_asm_x86_pseudo;
			break;
		} else return R_FALSE;
	case R_ASM_PAR_AOP:
		if (a->arch == R_ASM_ARCH_X86) {
			a->r_asm_parse = &r_asm_x86_aop;
			break;
		} else return R_FALSE;
	case R_ASM_PAR_REALLOC:
		if (a->arch == R_ASM_ARCH_X86 && a->syntax == R_ASM_SYN_INTEL) {
			a->r_asm_parse = &r_asm_x86_realloc;
			break;
		} else return R_FALSE;
	default:
		return R_FALSE;
	}
	a->parser = parser;
	a->r_asm_parse_cb = cb;
	a->aux = aux;
	return R_TRUE;
}

int r_asm_set_pc(struct r_asm_t *a, u64 pc)
{
	a->pc = pc;
	return R_TRUE;
}

int r_asm_disasm(struct r_asm_t *a, u8 *buf, u64 len)
{
	if (a->r_asm_disasm != NULL)
		return a->r_asm_disasm(a, buf, len);
	
	return 0;
}

int r_asm_asm(struct r_asm_t *a, char *buf)
{
	if (a->r_asm_asm != NULL)
		return a->r_asm_asm(a, buf);
	
	return 0;
}

int r_asm_parse(struct r_asm_t *a)
{
	int ret = 0;

	if (a->r_asm_parse != NULL)
		ret = a->r_asm_parse(a);
	
	if (a->r_asm_parse_cb != NULL)
		a->r_asm_parse_cb(a);

	return ret;
}
