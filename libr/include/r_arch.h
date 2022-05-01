/* radare2 - LGPL - Copyright 2009-2022 - nibble, pancake, xvilka */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>

// TODO: rename to R_ARCH
enum {
	R_ASM_SYNTAX_NONE = 0,
	R_ASM_SYNTAX_INTEL,
	R_ASM_SYNTAX_ATT,
	R_ASM_SYNTAX_MASM,
	R_ASM_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	R_ASM_SYNTAX_JZ, // hack to use jz instead of je on x86
};


// TODO: add reference counting and accessor APIs
typedef struct r_arch_config_t {
	char *arch;
	char *cpu;
	char *os;
	int bits;
	int big_endian;
	int syntax;
	//
	int pcalign;
	int dataalign;
	int seggrn;
	int invhex;
	int bitshift;
	char *features;
	R_REF_TYPE;
} RArchConfig;

// TODO: create r_arch API at some point and move this from H to C
static inline void my_ac_free(RArchConfig *cfg) {
	if (cfg) {
		free (cfg->arch);
		free (cfg->cpu);
		free (cfg->os);
		free (cfg);
	}
}

static inline RArchConfig *r_arch_config_new(void) {
	RArchConfig *ac = R_NEW0 (RArchConfig);
	ac->arch = strdup (R_SYS_ARCH);
	ac->bits = R_SYS_BITS;
	ac->bitshift = 0;
	ac->syntax = R_ASM_SYNTAX_INTEL;
	ac->free = (void (*)(void*))my_ac_free;
	ac->big_endian = false;
	return r_ref (ac);
}

#endif
