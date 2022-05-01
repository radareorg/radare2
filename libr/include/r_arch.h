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

static inline void r_arch_use(RArchConfig *config, R_NULLABLE const char *arch) {
	r_return_if_fail (config);
	R_LOG_DEBUG ("RArch.USE (%s)", arch);
	if (arch && !strcmp (arch, "null")) {
		return;
	}
	free (config->arch);
	config->arch = R_STR_ISNOTEMPTY (arch) ? strdup (arch) : NULL;
}

static inline void r_arch_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu) {
	r_return_if_fail (config);
	R_LOG_DEBUG ("RArch.CPU (%s)", cpu);
	free (config->cpu);
	config->cpu = R_STR_ISNOTEMPTY (cpu) ? strdup (cpu) : NULL;
}

static inline RArchConfig *r_arch_config_new(void) {
	RArchConfig *ac = R_NEW0 (RArchConfig);
	if (!ac) {
		return NULL;
	}
	ac->arch = strdup (R_SYS_ARCH);
	ac->bits = R_SYS_BITS;
	ac->bitshift = 0;
	ac->syntax = R_ASM_SYNTAX_INTEL;
	ac->free = (void (*)(void*))my_ac_free;
	ac->big_endian = false;
	return r_ref (ac);
}

#endif
