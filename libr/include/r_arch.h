/* radare2 - LGPL - Copyright 2009-2022 - nibble, pancake, xvilka */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

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
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *features;
	R_REF_TYPE;
} RArchConfig;

R_API void r_arch_use(RArchConfig *config, R_NULLABLE const char *arch);
R_API void r_arch_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu);
R_API void r_arch_set_bits(RArchConfig *config, int bits);
R_API RArchConfig *r_arch_config_new(void);

#ifdef __cplusplus
}
#endif

#endif
