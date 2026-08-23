/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _FENV_H
#define _FENV_H

#ifdef __cplusplus
extern "C" {
#endif

#define FE_TONEAREST 0
#define FE_DOWNWARD 0x400
#define FE_UPWARD 0x800
#define FE_TOWARDZERO 0xc00

#define FE_INVALID 1
#define FE_DIVBYZERO 4
#define FE_OVERFLOW 8
#define FE_UNDERFLOW 16
#define FE_INEXACT 32
#define FE_ALL_EXCEPT 63

typedef unsigned short fexcept_t;
typedef struct {
	unsigned short __control_word;
	unsigned short __unused1;
	unsigned short __status_word;
	unsigned short __unused2;
	unsigned short __tags;
	unsigned short __unused3;
	unsigned int __eip;
	unsigned short __cs_selector;
	unsigned int __opcode : 11;
	unsigned int __unused4 : 5;
	unsigned int __data_offset;
	unsigned short __data_selector;
	unsigned short __unused5;
	unsigned int __mxcsr;
} fenv_t;

static inline int fegetround(void) {
	return FE_TONEAREST;
}
static inline int fesetround(int round) {
	(void)round;
	return 0;
}
static inline int feclearexcept(int excepts) {
	(void)excepts;
	return 0;
}
static inline int fetestexcept(int excepts) {
	(void)excepts;
	return 0;
}
static inline int feraiseexcept(int excepts) {
	(void)excepts;
	return 0;
}
static inline int fegetenv(fenv_t *envp) {
	(void)envp;
	return 0;
}
static inline int fesetenv(const fenv_t *envp) {
	(void)envp;
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _FENV_H */
