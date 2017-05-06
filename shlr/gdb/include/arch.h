/*! \file */
#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

#define ARCH_X86_64 0
#define ARCH_X86_32 1
#define ARCH_ARM_32 2
#define ARCH_ARM_64 3
#define ARCH_MIPS 4
#define ARCH_AVR 5
#define ARCH_LM32 6

/*!
 * This struct defines a generic
 * register view
 */
typedef struct registers_t {
	char name[32]; /*! The Name of the current register */
	uint64_t offset; /*! Offset in the data block */
	uint64_t size;	/*! Size of the register */
} registers_t;

/*!
 * Existing register sets
 */
extern registers_t x86_64[];
extern registers_t x86_32[];
extern registers_t arm32[];
extern registers_t aarch64[];
extern registers_t lm32[];
extern registers_t mips[];
extern registers_t avr[];


#endif
