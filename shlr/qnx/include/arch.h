/*! \file */
#ifndef ARCH_H
#define ARCH_H

#include "r_types.h"

#define ARCH_X86_64 0
#define ARCH_X86_32 1
#define ARCH_ARM_32 2
#define ARCH_ARM_64 3

/*!
 * This struct defines a generic
 * register view
 */
typedef struct registers_t {
	char name[32];   /*! The Name of the current register */
	ut64 offset; /*! Offset in the data block */
	ut64 size;   /*! Size of the register */
} registers_t;

#endif
