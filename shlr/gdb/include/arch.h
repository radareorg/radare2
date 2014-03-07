/*! \file */
#ifndef ARCH_H
#define ARCH_H

#define ARCH_X86_64 0
#define ARCH_X86_32 1

/*!
 * This struct defines a generic
 * register view
 */
typedef struct registers_t {
	char name[32]; /*! The Name of the current register */
	uint64_t offset; /*! Offset in the data block */
	uint64_t size;	/*! Size of the register */
	uint64_t value; /*! Saves the value of the register */
} registers_t;

#endif
