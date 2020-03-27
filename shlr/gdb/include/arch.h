/*! \file */
#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

/*!
 * This struct defines a generic register view
 */
typedef struct gdb_reg {
	char name[32]; /*! The Name of the current register */
	uint64_t offset; /*! Offset in the data block */
	uint64_t size;	/*! Size of the register */
} gdb_reg_t;

gdb_reg_t *arch_parse_reg_profile(const char * reg_profile);

#endif
