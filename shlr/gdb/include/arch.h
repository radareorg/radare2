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

/*!
 * Existing register sets
 */
extern gdb_reg_t gdb_regs_x86_64[];
extern gdb_reg_t gdb_regs_x86_32[];
extern gdb_reg_t gdb_regs_arm32[];
extern gdb_reg_t gdb_regs_aarch64[];
extern gdb_reg_t gdb_regs_lm32[];
extern gdb_reg_t gdb_regs_mips[];
extern gdb_reg_t gdb_regs_avr[];
extern gdb_reg_t gdb_regs_v850[];


#endif
