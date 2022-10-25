/* v850.h -- Header file for NEC V850 opcode table
   Copyright (C) 1996-2020 Free Software Foundation, Inc.
   Written by J.T. Conklin, Cygnus Support

   This file is part of GDB, GAS, and the GNU binutils.

   -- hacked up by pancake for analysis and emulation purposes
*/

#ifndef V850DIS_H
#define V850DIS_H

#include <r_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct v850_opcode {
	const char *name;
	unsigned long opcode; // binary representation of the opcode
	unsigned long mask; // binary mask to match the opcode bits
	unsigned char operands[8];
	unsigned int memop; // which operand is accessing the memory?
	unsigned int processors; // mask for cpu models
	int type; // R_ANAL_OP_TYPE_xxx
	char *esil;
	int family; // R_ANAL_OP_FAMILY_xxx
} v850_opcode;

typedef struct {
	int atype;
	ut64 value;
	const char *str;
} v850_arg;

typedef struct {
	char *text;
	char *esil;
	int size;
	long value; // used to save references, values, immedaites, ..
	const v850_opcode *op;
	v850_arg args[4];
} v850np_inst;

/* Values for architecture number.  */
enum {
	arch_V850 = 0,
	arch_V850E = 1,
	arch_V850E1 = 2,
	arch_V850E2 = 3,
	arch_V850E2V3 = 4,
	arch_V850E3V5 = 5,
	arch_separator = 6
};

#define opt_EXTENSION  (arch_separator)
#define opt_ALIAS      (opt_EXTENSION + 1)

/* Values for the processors field in the v850_opcode structure.  */
#define V850_CPU_0      (1 << (arch_V850))     /* Just the V850.  */
#define V850_CPU_E      (1 << (arch_V850E))    /* Just the V850E.  */
#define V850_CPU_E1     (1 << (arch_V850E1))   /* Just the V850E1.  */
#define V850_CPU_E2     (1 << (arch_V850E2))   /* Just the V850E2.  */
#define V850_CPU_E2V3   (1 << (arch_V850E2V3)) /* Just the V850E2V3.  */
#define V850_CPU_E3V5   (1 << (arch_V850E3V5)) /* Just the V850E3V5.  */
#define V850_CPU_E0     (1 << 8) // used by the old v850 plugin

/* UPPERS */
#define V850_CPU_E3V5_UP (V850_CPU_E3V5)
#define V850_CPU_E2V3_UP (V850_CPU_E2V3 | V850_CPU_E3V5_UP)
#define V850_CPU_E2_UP   (V850_CPU_E2   | V850_CPU_E2V3_UP)
#define V850_CPU_E_UP    (V850_CPU_E    | V850_CPU_E1 | V850_CPU_E2_UP)
#define V850_CPU_ALL     (V850_CPU_0    | V850_CPU_E_UP)

#define V850_CPU_MASK    (V850_CPU_ALL)
#define V850_CPU_NON0    (V850_CPU_ALL & (~ V850_CPU_0))         /* Any processor except the V850.  */
#define V850_CPU_UNKNOWN ~(V850_CPU_MASK)

/* OPTIONS */
#define V850_CPU_OPTION_EXTENSION (1 << (opt_EXTENSION))         /* Enable extension opcodes.  */
#define V850_CPU_OPTION_ALIAS     (1 << (opt_ALIAS))             /* Enable alias opcodes.  */

#define SET_V850_CPU_MASK(mask,set)	((mask) = ((mask) & ~V850_CPU_MASK) | (set))

// the table is sorted by major opcode number for performance reasons
extern const v850_opcode v850_opcodes[];
extern const size_t v850_num_opcodes;


struct v850_operand {
	/* The number of bits in the operand. when -1, those bits are not contiguous */
	int bits;

	/* (bits >= 0):  How far the operand is left shifted in the instruction.  */
	/* (bits == -1): Bit mask of the bits in the operand.  */
	int shift;

	/* Insertion function.  This is used by the assembler.  To insert an
	   operand value into an instruction, check this field.

	   If it is NULL, execute
	   i |= (op & ((1 << o->bits) - 1)) << o->shift;
	   (i is the instruction which we are filling in, o is a pointer to
	   this structure, and op is the opcode value; this assumes twos
	   complement arithmetic).

	   If this field is not NULL, then simply call it with the
	   instruction and the operand value.  It will return the new value
	   of the instruction.  If the ERRMSG argument is not NULL, then if
	   the operand value is illegal, *ERRMSG will be set to a warning
	   string (the operand will be inserted in any case).  If the
	   operand value is legal, *ERRMSG will be unchanged (most operands
	   can accept any value).  */
	ut64 (* insert) (ut64 instruction, long op, const char ** errmsg);

	/* Extraction function.  This is used by the disassembler.  To
	   extract this operand type from an instruction, check this field.

	   If it is NULL, compute
	   op = o->bits == -1 ? ((i) & o->shift) : ((i) >> o->shift) & ((1 << o->bits) - 1);
	   if (o->flags & V850_OPERAND_SIGNED)
	   op = (op << (32 - o->bits)) >> (32 - o->bits);
	   (i is the instruction, o is a pointer to this structure, and op
	   is the result; this assumes twos complement arithmetic).

	   If this field is not NULL, then simply call it with the
	   instruction value.  It will return the value of the operand.  If
	   the INVALID argument is not NULL, *INVALID will be set to
	   non-zero if this operand type can not actually be extracted from
	   this operand (i.e., the instruction does not match).  If the
	   operand is valid, *INVALID will not be changed.  */
	ut64 (* extract) (ut64 instruction, bool * invalid);

	/* One bit syntax flags.  */
	int flags;
	int default_reloc;
};

/* Elements in the table are retrieved by indexing with values from
   the operands field of the v850_opcodes table.  */

extern const struct v850_operand v850_operands[];

/* Values defined for the flags field of a struct v850_operand.  */

/* This operand names a general purpose register.  */
#define V850_OPERAND_REG	0x01
/* This operand is the ep register.  */
#define V850_OPERAND_EP		0x02
/* This operand names a system register.  */
#define V850_OPERAND_SRG	0x04
/* Prologue eilogue type instruction, V850E specific.  */
#define V850E_OPERAND_REG_LIST	0x08
/* This operand names a condition code used in the setf instruction.  */
#define V850_OPERAND_CC		0x10
/* This operand names a floating point value */
#define V850_OPERAND_FLOAT_CC	0x20
/* This operand names a vector purpose register.  */
#define V850_OPERAND_VREG	0x40
/* 16 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE16	0x80
/* hi16 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE16HI	0x100
/* 23 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE23	0x200
/* 32 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE32	0x400
/* This is a D9->D22 relaxable operand. */
#define V850_OPERAND_RELAX	0x800
/* This operand takes signed values.  */
#define V850_OPERAND_SIGNED	0x1000
/* This operand is a displacement.  */
#define V850_OPERAND_DISP	0x2000
/* This operand is a PC displacement.  */
#define V850_PCREL		0x4000
/* The register specified must be even number.  */
#define V850_REG_EVEN		0x8000
/* The register specified must not be r0.  */
#define V850_NOT_R0	        0x20000
/* The register specified must not be 0.  */
#define V850_NOT_IMM0	        0x40000
/* The condition code must not be SA CONDITION.  */
#define V850_NOT_SA		0x80000
/* The operand has '!' prefix.  */
#define V850_OPERAND_BANG	0x100000
/* The operand has '%' prefix.  */
#define V850_OPERAND_PERCENT	0x200000
/* This operand is a cache operation.  */
#define V850_OPERAND_CACHEOP	0x400000
/* This operand is a prefetch operation.  */
#define V850_OPERAND_PREFOP	0x800000
/* A PC-relative displacement where a positive value indicates a backwards displacement.  */
#define V850_INVERSE_PCREL	0x1000000

int v850np_disasm(v850np_inst *inst, int cpumodel, ut64 addr, const ut8* buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* V850_H */
