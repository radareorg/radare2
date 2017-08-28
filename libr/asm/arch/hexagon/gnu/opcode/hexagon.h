

/* Opcode table for the Hexagon.
   Copyright 2004 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler, GDB, the GNU debugger, and
   the GNU Binutils.

   GAS/GDB is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   GAS/GDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS or GDB; see the file COPYING.	If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA
*/

#ifndef OPCODES_HEXAGON_H
#define OPCODES_HEXAGON_H 1

/* List of the various cpu types.
   The tables currently use bit masks to say whether the instruction or
   whatever is supported by a particular cpu.  This lets us have one entry
   apply to several cpus.

   The `base' cpu must be 0. The cpu type is treated independently of
   endianness. The complete `mach' number includes endianness.
   These values are internal to opcodes/bfd/binutils/gas.  */
#define HEXAGON_MACH    0
#define HEXAGON_MACH_V2 2
#define HEXAGON_MACH_V3 3
#define HEXAGON_MACH_V4 4
#define HEXAGON_MACH_V5 5
/* Additional cpu values can be inserted here and HEXAGON_MACH_BIG moved down.  */
#define HEXAGON_MACH_BIG 16

/* Mask of number of bits necessary to record cpu type.  */
#define HEXAGON_MACH_CPU_MASK (HEXAGON_MACH_BIG - 1)
/* Mask of number of bits necessary to record cpu type + endianness.  */
#define HEXAGON_MACH_MASK ((HEXAGON_MACH_BIG << 1) - 1)

/* Qualifier for several table entries. */
#define HEXAGON_IS_V2 (1 << 31)
#define HEXAGON_IS_V3 (1 << 30)
#define HEXAGON_IS_V4 (1 << 29)
#define HEXAGON_IS_V5 (1 << 28)
#define HEXAGON_V2_AND_V3 (HEXAGON_IS_V3 | HEXAGON_IS_V2)
#define HEXAGON_V2_AND_UP (HEXAGON_IS_V5 | HEXAGON_IS_V4 | HEXAGON_IS_V3 | HEXAGON_IS_V2)
#define HEXAGON_V3_AND_UP (HEXAGON_IS_V5 | HEXAGON_IS_V4 | HEXAGON_IS_V3)
#define HEXAGON_V4_AND_UP (HEXAGON_IS_V5 | HEXAGON_IS_V4)

/* This is the instruction size in bytes. */
#define HEXAGON_INSN_LEN (4)

/** Maximum number of insns in a packet.
*/
#define MAX_PACKET_INSNS 4

/* This is the mnemonic length for mapped insns. */
#define HEXAGON_MAPPED_LEN (256)

/* Determine if a number can be represented in 16 bits (unsigned) */
#define HEXAGON_IS16BITS(num) 0	/* not yet implemented */

/* Determine if a number is a 16-bit instruction */
#define HEXAGON_IS16INSN(num) 0	/* not yet implemented */

/* Extract the low 16 bits */
#define HEXAGON_LO16(num) ((num) & ~(-1UL << 16))

/* Extract the high 16 bits */
#define HEXAGON_HI16(num) (HEXAGON_LO16 ((num) >> 16))

/* Extract the extender bits. */
#define HEXAGON_KXER_MASK(num) ((num) & (-1 << 6))

/* Extract the extended bits. */
#define HEXAGON_KXED_MASK(num) ((num) & ~(-1 << 6))

/* Registers. */
#define HEXAGON_NUM_GENERAL_PURPOSE_REGS 32
#define HEXAGON_NUM_CONTROL_REGS         32
#define HEXAGON_NUM_SYS_CTRL_REGS        64
#define HEXAGON_NUM_PREDICATE_REGS       4
#define HEXAGON_NUM_GUEST_REGS           32

/* Specify the register sub-ranges. */
#define HEXAGON_SUBREGS    (16)
#define HEXAGON_SUBREGS_LO  (0)
#define HEXAGON_SUBREGS_HI (16)
#define HEXAGON_SUBREGS_TO(r, p) (((r) < HEXAGON_SUBREGS_HI \
                                 ? (r) \
                                 : (r) - HEXAGON_SUBREGS / 2) \
                                / ((p)? 2: 1))
#define HEXAGON_SUBREGS_FROM(r, p) ((r) * ((p)? 2: 1) < HEXAGON_SUBREGS / 2 \
                                  ? (r) * ((p)? 2: 1) \
                                  : (r) * ((p)? 2: 1) - HEXAGON_SUBREGS / 2 + HEXAGON_SUBREGS_HI)

/** Slots used by some insns.
*/
#define HEXAGON_SLOTS_DUPLEX (0x3) /** < Paired isns. */
#define HEXAGON_SLOTS_STORES (0x2) /** < In-order dual-stores. */
#define HEXAGON_SLOTS_1      (0x2) /** < Slot #1. */
#define HEXAGON_SLOTS_MEM1   (0x1) /** < Preference for single memory access. */

/** Insn type opcode ranges.
*/
#define HEXAGON_INSN_TYPE_A7   (0x70000000) /** A-type. */
#define HEXAGON_INSN_TYPE_X8   (0x80000000) /** X-type. */
#define HEXAGON_INSN_TYPE_A11  (0xb0000000) /** A-type. */
#define HEXAGON_INSN_TYPE_X12  (0xc0000000) /** X-type. */
#define HEXAGON_INSN_TYPE_X13  (0xd0000000) /** X-type. */
#define HEXAGON_INSN_TYPE_X14  (0xe0000000) /** X-type. */
#define HEXAGON_INSN_TYPE_A15  (0xf0000000) /** A-type. */
#define HEXAGON_INSN_TYPE_MASK(i) ((i) & 0xf0000000) /** Insn type mask. */
#define HEXAGON_INSN_TYPE_A(i) ((HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_A7) \
                              || (HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_A11) \
                              || (HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_A15))
#define HEXAGON_INSN_TYPE_X(i) ((HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_X8) \
                              || (HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_X12) \
                              || (HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_X13) \
                              || (HEXAGON_INSN_TYPE_MASK (i) == HEXAGON_INSN_TYPE_X14))

/* Type to denote an Hexagon instruction (at least a 32 bit unsigned int).  */
typedef unsigned int hexagon_insn;

typedef struct _hexagon_opcode
{
  char *syntax;              /* syntax of insn  */
  char *enc;                 /* string representing the encoding */
  int flags;                 /* various flag bits  */

/* Values for `flags'.  */

/* Return CPU number, given flag bits.  */
#define HEXAGON_CODE_CPU(b) ((b) & HEXAGON_MACH_CPU_MASK)
/* Return MACH number, given flag bits.  */
#define HEXAGON_CODE_MACH(b) ((b) & HEXAGON_MACH_MASK)

  /* First opcode flag bit available after machine mask
     (with room for machine/cpu).  */
#define HEXAGON_CODE_FLAG(f) ((f) << 8)

#define HEXAGON_CODE_IS_PREFIX (HEXAGON_CODE_FLAG (0x0001))
#define HEXAGON_CODE_IS_DUPLEX (HEXAGON_CODE_FLAG (0x0002))
#define HEXAGON_CODE_IS_COMPND (HEXAGON_CODE_FLAG (0x0004))
#define HEXAGON_CODE_IS_BRANCH (HEXAGON_CODE_FLAG (0x0008))
#define HEXAGON_CODE_IS_MEMORY (HEXAGON_CODE_FLAG (0x0010))
#define HEXAGON_CODE_IS_LOAD   (HEXAGON_CODE_FLAG (0x0020))
#define HEXAGON_CODE_IS_STORE  (HEXAGON_CODE_FLAG (0x0040))

/* These values are used to optimize assembly and disassembly.  Each insn
   is on a list of related insns (same first letter for assembly, same
   insn code for disassembly).  */

  struct _hexagon_opcode *next_asm;    /* Next instr to try during assembly.  */
  struct _hexagon_opcode *next_dis;    /* Next instr to try during disassembly.  */

/* Macros to create the hash values for the lists.  */
#define HEXAGON_HASH_OPCODE(string) \
  hexagon_hash_opcode (string)
#define HEXAGON_HASH_ICODE(insn) \
  hexagon_hash_icode (insn)

 /* Macros to access `next_asm', `next_dis' so users needn't care about the
    underlying mechanism.  */
#define HEXAGON_CODE_NEXT_ASM(op) ((op)? (op)->next_asm: (op))
#define HEXAGON_CODE_NEXT_DIS(op) ((op)? (op)->next_dis: (op))

  unsigned int slots;          /* Slots onto which the instruction can go */

  unsigned int implicit;   /* specifies implicit register writes */

  /* Values for implicit register definitions */
#define IMPLICIT_LR     0x0001
#define IMPLICIT_SP     0x0002
#define IMPLICIT_FP     0x0004
#define IMPLICIT_PC     0x0008
#define IMPLICIT_LC0    0x0010
#define IMPLICIT_SA0    0x0020
#define IMPLICIT_LC1    0x0040
#define IMPLICIT_SA1    0x0080
#define IMPLICIT_SR_OVF 0x0100
#define IMPLICIT_P3     0x0200
  /* V3 */
#define IMPLICIT_P0     0x0400
  /* V4 */
#define IMPLICIT_P1     0x0800

  unsigned int attributes;

  /* Values for 'attributes' */
#define A_IT_NOP                        0x00000001
#define A_RESTRICT_NOSRMOVE             0x00000002
#define A_RESTRICT_LOOP_LA              0x00000004
#define A_NOTE_LA_RESTRICT              A_RESTRICT_LOOP_LA
#define A_RESTRICT_COF_MAX1             0x00000008
#define A_RESTRICT_NOPACKET             0x00000010
#define A_NOTE_NOPACKET                 A_RESTRICT_NOPACKET
#define A_RESTRICT_NOSLOT1              0x00000020
#define A_NOTE_NOSLOT1                  A_RESTRICT_NOSLOT1
#define A_RESTRICT_NOCOF                0x00000040
#define A_COF                           0x00000080
#define A_RESTRICT_BRANCHADDER_MAX1     0x00000100
#define A_NOTE_BRANCHADDER_MAX1         A_RESTRICT_BRANCHADDER_MAX1
#define A_BRANCHADDER                   0x00000200
#define A_RESTRICT_SINGLE_MEM_FIRST     0x00000400
#define CONDITIONAL_EXEC                0x00000800
#define A_CONDEXEC                      CONDITIONAL_EXEC
#define A_NOTE_CONDITIONAL              CONDITIONAL_EXEC
#define CONDITION_SENSE_INVERTED        0x00001000
#define CONDITION_DOTNEW                0x00002000
#define A_DOTNEW                        CONDITION_DOTNEW
#define A_RESTRICT_PREFERSLOT0          0x00004000
#define A_RESTRICT_LATEPRED             0x00008000
#define A_NOTE_LATEPRED                 A_RESTRICT_LATEPRED
  /* V3 */
#define A_RESTRICT_PACKET_AXOK          0x00010000
#define A_NOTE_AXOK                     A_RESTRICT_PACKET_AXOK
#define A_RESTRICT_PACKET_SOMEREGS_OK   0x00020000
#define A_RELAX_COF_1ST                 0x00040000
#define A_RELAX_COF_2ND                 0x00080000
  /* V4 */
#define PACKED                          0x00100000
#define A_IT_EXTENDER                   0x00200000
#define EXTENDABLE_LOWER_CASE_IMMEDIATE 0x00400000
#define EXTENDABLE_UPPER_CASE_IMMEDIATE 0x00800000
#define A_RESTRICT_SLOT0ONLY            0x01000000
#define A_STORE                         0x02000000
#define A_STOREIMMED                    0x04000000
#define A_RESTRICT_NOSLOT1_STORE        0x08000000
#define MUST_EXTEND                     0x10000000
#define A_MUST_EXTEND                   MUST_EXTEND
#define A_IT_HWLOOP                     0x20000000
#define A_RESTRICT_NOLOOPSETUP          0x40000000
  /* V5 */
  /* Yet unused */
#define A_GUEST                         0x00000000
#define A_NOTE_GUEST                    0x00000000
#define A_EXTENDABLE                    0x00000000
#define A_EXT_LOWER_IMMED               0x00000000
#define A_EXT_UPPER_IMMED               0x00000000
#define A_ARCHV2                        0x00000000
#define A_ARCHV3                        0x00000000
#define A_CRSLOT23                      0x00000000
#define A_NOTE_CRSLOT23                 0x00000000
#define A_MEMSIZE_1B                    0x00000000
#define A_MEMSIZE_2B                    0x00000000
#define A_MEMSIZE_4B                    0x00000000
#define A_MEMSIZE_8B                    0x00000000
#define A_MEMLIKE                       0x00000000
#define A_IMPLICIT_WRITES_SP            0x00000000
#define A_IMPLICIT_READS_SP             0x00000000
#define A_IMPLICIT_READS_LR             0x00000000
#define A_IMPLICIT_WRITES_LR            0x00000000
#define A_IMPLICIT_WRITES_FP            0x00000000
#define A_IMPLICIT_READS_FP             0x00000000
#define A_IMPLICIT_READS_PC             0x00000000
#define A_IMPLICIT_WRITES_PC            0x00000000
#define A_IMPLICIT_READS_GP             0x00000000
#define A_IMPLICIT_READS_CS             0x00000000
#define A_IMPLICIT_READS_P0             0x00000000
#define A_IMPLICIT_WRITES_P0            0x00000000
#define A_IMPLICIT_READS_P1             0x00000000
#define A_IMPLICIT_WRITES_P1            0x00000000
#define A_IMPLICIT_WRITES_P3            0x00000000
#define A_IMPLICIT_WRITES_SRBIT         0x00000000
#define A_IMPLICIT_WRITES_LC0           0x00000000
#define A_IMPLICIT_WRITES_LC1           0x00000000
#define A_IMPLICIT_WRITES_SA0           0x00000000
#define A_IMPLICIT_WRITES_SA1           0x00000000
#define A_JUMP                          0x00000000
#define A_CJUMP                         0x00000000
#define A_NEWCMPJUMP                    0x00000000
#define A_DIRECT                        0x00000000
#define A_INDIRECT                      0x00000000
#define A_CALL                          0x00000000
#define A_ROPS_2                        0x00000000
#define A_ROPS_3                        0x00000000
#define A_MEMOP                         0x00000000
#define A_LOAD                          0x00000000
#define A_NVSTORE                       0x00000000
#define A_DOTOLD                        0x00000000
#define A_COMMUTES                      0x00000000
#define A_PRIV                          0x00000000
#define A_NOTE_PRIV                     0x00000000
#define A_SATURATE                      0x00000000
#define A_USATURATE                     0x00000000
#define A_NOTE_SR_OVF_WHEN_SATURATING   0x00000000
#define A_BIDIRSHIFTL                   0x00000000
#define A_BIDIRSHIFTR                   0x00000000
#define A_NOTE_OOBVSHIFT                0X00000000
#define A_ICOP                          0x00000000
#define A_INTRINSIC_RETURNS_UNSIGNED    0x00000000
#define A_CIRCADDR                      0x00000000
#define A_BREVADDR                      0x00000000
#define A_IT_MPY                        0x00000000
#define A_IT_MPY_32                     0x00000000
#define A_NOTE_SPECIALGROUPING          0x00000000
#define A_NOTE_PACKET_PC                0x00000000
#define A_NOTE_PACKET_NPC               0x00000000
#define A_NOTE_RELATIVE_ADDRESS         0x00000000
#define A_EXCEPTION_SWI                 0x00000000
#define A_NOTE_NEWVAL_SLOT0             0x00000000
#define A_DOTNEWVALUE                   0x00000000
#define A_FPOP                          0x00000000
#define A_FPDOUBLE                      0x00000000
#define A_FPSINGLE                      0x00000000
#define A_RET_TYPE                      0x00000000
#define A_PRED_BIT_4                    0x00000000
#define A_NOTE_COMPAT_ACCURACY          0x00000000
#define A_MPY                           0x00000000
#define A_CACHEOP                       0x00000000
#define A_RESTRICT_SLOT1_AOK            0x00000000
#define A_NOTE_SLOT1_AOK                A_RESTRICT_SLOT1_AOK
#define A_NOTE_DEALLOCRET               0x00000000
#define A_HINTJR                        0x00000000
#define A_PRED_BIT_7                    0x00000000
#define A_PRED_BIT_12                   0x00000000
#define A_PRED_BIT_13                   0x00000000
#define A_NOTE_NVSLOT0                  0x00000000
#define A_NOTE_DEPRECATED               0x00000000
#define A_HWLOOP0_SETUP                 0x00000000
#define A_HWLOOP1_SETUP                 0x00000000
#define A_DOTNEW_LOAD                   0x00000000

  /* If this opcode is mapped, then the function that performs the mapping */
  void *map;
} hexagon_opcode;

typedef size_t hexagon_hash;

typedef struct _hexagon_operand
{
/* Format that will appear in the hexagon_opcode syntax */
  char *fmt;

/* The number of bits in the operand (may be unused for a modifier).  */
  unsigned char bits;

/* The letter that identifies this operand in the hexagon_opcode enc string */
  char enc_letter;

/* For immediate arguments, the value should be shifted right by this amount */
  unsigned int shift_count;

/* The relocation type and that of the extension and itself after extended. */
  bfd_reloc_code_real_type reloc_type, reloc_kxer, reloc_kxed;

/* Various flag bits.  */
  int flags;

/* Values for `flags'.  */
#define HEXAGON_OPERAND_IS_IMMEDIATE 0x00000001
#define HEXAGON_OPERAND_PC_RELATIVE  0x00000002
#define HEXAGON_OPERAND_IS_SIGNED    0x00000004
#define HEXAGON_OPERAND_IS_PAIR      0x00000008
#define HEXAGON_OPERAND_IS_SUBSET    0x00000010
#define HEXAGON_OPERAND_IS_MODIFIER  0x00000020
#define HEXAGON_OPERAND_IS_PREDICATE 0x00000040
#define HEXAGON_OPERAND_IS_CONTROL   0x00000080
#define HEXAGON_OPERAND_IS_SYSTEM    0x00000100
#define HEXAGON_OPERAND_IS_LO16      0x00000200
#define HEXAGON_OPERAND_IS_HI16      0x00000400
#define HEXAGON_OPERAND_IS_READ      0x00000800
#define HEXAGON_OPERAND_IS_WRITE     0x00001000
#define HEXAGON_OPERAND_IS_MODIFIED  0x00002000
#define HEXAGON_OPERAND_IS_NEGATIVE  0x00004000
#define HEXAGON_OPERAND_IS_CONSTANT  0x00008000
#define HEXAGON_OPERAND_IS_NEW       0x00010000
#define HEXAGON_OPERAND_IS_GUEST     0x00020000
#define HEXAGON_OPERAND_IS_REGISTER  0x00040000
#define HEXAGON_OPERAND_IS_RNEW      0x00080000

#define HEXAGON_OPERAND_IS_RELAX     0x10000000
#define HEXAGON_OPERAND_IS_KXER      0x20000000
#define HEXAGON_OPERAND_IS_KXED      0x40000000
#define HEXAGON_OPERAND_IS_INVALID   0x80000000

/* Format string and alternate format string for disassembly. */
  char *dis_fmt, *alt_fmt;

/* Function used to change the original insn into another semantically equivalent. */
  char *(*parse) (const struct _hexagon_operand *, hexagon_insn *,
                  const hexagon_opcode *, char *, long *, int *, char **);
} hexagon_operand;

typedef struct hexagon_operand_arg
{
  const hexagon_operand *operand;
  long value;
  char string [HEXAGON_MAPPED_LEN];
} hexagon_operand_arg;

typedef void (*hexagon_mapping) (char *, size_t, const hexagon_operand_arg []);

typedef struct hexagon_reg
{
  const char *name;
  int reg_num;
  int flags;

  /* Values for flags. */
#define HEXAGON_REG_IS_READONLY  (1 << 0)
#define HEXAGON_REG_IS_WRITEONLY (1 << 1)
#define HEXAGON_REG_IS_READWRITE (1 << 2)
} hexagon_reg;

typedef struct hexagon_reg_score
{
  char used, letter;
#define HEXAGON_PRED_LEN (3)
#define HEXAGON_PRED_MSK (~(-1 << HEXAGON_PRED_LEN))
#define HEXAGON_PRED_YES (0x01)
#define HEXAGON_PRED_NOT (0x02)
#define HEXAGON_PRED_NEW (0x04)
#define HEXAGON_PRED_GET(P, I) (((P) >> ((I) * HEXAGON_PRED_LEN)) & HEXAGON_PRED_MSK)
#define HEXAGON_PRED_SET(P, I, N) \
  ((HEXAGON_PRED_GET (P, I) | ((N) & HEXAGON_PRED_MSK)) << ((I) * HEXAGON_PRED_LEN))
  long pred: (HEXAGON_NUM_PREDICATE_REGS * HEXAGON_PRED_LEN);
  size_t ndx;
} hexagon_reg_score;

/* Bits that say what version of cpu we have. These should be passed to
   hexagon_init_opcode_tables. At present, all there is is the cpu type.  */

/* CPU number, given value passed to `hexagon_init_opcode_tables'.  */
#define HEXAGON_HAVE_CPU(bits) ((bits) & HEXAGON_MACH_CPU_MASK)
/* MACH number, given value passed to `hexagon_init_opcode_tables'.  */
#define HEXAGON_HAVE_MACH(bits) ((bits) & HEXAGON_MACH_MASK)

extern const hexagon_operand hexagon_operands [];
extern const size_t hexagon_operand_count;
extern hexagon_opcode *hexagon_opcodes;
extern size_t hexagon_opcodes_count;
extern int hexagon_verify_hw;
extern hexagon_insn hexagon_nop, hexagon_kext;

/** Packet delimeters.
*/
#define PACKET_BEGIN     '{'         /** < Beginning of packet. */
#define PACKET_END       '}'         /** < End of packet. */
#define PACKET_END_INNER ":endloop0" /** < End of inner loop. */
#define PACKET_END_OUTER ":endloop1" /** < End of outer loop. */
#define PACKET_PAIR      ';'         /** < Sub-insn separator. */

/** Bits 15:14 in the instruction mark boundaries.
*/
#define HEXAGON_END_PACKET_POS  (14)
#define HEXAGON_END_PACKET_MASK (3 << HEXAGON_END_PACKET_POS)
#define HEXAGON_END_PACKET      (3 << HEXAGON_END_PACKET_POS) /** < End of packet. */
#define HEXAGON_END_LOOP        (2 << HEXAGON_END_PACKET_POS) /** < End of loop. */
#define HEXAGON_END_NOT         (1 << HEXAGON_END_PACKET_POS) /** < Neither. */
#define HEXAGON_END_PAIR        (0 << HEXAGON_END_PACKET_POS) /** < Compound insn. */

/** Get, set and reset packet bits in insn.
*/
#define HEXAGON_END_PACKET_GET(insn) \
  ((insn) & HEXAGON_END_PACKET_MASK)                          /** < Get */
#define HEXAGON_END_PACKET_SET(insn, bits) \
  (((insn) & ~HEXAGON_END_PACKET_MASK) | (bits))              /** < Set */
#define HEXAGON_END_PACKET_RESET(insn) \
  (HEXAGON_END_PACKET_SET ((insn), \
                         HEXAGON_END_PACKET_GET (insn) == HEXAGON_END_PAIR \
                         ? HEXAGON_END_PAIR: HEXAGON_END_NOT)) /** < Reset */

/** Test for arch version.
*/
#define hexagon_if_arch_v1() (FALSE)                         /** < V1 (Obsolete) */
#define hexagon_if_arch_v2() (hexagon_if_arch (HEXAGON_MACH_V2)) /** < V2 */
#define hexagon_if_arch_v3() (hexagon_if_arch (HEXAGON_MACH_V3)) /** < V3 */
#define hexagon_if_arch_v4() (hexagon_if_arch (HEXAGON_MACH_V4)) /** < V4 */
#define hexagon_if_arch_v5() (hexagon_if_arch (HEXAGON_MACH_V5)) /** < V5 */

extern int hexagon_arch (void);
extern int hexagon_if_arch (int);
extern int hexagon_if_arch_kext (void);
extern int hexagon_if_arch_pairs (void);
extern int hexagon_if_arch_autoand (void);
extern int hexagon_get_opcode_mach (int, int);
extern hexagon_hash hexagon_hash_opcode (const char *);
extern hexagon_hash hexagon_hash_icode (hexagon_insn);
extern hexagon_insn hexagon_encode_opcode (const char *);
extern hexagon_insn hexagon_encode_mask (char *);
/* `hexagon_opcode_init_tables' must be called before `hexagon_xxx_supported'.  */
extern void hexagon_opcode_init_tables (int);
extern const hexagon_opcode *hexagon_opcode_next_asm (const hexagon_opcode *);
extern const hexagon_opcode *hexagon_opcode_lookup_asm (const char *);
extern const hexagon_opcode *hexagon_opcode_lookup_dis (hexagon_insn);
extern const hexagon_opcode *hexagon_lookup_insn (hexagon_insn);
extern int hexagon_opcode_supported (const hexagon_opcode *);
extern int hexagon_encode_operand
  (const hexagon_operand *, hexagon_insn *, const hexagon_opcode *,
   long, long *, int, int, char **);
extern const hexagon_operand *hexagon_lookup_operand (const char *);
extern const hexagon_operand *hexagon_lookup_reloc
  (bfd_reloc_code_real_type, int, const hexagon_opcode *);
extern int hexagon_extract_operand
  (const hexagon_operand *, hexagon_insn, bfd_vma, char *, int *, char **);
extern int hexagon_extract_predicate_operand
  (const hexagon_operand *, hexagon_insn, char *, int *, char **);
extern int hexagon_extract_modifier_operand
  (const hexagon_operand *, hexagon_insn, char *, int *, char **);
extern char *hexagon_dis_operand
  (const hexagon_operand *, hexagon_insn, bfd_vma, bfd_vma, char *, char *, char **);
extern int hexagon_dis_opcode
  (char *, hexagon_insn, bfd_vma, const hexagon_opcode *, char **);
extern const hexagon_operand *hexagon_operand_find_lo16 (const hexagon_operand *);
extern const hexagon_operand *hexagon_operand_find_hi16 (const hexagon_operand *);
extern const hexagon_operand *hexagon_operand_find
  (const hexagon_operand *, const char *);

/* We don't put the packet header in the opcode table */
extern const hexagon_opcode hexagon_packet_header_opcode;

#endif /* OPCODES_HEXAGON_H */
