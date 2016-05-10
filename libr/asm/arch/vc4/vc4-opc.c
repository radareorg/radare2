/* Instruction opcode table for vc4.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#include "sysdep.h"
#include <string.h>
#include "ansidecl.h"
#include "mybfd.h"
#include "symcat.h"
#include "vc4-desc.h"
#include "vc4-opc.h"
#include "libiberty.h"
#include "dis-asm.h"

/* The hash functions are recorded here to help keep assembler code out of
   the disassembler and vice versa.  */

static int asm_hash_insn_p        (const CGEN_INSN *);
static unsigned int asm_hash_insn (const char *);
static int dis_hash_insn_p        (const CGEN_INSN *);
static unsigned int dis_hash_insn (const char *, CGEN_INSN_INT);

/* Instruction formats.  */

#define F(f) & vc4_cgen_ifld_table[VC4_##f]
static const CGEN_IFMT ifmt_empty ATTRIBUTE_UNUSED = {
  0, 0, 0x0, { { 0 } }
};

static const CGEN_IFMT ifmt_bkpt ATTRIBUTE_UNUSED = {
  16, 16, 0xffff, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_5) }, { F (F_OP4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_swireg ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_swiimm ATTRIBUTE_UNUSED = {
  16, 16, 0xffc0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_6) }, { F (F_OP5_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_pushrn ATTRIBUTE_UNUSED = {
  16, 16, 0xff9f, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_pushrnrm0 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_pushrnrm6 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_6) }, { 0 } }
};

static const CGEN_IFMT ifmt_pushrnrm16 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_pushrnrm24 ATTRIBUTE_UNUSED = {
  16, 16, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_24) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldind ATTRIBUTE_UNUSED = {
  16, 16, 0xf900, { { F (F_OPLEN) }, { F (F_OP11) }, { F (F_OP10_9) }, { F (F_OP8) }, { F (F_OP7_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldoff ATTRIBUTE_UNUSED = {
  16, 16, 0xf000, { { F (F_OPLEN) }, { F (F_LDSTOFF) }, { F (F_OP7_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldoff12 ATTRIBUTE_UNUSED = {
  16, 32, 0xfe20, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_9) }, { F (F_OFFSET12) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldoff16 ATTRIBUTE_UNUSED = {
  16, 32, 0xfc20, { { F (F_OPLEN) }, { F (F_OP31_16S) }, { F (F_OP11_10) }, { F (F_OP9_8) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldcndidx ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_6) }, { F (F_OP22_21) }, { F (F_OP5) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldcnddisp ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_6) }, { F (F_OP22) }, { F (F_OP5) }, { F (F_OP21_16S) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldpredec ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_6) }, { F (F_OP22_21) }, { F (F_OP5) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldsp ATTRIBUTE_UNUSED = {
  16, 16, 0xfe00, { { F (F_OPLEN) }, { F (F_OP11_9) }, { F (F_SPOFFSET) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_addsp ATTRIBUTE_UNUSED = {
  16, 16, 0xf81f, { { F (F_OPLEN) }, { F (F_OP11) }, { F (F_ADDSPOFFSET) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_lea ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OPLEN) }, { F (F_OP11) }, { F (F_ADDSPOFFSET) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc ATTRIBUTE_UNUSED = {
  16, 16, 0xf800, { { F (F_OPLEN) }, { F (F_OP11) }, { F (F_OP10_7) }, { F (F_PCRELCC) }, { 0 } }
};

static const CGEN_IFMT ifmt_mov16 ATTRIBUTE_UNUSED = {
  16, 16, 0xff00, { { F (F_OP15_13) }, { F (F_ALU16OP) }, { F (F_OP7_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_movi16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfe00, { { F (F_OP15_13) }, { F (F_ALU16OPI) }, { F (F_OP8_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds8i16 ATTRIBUTE_UNUSED = {
  16, 16, 0xfe00, { { F (F_OP15_13) }, { F (F_ALU16OPI) }, { F (F_OP8_4_SHL3) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc32r ATTRIBUTE_UNUSED = {
  16, 32, 0xf0f0, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_26) }, { F (F_OP11_8) }, { F (F_PCREL10) }, { F (F_OP7_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc32i ATTRIBUTE_UNUSED = {
  16, 32, 0xf0f0, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_24) }, { F (F_OP11_8) }, { F (F_OP7_4) }, { F (F_PCREL8) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_addcmpbrr ATTRIBUTE_UNUSED = {
  16, 32, 0xf000, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_26) }, { F (F_OP11_8) }, { F (F_PCREL10) }, { F (F_OP7_4) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_addcmpbri ATTRIBUTE_UNUSED = {
  16, 32, 0xf000, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_26) }, { F (F_OP11_8) }, { F (F_PCREL10) }, { F (F_OP7_4S) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_addcmpbir ATTRIBUTE_UNUSED = {
  16, 32, 0xf000, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_24) }, { F (F_OP11_8) }, { F (F_OP7_4) }, { F (F_PCREL8) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_addcmpbii ATTRIBUTE_UNUSED = {
  16, 32, 0xf000, { { F (F_OPLEN) }, { F (F_OP31_30) }, { F (F_OP29_24) }, { F (F_OP11_8) }, { F (F_OP7_4S) }, { F (F_PCREL8) }, { F (F_OP3_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc32 ATTRIBUTE_UNUSED = {
  16, 32, 0xf080, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OFFSET23BITS) }, { 0 } }
};

static const CGEN_IFMT ifmt_bl32 ATTRIBUTE_UNUSED = {
  16, 32, 0xf080, { { F (F_OPLEN) }, { F (F_OP7) }, { F (F_OFFSET27BITS) }, { 0 } }
};

static const CGEN_IFMT ifmt_mov32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22_21) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_movi32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22) }, { F (F_OP21_16S) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds2i32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL1) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds4i32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL2) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds8i32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL3) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds16i32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_10) }, { F (F_OP26_23) }, { F (F_OP9_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL4) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_mulhdrss ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22_21) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_mulhdiss ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_clamp16r ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22_21) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds5i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds6i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL6) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds7i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL7) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds8i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL8) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_subs1i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL1) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_subs2i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL2) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_subs3i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL3) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_subs4i ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_8) }, { F (F_OP26_23) }, { F (F_OP7_5) }, { F (F_OP22) }, { F (F_OP21_16S_SHL4) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_lea32r ATTRIBUTE_UNUSED = {
  16, 32, 0xfc00, { { F (F_OPLEN) }, { F (F_OP31_16S) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_lea32pc ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_PCREL16) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_moviu32 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_16S) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds2iu32_shl1 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_16S_SHL1) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds4iu32_shl2 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_16S_SHL2) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds8iu32_shl3 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_16S_SHL3) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_adds16iu32_shl4 ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_16S_SHL4) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_faddr ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_9) }, { F (F_OP26_23) }, { F (F_OP8_5) }, { F (F_OP22_21) }, { F (F_OP4_0) }, { F (F_OP20_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_faddi ATTRIBUTE_UNUSED = {
  16, 32, 0xffe0, { { F (F_OPLEN) }, { F (F_OP31_27) }, { F (F_OP11_9) }, { F (F_OP26_23) }, { F (F_OP8_5) }, { F (F_OP22) }, { F (F_OP21_16) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_lea48 ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_PCREL32_48) }, { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldpcrel27 ATTRIBUTE_UNUSED = {
  16, 48, 0xff20, { { F (F_OP47_43) }, { F (F_PCREL27_48) }, { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldoff27 ATTRIBUTE_UNUSED = {
  16, 48, 0xff20, { { F (F_OP47_43) }, { F (F_OFFSET27_48) }, { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_add48i ATTRIBUTE_UNUSED = {
  16, 48, 0xfc00, { { F (F_OP47_16) }, { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_movi48 ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OP47_16) }, { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_vec48 ATTRIBUTE_UNUSED = {
  16, 48, 0xf800, { { F (F_OP47_16) }, { F (F_OPLEN) }, { F (F_OP11) }, { F (F_OP10_0) }, { 0 } }
};

static const CGEN_IFMT ifmt_vec80 ATTRIBUTE_UNUSED = {
  16, 80, 0xf800, { { F (F_OP47_16) }, { F (F_OP79_48) }, { F (F_OPLEN) }, { F (F_OP11) }, { F (F_OP10_0) }, { 0 } }
};

#undef F

#define A(a) (1 << CGEN_INSN_##a)
#define OPERAND(op) VC4_OPERAND_##op
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The instruction table.  */

static const CGEN_OPCODE vc4_cgen_insn_opcode_table[MAX_INSNS] =
{
  /* Special null first entry.
     A `num' value of zero is thus invalid.
     Also, the special `invalid' insn resides here.  */
  { { 0, 0, 0, 0 }, {{0}}, 0, {0}},
/* bkpt */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x0 }
  },
/* nop */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x1 }
  },
/* sleep */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x2 }
  },
/* user */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x3 }
  },
/* ei */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x4 }
  },
/* di */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x5 }
  },
/* cbclr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x6 }
  },
/* cbinc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x7 }
  },
/* cbchg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x8 }
  },
/* cbdec */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x9 }
  },
/* rti */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0xa }
  },
/* swi $alu32dreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), 0 } },
    & ifmt_swireg, { 0x20 }
  },
/* rts */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_bkpt, { 0x5a }
  },
/* b $alu32dreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), 0 } },
    & ifmt_swireg, { 0x40 }
  },
/* bl $alu32dreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), 0 } },
    & ifmt_swireg, { 0x60 }
  },
/* tbb $alu32dreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), 0 } },
    & ifmt_swireg, { 0x80 }
  },
/* tbh $alu32dreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), 0 } },
    & ifmt_swireg, { 0xa0 }
  },
/* mov $alu32dreg,cpuid */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), ',', 'c', 'p', 'u', 'i', 'd', 0 } },
    & ifmt_swireg, { 0xe0 }
  },
/* swi $swi_imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (SWI_IMM), 0 } },
    & ifmt_swiimm, { 0x1c0 }
  },
/* push $ppstartreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (PPSTARTREG), 0 } },
    & ifmt_pushrn, { 0x280 }
  },
/* push $ppstartreg,lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (PPSTARTREG), ',', 'l', 'r', 0 } },
    & ifmt_pushrn, { 0x380 }
  },
/* push r0-$ppendreg0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '0', '-', OP (PPENDREG0), 0 } },
    & ifmt_pushrnrm0, { 0x280 }
  },
/* push r6-$ppendreg6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '6', '-', OP (PPENDREG6), 0 } },
    & ifmt_pushrnrm6, { 0x2a0 }
  },
/* push r16-$ppendreg16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '1', '6', '-', OP (PPENDREG16), 0 } },
    & ifmt_pushrnrm16, { 0x2c0 }
  },
/* push r24-$ppendreg24 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '2', '4', '-', OP (PPENDREG24), 0 } },
    & ifmt_pushrnrm24, { 0x2e0 }
  },
/* push r0-$ppendreg0,lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '0', '-', OP (PPENDREG0), ',', 'l', 'r', 0 } },
    & ifmt_pushrnrm0, { 0x380 }
  },
/* push r6-$ppendreg6,lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '6', '-', OP (PPENDREG6), ',', 'l', 'r', 0 } },
    & ifmt_pushrnrm6, { 0x3a0 }
  },
/* push r16-$ppendreg16,lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '1', '6', '-', OP (PPENDREG16), ',', 'l', 'r', 0 } },
    & ifmt_pushrnrm16, { 0x3c0 }
  },
/* push r24-$ppendreg24,lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '2', '4', '-', OP (PPENDREG24), ',', 'l', 'r', 0 } },
    & ifmt_pushrnrm24, { 0x3e0 }
  },
/* pop $ppstartreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (PPSTARTREG), 0 } },
    & ifmt_pushrn, { 0x200 }
  },
/* pop $ppstartreg,pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (PPSTARTREG), ',', 'p', 'c', 0 } },
    & ifmt_pushrn, { 0x300 }
  },
/* pop r0-$ppendreg0 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '0', '-', OP (PPENDREG0), 0 } },
    & ifmt_pushrnrm0, { 0x200 }
  },
/* pop r6-$ppendreg6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '6', '-', OP (PPENDREG6), 0 } },
    & ifmt_pushrnrm6, { 0x220 }
  },
/* pop r16-$ppendreg16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '1', '6', '-', OP (PPENDREG16), 0 } },
    & ifmt_pushrnrm16, { 0x240 }
  },
/* pop r24-$ppendreg24 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '2', '4', '-', OP (PPENDREG24), 0 } },
    & ifmt_pushrnrm24, { 0x260 }
  },
/* pop r0-$ppendreg0,pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '0', '-', OP (PPENDREG0), ',', 'p', 'c', 0 } },
    & ifmt_pushrnrm0, { 0x300 }
  },
/* pop r6-$ppendreg6,pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '6', '-', OP (PPENDREG6), ',', 'p', 'c', 0 } },
    & ifmt_pushrnrm6, { 0x320 }
  },
/* pop r16-$ppendreg16,pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '1', '6', '-', OP (PPENDREG16), ',', 'p', 'c', 0 } },
    & ifmt_pushrnrm16, { 0x340 }
  },
/* pop r24-$ppendreg24,pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'r', '2', '4', '-', OP (PPENDREG24), ',', 'p', 'c', 0 } },
    & ifmt_pushrnrm24, { 0x360 }
  },
/* ld$accsz $alu16dreg,($alu16sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ), ' ', OP (ALU16DREG), ',', '(', OP (ALU16SREG), ')', 0 } },
    & ifmt_ldind, { 0x800 }
  },
/* st$accsz $alu16dreg,($alu16sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ), ' ', OP (ALU16DREG), ',', '(', OP (ALU16SREG), ')', 0 } },
    & ifmt_ldind, { 0x900 }
  },
/* ld $alu16dreg,$ldstoff($alu16sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (LDSTOFF), '(', OP (ALU16SREG), ')', 0 } },
    & ifmt_ldoff, { 0x2000 }
  },
/* st $alu16dreg,$ldstoff($alu16sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (LDSTOFF), '(', OP (ALU16SREG), ')', 0 } },
    & ifmt_ldoff, { 0x3000 }
  },
/* ld$accsz32 $alu32dreg,$offset12($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', OP (OFFSET12), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldoff12, { 0xa200 }
  },
/* st$accsz32 $alu32dreg,$offset12($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', OP (OFFSET12), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldoff12, { 0xa220 }
  },
/* ld$accsz32 $alu32dreg,$offset16($off16basereg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', OP (OFFSET16), '(', OP (OFF16BASEREG), ')', 0 } },
    & ifmt_ldoff16, { 0xa800 }
  },
/* st$accsz32 $alu32dreg,$offset16($off16basereg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', OP (OFFSET16), '(', OP (OFF16BASEREG), ')', 0 } },
    & ifmt_ldoff16, { 0xa820 }
  },
/* ld${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<2) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '2', ')', 0 } },
    & ifmt_ldcndidx, { 0xa000, { 0x0 }, { 0x60 } }
  },
/* ldh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', ')', 0 } },
    & ifmt_ldcndidx, { 0xa040, { 0x0 }, { 0x60 } }
  },
/* ldb${alu32cond} $alu32dreg,($alu32areg,$alu32breg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), ')', 0 } },
    & ifmt_ldcndidx, { 0xa080, { 0x0 }, { 0x60 } }
  },
/* ldsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', ')', 0 } },
    & ifmt_ldcndidx, { 0xa0c0, { 0x0 }, { 0x60 } }
  },
/* st${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<2) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '2', ')', 0 } },
    & ifmt_ldcndidx, { 0xa020, { 0x0 }, { 0x60 } }
  },
/* sth${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', ')', 0 } },
    & ifmt_ldcndidx, { 0xa060, { 0x0 }, { 0x60 } }
  },
/* stb${alu32cond} $alu32dreg,($alu32areg,$alu32breg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), ')', 0 } },
    & ifmt_ldcndidx, { 0xa0a0, { 0x0 }, { 0x60 } }
  },
/* stsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', ')', 0 } },
    & ifmt_ldcndidx, { 0xa0e0, { 0x0 }, { 0x60 } }
  },
/* ld${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa000, { 0x40 }, { 0x40 } }
  },
/* ldh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa040, { 0x40 }, { 0x40 } }
  },
/* ldb${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa080, { 0x40 }, { 0x40 } }
  },
/* ldsh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa0c0, { 0x40 }, { 0x40 } }
  },
/* st${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa020, { 0x40 }, { 0x40 } }
  },
/* sth${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa060, { 0x40 }, { 0x40 } }
  },
/* stb${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa0a0, { 0x40 }, { 0x40 } }
  },
/* stsh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (IMM6), '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldcnddisp, { 0xa0e0, { 0x40 }, { 0x40 } }
  },
/* ld${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa400, { 0x0 }, { 0x7f } }
  },
/* ldh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa440, { 0x0 }, { 0x7f } }
  },
/* ldb${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa480, { 0x0 }, { 0x7f } }
  },
/* ldsh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa4c0, { 0x0 }, { 0x7f } }
  },
/* st${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa420, { 0x0 }, { 0x7f } }
  },
/* sth${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa460, { 0x0 }, { 0x7f } }
  },
/* stb${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa4a0, { 0x0 }, { 0x7f } }
  },
/* stsh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '-', '-', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldpredec, { 0xa4e0, { 0x0 }, { 0x7f } }
  },
/* ld${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa500, { 0x0 }, { 0x7f } }
  },
/* ldh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa540, { 0x0 }, { 0x7f } }
  },
/* ldb${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa580, { 0x0 }, { 0x7f } }
  },
/* ldsh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa5c0, { 0x0 }, { 0x7f } }
  },
/* st${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa520, { 0x0 }, { 0x7f } }
  },
/* sth${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa560, { 0x0 }, { 0x7f } }
  },
/* stb${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa5a0, { 0x0 }, { 0x7f } }
  },
/* stsh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', '+', '+', 0 } },
    & ifmt_ldpredec, { 0xa5e0, { 0x0 }, { 0x7f } }
  },
/* ld $alu16dreg,$spoffset(sp) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (SPOFFSET), '(', 's', 'p', ')', 0 } },
    & ifmt_ldsp, { 0x400 }
  },
/* st $alu16dreg,$spoffset(sp) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (SPOFFSET), '(', 's', 'p', ')', 0 } },
    & ifmt_ldsp, { 0x600 }
  },
/* add sp,#$addspoffset */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 's', 'p', ',', '#', OP (ADDSPOFFSET), 0 } },
    & ifmt_addsp, { 0x1019 }
  },
/* lea $alu32dreg,$addspoffset(sp) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU32DREG), ',', OP (ADDSPOFFSET), '(', 's', 'p', ')', 0 } },
    & ifmt_lea, { 0x1000 }
  },
/* b$condcode $pcrelcc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODE), ' ', OP (PCRELCC), 0 } },
    & ifmt_bcc, { 0x1800 }
  },
/* mov $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4000 }
  },
/* cmn $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4100 }
  },
/* add $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4200 }
  },
/* bic $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4300 }
  },
/* mul $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4400 }
  },
/* eor $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4500 }
  },
/* sub $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4600 }
  },
/* and $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4700 }
  },
/* not $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4800 }
  },
/* ror $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4900 }
  },
/* cmp $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4a00 }
  },
/* rsub $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4b00 }
  },
/* btst $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4c00 }
  },
/* or $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4d00 }
  },
/* bmask $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4e00 }
  },
/* max $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x4f00 }
  },
/* bset $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5000 }
  },
/* min $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5100 }
  },
/* bclr $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5200 }
  },
/* addscale $alu16dreg,$alu16sreg<<1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), '<', '<', '1', 0 } },
    & ifmt_mov16, { 0x5300 }
  },
/* bchg $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5400 }
  },
/* addscale $alu16dreg,$alu16sreg<<2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), '<', '<', '2', 0 } },
    & ifmt_mov16, { 0x5500 }
  },
/* addscale $alu16dreg,$alu16sreg<<3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), '<', '<', '3', 0 } },
    & ifmt_mov16, { 0x5600 }
  },
/* addscale $alu16dreg,$alu16sreg<<4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), '<', '<', '4', 0 } },
    & ifmt_mov16, { 0x5700 }
  },
/* signext $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5800 }
  },
/* neg $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5900 }
  },
/* lsr $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5a00 }
  },
/* msb $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5b00 }
  },
/* shl $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5c00 }
  },
/* bitrev $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5d00 }
  },
/* asr $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5e00 }
  },
/* abs $alu16dreg,$alu16sreg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', OP (ALU16SREG), 0 } },
    & ifmt_mov16, { 0x5f00 }
  },
/* mov $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6000 }
  },
/* add $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6200 }
  },
/* mul $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6400 }
  },
/* sub $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6600 }
  },
/* not $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6800 }
  },
/* cmp $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6a00 }
  },
/* btst $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6c00 }
  },
/* bmask $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x6e00 }
  },
/* bset $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7000 }
  },
/* bclr $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7200 }
  },
/* bchg $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7400 }
  },
/* addscale $alu16dreg,#$alu16imm_shl3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM_SHL3), 0 } },
    & ifmt_adds8i16, { 0x7600 }
  },
/* signext $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7800 }
  },
/* lsr $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7a00 }
  },
/* shl $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7c00 }
  },
/* asr $alu16dreg,#$alu16imm */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU16DREG), ',', '#', OP (ALU16IMM), 0 } },
    & ifmt_movi16, { 0x7e00 }
  },
/* b$condcodebcc32 $alu16dreg,$bcc32sreg,$pcrel10bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', OP (BCC32SREG), ',', OP (PCREL10BITS), 0 } },
    & ifmt_bcc32r, { 0x8000, { 0x4000 }, { 0xc000 } }
  },
/* b$condcodebcc32 $alu16dreg,#$bcc32imm,$pcrel8bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', '#', OP (BCC32IMM), ',', OP (PCREL8BITS), 0 } },
    & ifmt_bcc32i, { 0x8000, { 0xc000 }, { 0xc000 } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,$addcmpbareg,$bcc32sreg,$pcrel10bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', OP (ADDCMPBAREG), ',', OP (BCC32SREG), ',', OP (PCREL10BITS), 0 } },
    & ifmt_addcmpbrr, { 0x8000, { 0x0 }, { 0xc000 } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,#$addcmpbimm,$bcc32sreg,$pcrel10bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', '#', OP (ADDCMPBIMM), ',', OP (BCC32SREG), ',', OP (PCREL10BITS), 0 } },
    & ifmt_addcmpbri, { 0x8000, { 0x4000 }, { 0xc000 } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,$addcmpbareg,#$bcc32imm,$pcrel8bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', OP (ADDCMPBAREG), ',', '#', OP (BCC32IMM), ',', OP (PCREL8BITS), 0 } },
    & ifmt_addcmpbir, { 0x8000, { 0x8000 }, { 0xc000 } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,#$addcmpbimm,#$bcc32imm,$pcrel8bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (ALU16DREG), ',', '#', OP (ADDCMPBIMM), ',', '#', OP (BCC32IMM), ',', OP (PCREL8BITS), 0 } },
    & ifmt_addcmpbii, { 0x8000, { 0xc000 }, { 0xc000 } }
  },
/* b$condcodebcc32 $offset23bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (CONDCODEBCC32), ' ', OP (OFFSET23BITS), 0 } },
    & ifmt_bcc32, { 0x9000 }
  },
/* bl $offset27bits */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (OFFSET27BITS), 0 } },
    & ifmt_bl32, { 0x9080 }
  },
/* mov${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc000, { 0x0 }, { 0x60 } }
  },
/* cmn${alu32cond} $alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc020, { 0x0 }, { 0x60 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc040, { 0x0 }, { 0x60 } }
  },
/* bic${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc060, { 0x0 }, { 0x60 } }
  },
/* mul${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc080, { 0x0 }, { 0x60 } }
  },
/* eor${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc0a0, { 0x0 }, { 0x60 } }
  },
/* sub${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc0c0, { 0x0 }, { 0x60 } }
  },
/* and${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc0e0, { 0x0 }, { 0x60 } }
  },
/* not${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc100, { 0x0 }, { 0x60 } }
  },
/* ror${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc120, { 0x0 }, { 0x60 } }
  },
/* cmp${alu32cond} $alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc140, { 0x0 }, { 0x60 } }
  },
/* rsub${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc160, { 0x0 }, { 0x60 } }
  },
/* btst${alu32cond} $alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc180, { 0x0 }, { 0x60 } }
  },
/* or${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc1a0, { 0x0 }, { 0x60 } }
  },
/* bmask${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc1c0, { 0x0 }, { 0x60 } }
  },
/* max${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc1e0, { 0x0 }, { 0x60 } }
  },
/* bset${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc200, { 0x0 }, { 0x60 } }
  },
/* min${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc220, { 0x0 }, { 0x60 } }
  },
/* bclr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc240, { 0x0 }, { 0x60 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', 0 } },
    & ifmt_mov32, { 0xc260, { 0x0 }, { 0x60 } }
  },
/* bchg${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc280, { 0x0 }, { 0x60 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '2', 0 } },
    & ifmt_mov32, { 0xc2a0, { 0x0 }, { 0x60 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '3', 0 } },
    & ifmt_mov32, { 0xc2c0, { 0x0 }, { 0x60 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '4', 0 } },
    & ifmt_mov32, { 0xc2e0, { 0x0 }, { 0x60 } }
  },
/* signext${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc300, { 0x0 }, { 0x60 } }
  },
/* neg${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc320, { 0x0 }, { 0x60 } }
  },
/* lsr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc340, { 0x0 }, { 0x60 } }
  },
/* msb${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc360, { 0x0 }, { 0x60 } }
  },
/* shl${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc380, { 0x0 }, { 0x60 } }
  },
/* bitrev${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc3a0, { 0x0 }, { 0x60 } }
  },
/* asr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc3c0, { 0x0 }, { 0x60 } }
  },
/* abs${alu32cond} $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mov32, { 0xc3e0, { 0x0 }, { 0x60 } }
  },
/* mov${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc000, { 0x40 }, { 0x40 } }
  },
/* cmn${alu32cond} $alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc020, { 0x40 }, { 0x40 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc040, { 0x40 }, { 0x40 } }
  },
/* bic${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc060, { 0x40 }, { 0x40 } }
  },
/* mul${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc080, { 0x40 }, { 0x40 } }
  },
/* eor${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc0a0, { 0x40 }, { 0x40 } }
  },
/* sub${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc0c0, { 0x40 }, { 0x40 } }
  },
/* and${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc0e0, { 0x40 }, { 0x40 } }
  },
/* not${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc100, { 0x40 }, { 0x40 } }
  },
/* ror${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc120, { 0x40 }, { 0x40 } }
  },
/* cmp${alu32cond} $alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc140, { 0x40 }, { 0x40 } }
  },
/* rsub${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc160, { 0x40 }, { 0x40 } }
  },
/* btst${alu32cond} $alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc180, { 0x40 }, { 0x40 } }
  },
/* or${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc1a0, { 0x40 }, { 0x40 } }
  },
/* bmask${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc1c0, { 0x40 }, { 0x40 } }
  },
/* max${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc1e0, { 0x40 }, { 0x40 } }
  },
/* bset${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc200, { 0x40 }, { 0x40 } }
  },
/* min${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc220, { 0x40 }, { 0x40 } }
  },
/* bclr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc240, { 0x40 }, { 0x40 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL1), 0 } },
    & ifmt_adds2i32, { 0xc260, { 0x40 }, { 0x40 } }
  },
/* bchg${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc280, { 0x40 }, { 0x40 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL2), 0 } },
    & ifmt_adds4i32, { 0xc2a0, { 0x40 }, { 0x40 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL3), 0 } },
    & ifmt_adds8i32, { 0xc2c0, { 0x40 }, { 0x40 } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL4), 0 } },
    & ifmt_adds16i32, { 0xc2e0, { 0x40 }, { 0x40 } }
  },
/* signext${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc300, { 0x40 }, { 0x40 } }
  },
/* neg${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc320, { 0x40 }, { 0x40 } }
  },
/* lsr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc340, { 0x40 }, { 0x40 } }
  },
/* msb${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc360, { 0x40 }, { 0x40 } }
  },
/* shl${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc380, { 0x40 }, { 0x40 } }
  },
/* bitrev${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc3a0, { 0x40 }, { 0x40 } }
  },
/* asr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc3c0, { 0x40 }, { 0x40 } }
  },
/* abs${alu32cond} $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_movi32, { 0xc3e0, { 0x40 }, { 0x40 } }
  },
/* mulhd$alu32cond.ss $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc400, { 0x0 }, { 0x60 } }
  },
/* mulhd$alu32cond.su $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc420, { 0x0 }, { 0x60 } }
  },
/* mulhd$alu32cond.us $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc440, { 0x0 }, { 0x60 } }
  },
/* mulhd$alu32cond.uu $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc460, { 0x0 }, { 0x60 } }
  },
/* div$alu32cond.ss $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc480, { 0x0 }, { 0x60 } }
  },
/* div$alu32cond.su $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc4a0, { 0x0 }, { 0x60 } }
  },
/* div$alu32cond.us $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc4c0, { 0x0 }, { 0x60 } }
  },
/* div$alu32cond.uu $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc4e0, { 0x0 }, { 0x60 } }
  },
/* mulhd$alu32cond.ss $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc400, { 0x40 }, { 0x40 } }
  },
/* mulhd$alu32cond.su $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc420, { 0x40 }, { 0x40 } }
  },
/* mulhd$alu32cond.us $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc440, { 0x40 }, { 0x40 } }
  },
/* mulhd$alu32cond.uu $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc460, { 0x40 }, { 0x40 } }
  },
/* div$alu32cond.ss $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc480, { 0x40 }, { 0x40 } }
  },
/* div$alu32cond.su $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 's', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc4a0, { 0x40 }, { 0x40 } }
  },
/* div$alu32cond.us $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 's', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc4c0, { 0x40 }, { 0x40 } }
  },
/* div$alu32cond.uu $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), '.', 'u', 'u', ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc4e0, { 0x40 }, { 0x40 } }
  },
/* adds$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc500, { 0x0 }, { 0x60 } }
  },
/* subs$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc520, { 0x0 }, { 0x60 } }
  },
/* shls$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xc540, { 0x0 }, { 0x60 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '5', 0 } },
    & ifmt_mulhdrss, { 0xc580, { 0x0 }, { 0x60 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '6', 0 } },
    & ifmt_mulhdrss, { 0xc5a0, { 0x0 }, { 0x60 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '7', 0 } },
    & ifmt_mulhdrss, { 0xc5c0, { 0x0 }, { 0x60 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<8 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '8', 0 } },
    & ifmt_mulhdrss, { 0xc5e0, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '1', 0 } },
    & ifmt_mulhdrss, { 0xc620, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '2', 0 } },
    & ifmt_mulhdrss, { 0xc640, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '3', 0 } },
    & ifmt_mulhdrss, { 0xc660, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '4', 0 } },
    & ifmt_mulhdrss, { 0xc680, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '5', 0 } },
    & ifmt_mulhdrss, { 0xc6a0, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '6', 0 } },
    & ifmt_mulhdrss, { 0xc6c0, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '7', 0 } },
    & ifmt_mulhdrss, { 0xc6e0, { 0x0 }, { 0x60 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<8 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), '<', '<', '8', 0 } },
    & ifmt_mulhdrss, { 0xc700, { 0x0 }, { 0x60 } }
  },
/* clamp16$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_clamp16r, { 0xc560, { 0x0 }, { 0xf860 } }
  },
/* count$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_clamp16r, { 0xc600, { 0x0 }, { 0xf860 } }
  },
/* adds$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc500, { 0x40 }, { 0x40 } }
  },
/* subs$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc520, { 0x40 }, { 0x40 } }
  },
/* shls$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc540, { 0x40 }, { 0x40 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL5), 0 } },
    & ifmt_adds5i, { 0xc580, { 0x40 }, { 0x40 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL6), 0 } },
    & ifmt_adds6i, { 0xc5a0, { 0x40 }, { 0x40 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL7), 0 } },
    & ifmt_adds7i, { 0xc5c0, { 0x40 }, { 0x40 } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl8 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL8), 0 } },
    & ifmt_adds8i, { 0xc5e0, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl1 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL1), 0 } },
    & ifmt_subs1i, { 0xc620, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL2), 0 } },
    & ifmt_subs2i, { 0xc640, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL3), 0 } },
    & ifmt_subs3i, { 0xc660, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL4), 0 } },
    & ifmt_subs4i, { 0xc680, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL5), 0 } },
    & ifmt_adds5i, { 0xc6a0, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL6), 0 } },
    & ifmt_adds6i, { 0xc6c0, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL7), 0 } },
    & ifmt_adds7i, { 0xc6e0, { 0x40 }, { 0x40 } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl8 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (IMM6_SHL8), 0 } },
    & ifmt_adds8i, { 0xc700, { 0x40 }, { 0x40 } }
  },
/* clamp16$alu32cond $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc560, { 0x40 }, { 0x40 } }
  },
/* count$alu32cond $alu32dreg,#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xc600, { 0x40 }, { 0x40 } }
  },
/* lea $alu48idreg,$offset16($alu48isreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', OP (OFFSET16), '(', OP (ALU48ISREG), ')', 0 } },
    & ifmt_lea32r, { 0xb400 }
  },
/* lea $alu48idreg,$pcrel16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', OP (PCREL16), 0 } },
    & ifmt_lea32pc, { 0xbfe0 }
  },
/* mov $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb000 }
  },
/* cmn $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb020 }
  },
/* add $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb040 }
  },
/* bic $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb060 }
  },
/* mul $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb080 }
  },
/* eor $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb0a0 }
  },
/* sub $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb0c0 }
  },
/* and $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb0e0 }
  },
/* not $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb100 }
  },
/* ror $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb120 }
  },
/* cmp $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb140 }
  },
/* rsub $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb160 }
  },
/* btst $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb180 }
  },
/* or $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb1a0 }
  },
/* bmask $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb1c0 }
  },
/* max $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb1e0 }
  },
/* bset $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb200 }
  },
/* min $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb220 }
  },
/* bclr $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb240 }
  },
/* add $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_adds2iu32_shl1, { 0xb260 }
  },
/* bchg $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb280 }
  },
/* add $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_adds4iu32_shl2, { 0xb2a0 }
  },
/* add $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_adds8iu32_shl3, { 0xb2c0 }
  },
/* add $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_adds16iu32_shl4, { 0xb2e0 }
  },
/* signext $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb300 }
  },
/* neg $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb320 }
  },
/* lsr $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb340 }
  },
/* msb $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb360 }
  },
/* shl $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb380 }
  },
/* bitrev $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb3a0 }
  },
/* asr $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb3c0 }
  },
/* abs $alu48idreg,#$offset16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (OFFSET16), 0 } },
    & ifmt_moviu32, { 0xb3e0 }
  },
/* fadd$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc800, { 0x0 }, { 0x60 } }
  },
/* fsub$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc820, { 0x0 }, { 0x60 } }
  },
/* fmul$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc840, { 0x0 }, { 0x60 } }
  },
/* fdiv$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc860, { 0x0 }, { 0x60 } }
  },
/* fcmp$alu32cond $alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc880, { 0x0 }, { 0x60 } }
  },
/* fabs$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc8a0, { 0x0 }, { 0x60 } }
  },
/* frsb$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc8c0, { 0x0 }, { 0x60 } }
  },
/* fmax$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc8e0, { 0x0 }, { 0x60 } }
  },
/* frcp$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc900, { 0x0 }, { 0x60 } }
  },
/* frsqrt$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc920, { 0x0 }, { 0x60 } }
  },
/* fnmul$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc940, { 0x0 }, { 0x60 } }
  },
/* fmin$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc960, { 0x0 }, { 0x60 } }
  },
/* fceil$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc980, { 0x0 }, { 0x60 } }
  },
/* ffloor$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc9a0, { 0x0 }, { 0x60 } }
  },
/* flog2$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc9c0, { 0x0 }, { 0x60 } }
  },
/* fexp2$alu32cond $alu32dreg,$alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32BREG), 0 } },
    & ifmt_faddr, { 0xc9e0, { 0x0 }, { 0x60 } }
  },
/* fadd$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc800, { 0x40 }, { 0x40 } }
  },
/* fsub$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc820, { 0x40 }, { 0x40 } }
  },
/* fmul$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc840, { 0x40 }, { 0x40 } }
  },
/* fdiv$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc860, { 0x40 }, { 0x40 } }
  },
/* fcmp$alu32cond $alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc880, { 0x40 }, { 0x40 } }
  },
/* fabs$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc8a0, { 0x40 }, { 0x40 } }
  },
/* frsb$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc8c0, { 0x40 }, { 0x40 } }
  },
/* fmax$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc8e0, { 0x40 }, { 0x40 } }
  },
/* frcp$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc900, { 0x40 }, { 0x40 } }
  },
/* frsqrt$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc920, { 0x40 }, { 0x40 } }
  },
/* fnmul$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc940, { 0x40 }, { 0x40 } }
  },
/* fmin$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc960, { 0x40 }, { 0x40 } }
  },
/* fceil$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc980, { 0x40 }, { 0x40 } }
  },
/* ffloor$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc9a0, { 0x40 }, { 0x40 } }
  },
/* flog2$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc9c0, { 0x40 }, { 0x40 } }
  },
/* fexp2$alu32cond $alu32dreg,#$floatimm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', '#', OP (FLOATIMM6), 0 } },
    & ifmt_faddi, { 0xc9e0, { 0x40 }, { 0x40 } }
  },
/* ftrunc$alu32cond $alu32dreg,$alu32areg,sasl $alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'l', ' ', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xca00, { 0x0 }, { 0x60 } }
  },
/* floor$alu32cond $alu32dreg,$alu32areg,sasl $alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'l', ' ', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xca20, { 0x0 }, { 0x60 } }
  },
/* flts$alu32cond $alu32dreg,$alu32areg,sasr $alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'r', ' ', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xca40, { 0x0 }, { 0x60 } }
  },
/* fltu$alu32cond $alu32dreg,$alu32areg,sasr $alu32breg */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'r', ' ', OP (ALU32BREG), 0 } },
    & ifmt_mulhdrss, { 0xca60, { 0x0 }, { 0x60 } }
  },
/* ftrunc$alu32cond $alu32dreg,$alu32areg,sasl#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'l', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xca00, { 0x40 }, { 0x40 } }
  },
/* floor$alu32cond $alu32dreg,$alu32areg,sasl#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'l', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xca20, { 0x40 }, { 0x40 } }
  },
/* flts$alu32cond $alu32dreg,$alu32areg,sasr#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'r', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xca40, { 0x40 }, { 0x40 } }
  },
/* fltu$alu32cond $alu32dreg,$alu32areg,sasr#$imm6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ALU32COND), ' ', OP (ALU32DREG), ',', OP (ALU32AREG), ',', 's', 'a', 's', 'r', '#', OP (IMM6), 0 } },
    & ifmt_mulhdiss, { 0xca60, { 0x40 }, { 0x40 } }
  },
/* lea $alu48idreg,$alu48pcrel */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', OP (ALU48PCREL), 0 } },
    & ifmt_lea48, { 0xe500 }
  },
/* ld$accsz32 $alu48idreg,$mem48pcrel27 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU48IDREG), ',', OP (MEM48PCREL27), 0 } },
    & ifmt_ldpcrel27, { 0xe700, { 0x0, 0xf800 }, { 0x0, 0xf800 } }
  },
/* st$accsz32 $alu48idreg,$mem48pcrel27 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU48IDREG), ',', OP (MEM48PCREL27), 0 } },
    & ifmt_ldpcrel27, { 0xe720, { 0x0, 0xf800 }, { 0x0, 0xf800 } }
  },
/* ld$accsz32 $alu48idreg,$mem48offset27($mem48sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU48IDREG), ',', OP (MEM48OFFSET27), '(', OP (MEM48SREG), ')', 0 } },
    & ifmt_ldoff27, { 0xe600 }
  },
/* st$accsz32 $alu48idreg,$mem48offset27($mem48sreg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU48IDREG), ',', OP (MEM48OFFSET27), '(', OP (MEM48SREG), ')', 0 } },
    & ifmt_ldoff27, { 0xe620 }
  },
/* add $alu48idreg,$alu48isreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', OP (ALU48ISREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_add48i, { 0xec00 }
  },
/* mov $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe800 }
  },
/* cmn $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe820 }
  },
/* add $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe840 }
  },
/* bic $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe860 }
  },
/* mul $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe880 }
  },
/* eor $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe8a0 }
  },
/* sub $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe8c0 }
  },
/* and $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe8e0 }
  },
/* cmp $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe940 }
  },
/* rsub $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe960 }
  },
/* or $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe9a0 }
  },
/* max $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xe9e0 }
  },
/* min $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48, { 0xea20 }
  },
/* vec48 $operand10_0,$operand47_16 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (OPERAND10_0), ',', OP (OPERAND47_16), 0 } },
    & ifmt_vec48, { 0xf000 }
  },
/* vec80 $operand10_0,$operand47_16,$operand79_48 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (OPERAND10_0), ',', OP (OPERAND47_16), ',', OP (OPERAND79_48), 0 } },
    & ifmt_vec80, { 0xf800 }
  },
};

#undef A
#undef OPERAND
#undef MNEM
#undef OP

/* Formats for ALIAS macro-insns.  */

#define F(f) & vc4_cgen_ifld_table[VC4_##f]
static const CGEN_IFMT ifmt_pushlr ATTRIBUTE_UNUSED = {
  16, 16, 0xffff, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_24) }, { 0 } }
};

static const CGEN_IFMT ifmt_poppc ATTRIBUTE_UNUSED = {
  16, 16, 0xffff, { { F (F_OPLEN) }, { F (F_OP11_8) }, { F (F_OP7) }, { F (F_OP6_5) }, { F (F_OP4_0_BASE_24) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldoffzero ATTRIBUTE_UNUSED = {
  16, 32, 0xff20, { { F (F_OPLEN) }, { F (F_OP11_9) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { F (F_OP31_27) }, { F (F_OP8) }, { F (F_OP26_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_stoffzero ATTRIBUTE_UNUSED = {
  16, 32, 0xff20, { { F (F_OPLEN) }, { F (F_OP11_9) }, { F (F_OP7_6) }, { F (F_OP5) }, { F (F_OP4_0) }, { F (F_OP31_27) }, { F (F_OP8) }, { F (F_OP26_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_add48i_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xfc00, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_movi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_cmni48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_addi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_bici48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_muli48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_eori48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_subi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_andi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_cmpi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_rsubi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_ori48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_maxi48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

static const CGEN_IFMT ifmt_mini48_norelax ATTRIBUTE_UNUSED = {
  16, 48, 0xffe0, { { F (F_OPLEN) }, { F (F_OP11_10) }, { F (F_OP9_5) }, { F (F_OP4_0) }, { F (F_OP47_16) }, { 0 } }
};

#undef F

/* Each non-simple macro entry points to an array of expansion possibilities.  */

#define A(a) (1 << CGEN_INSN_##a)
#define OPERAND(op) VC4_OPERAND_##op
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The macro instruction table.  */

static const CGEN_IBASE vc4_cgen_macro_insn_table[] =
{
/* push lr */
  {
    -1, "pushlr", "push", 16,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop pc */
  {
    -1, "poppc", "pop", 16,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz32 $alu32dreg,($alu32areg) */
  {
    -1, "ldoffzero", "ld", 32,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz32 $alu32dreg,($alu32areg) */
  {
    -1, "stoffzero", "st", 32,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,$alu48isreg,#$alu48immu */
  {
    -1, "add48i_norelax", "add", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu48idreg,#$alu48immu */
  {
    -1, "movi48_norelax", "mov", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn $alu48idreg,#$alu48immu */
  {
    -1, "cmni48_norelax", "cmn", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$alu48immu */
  {
    -1, "addi48_norelax", "add", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic $alu48idreg,#$alu48immu */
  {
    -1, "bici48_norelax", "bic", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul $alu48idreg,#$alu48immu */
  {
    -1, "muli48_norelax", "mul", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor $alu48idreg,#$alu48immu */
  {
    -1, "eori48_norelax", "eor", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub $alu48idreg,#$alu48immu */
  {
    -1, "subi48_norelax", "sub", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* and $alu48idreg,#$alu48immu */
  {
    -1, "andi48_norelax", "and", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp $alu48idreg,#$alu48immu */
  {
    -1, "cmpi48_norelax", "cmp", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub $alu48idreg,#$alu48immu */
  {
    -1, "rsubi48_norelax", "rsub", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* or $alu48idreg,#$alu48immu */
  {
    -1, "ori48_norelax", "or", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* max $alu48idreg,#$alu48immu */
  {
    -1, "maxi48_norelax", "max", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
/* min $alu48idreg,#$alu48immu */
  {
    -1, "mini48_norelax", "min", 48,
    { 0|A(ALIAS), { { { (1<<MACH_BASE), 0 } } } }
  },
};

/* The macro instruction opcode table.  */

static const CGEN_OPCODE vc4_cgen_macro_insn_opcode_table[] =
{
/* push lr */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'l', 'r', 0 } },
    & ifmt_pushlr, { 0x3ef }
  },
/* pop pc */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', 'p', 'c', 0 } },
    & ifmt_poppc, { 0x36f }
  },
/* ld$accsz32 $alu32dreg,($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_ldoffzero, { 0xa200, { 0x0 }, { 0x7ff } }
  },
/* st$accsz32 $alu32dreg,($alu32areg) */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (ACCSZ32), ' ', OP (ALU32DREG), ',', '(', OP (ALU32AREG), ')', 0 } },
    & ifmt_stoffzero, { 0xa220, { 0x0 }, { 0x7ff } }
  },
/* add $alu48idreg,$alu48isreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', OP (ALU48ISREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_add48i_norelax, { 0xec00 }
  },
/* mov $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_movi48_norelax, { 0xe800 }
  },
/* cmn $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_cmni48_norelax, { 0xe820 }
  },
/* add $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_addi48_norelax, { 0xe840 }
  },
/* bic $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_bici48_norelax, { 0xe860 }
  },
/* mul $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_muli48_norelax, { 0xe880 }
  },
/* eor $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_eori48_norelax, { 0xe8a0 }
  },
/* sub $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_subi48_norelax, { 0xe8c0 }
  },
/* and $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_andi48_norelax, { 0xe8e0 }
  },
/* cmp $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_cmpi48_norelax, { 0xe940 }
  },
/* rsub $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_rsubi48_norelax, { 0xe960 }
  },
/* or $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_ori48_norelax, { 0xe9a0 }
  },
/* max $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_maxi48_norelax, { 0xe9e0 }
  },
/* min $alu48idreg,#$alu48immu */
  {
    { 0, 0, 0, 0 },
    { { MNEM, ' ', OP (ALU48IDREG), ',', '#', OP (ALU48IMMU), 0 } },
    & ifmt_mini48_norelax, { 0xea20 }
  },
};

#undef A
#undef OPERAND
#undef MNEM
#undef OP

#ifndef CGEN_ASM_HASH_P
#define CGEN_ASM_HASH_P(insn) 1
#endif

#ifndef CGEN_DIS_HASH_P
#define CGEN_DIS_HASH_P(insn) 1
#endif

/* Return non-zero if INSN is to be added to the hash table.
   Targets are free to override CGEN_{ASM,DIS}_HASH_P in the .opc file.  */

static int
asm_hash_insn_p (insn)
     const CGEN_INSN *insn ATTRIBUTE_UNUSED;
{
  return CGEN_ASM_HASH_P (insn);
}

static int
dis_hash_insn_p (insn)
     const CGEN_INSN *insn;
{
  /* If building the hash table and the NO-DIS attribute is present,
     ignore.  */
  if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_NO_DIS))
    return 0;
  return CGEN_DIS_HASH_P (insn);
}

#ifndef CGEN_ASM_HASH
#define CGEN_ASM_HASH_SIZE 127
#ifdef CGEN_MNEMONIC_OPERANDS
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE)
#else
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE) /*FIXME*/
#endif
#endif

/* It doesn't make much sense to provide a default here,
   but while this is under development we do.
   BUFFER is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

#ifndef CGEN_DIS_HASH
#define CGEN_DIS_HASH_SIZE 256
#define CGEN_DIS_HASH(buf, value) (*(unsigned char *) (buf))
#endif

/* The result is the hash value of the insn.
   Targets are free to override CGEN_{ASM,DIS}_HASH in the .opc file.  */

static unsigned int
asm_hash_insn (mnem)
     const char * mnem;
{
  return CGEN_ASM_HASH (mnem);
}

/* BUF is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

static unsigned int
dis_hash_insn (buf, value)
     const char * buf ATTRIBUTE_UNUSED;
     CGEN_INSN_INT value ATTRIBUTE_UNUSED;
{
  return CGEN_DIS_HASH (buf, value);
}

/* Set the recorded length of the insn in the CGEN_FIELDS struct.  */

static void
set_fields_bitsize (CGEN_FIELDS *fields, int size)
{
  CGEN_FIELDS_BITSIZE (fields) = size;
}

/* Function to call before using the operand instance table.
   This plugs the opcode entries and macro instructions into the cpu table.  */

void
vc4_cgen_init_opcode_table (CGEN_CPU_DESC cd)
{
  int i;
  int num_macros = (sizeof (vc4_cgen_macro_insn_table) /
		    sizeof (vc4_cgen_macro_insn_table[0]));
  const CGEN_IBASE *ib = & vc4_cgen_macro_insn_table[0];
  const CGEN_OPCODE *oc = & vc4_cgen_macro_insn_opcode_table[0];
  CGEN_INSN *insns = xmalloc (num_macros * sizeof (CGEN_INSN));

  /* This test has been added to avoid a warning generated
     if memset is called with a third argument of value zero.  */
  if (num_macros >= 1)
    memset (insns, 0, num_macros * sizeof (CGEN_INSN));
  for (i = 0; i < num_macros; ++i)
    {
      insns[i].base = &ib[i];
      insns[i].opcode = &oc[i];
      vc4_cgen_build_insn_regex (& insns[i]);
    }
  cd->macro_insn_table.init_entries = insns;
  cd->macro_insn_table.entry_size = sizeof (CGEN_IBASE);
  cd->macro_insn_table.num_init_entries = num_macros;

  oc = & vc4_cgen_insn_opcode_table[0];
  insns = (CGEN_INSN *) cd->insn_table.init_entries;
  for (i = 0; i < MAX_INSNS; ++i)
    {
      insns[i].opcode = &oc[i];
      vc4_cgen_build_insn_regex (& insns[i]);
    }

  cd->sizeof_fields = sizeof (CGEN_FIELDS);
  cd->set_fields_bitsize = set_fields_bitsize;

  cd->asm_hash_p = asm_hash_insn_p;
  cd->asm_hash = asm_hash_insn;
  cd->asm_hash_size = CGEN_ASM_HASH_SIZE;

  cd->dis_hash_p = dis_hash_insn_p;
  cd->dis_hash = dis_hash_insn;
  cd->dis_hash_size = CGEN_DIS_HASH_SIZE;
}
