/* tic30.h -- Header file for TI TMS320C30 opcode table
   Copyright (C) 1998-2025 Free Software Foundation, Inc.
   Contributed by Steven Haworth (steve@pm.cse.rmit.edu.au)

   This file is part of GDB, GAS, and the GNU binutils.

   GDB, GAS, and the GNU binutils are free software; you can redistribute
   them and/or modify them under the terms of the GNU General Public
   License as published by the Free Software Foundation; either version 3,
   or (at your option) any later version.

   GDB, GAS, and the GNU binutils are distributed in the hope that they
   will be useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
   the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING3.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* FIXME: The opcode table should be in opcodes/tic30-opc.c, not in a
   header file.  */

#ifndef _TMS320_H_
#define _TMS320_H_

struct _register
{
  const char *name;
  unsigned char opcode;
  unsigned char regtype;
};

typedef struct _register reg;

#define REG_Rn    0x01
#define REG_ARn   0x02
#define REG_DP    0x03
#define REG_OTHER 0x04

static const reg tic30_regtab[] = {
  { "r0", 0x00, REG_Rn },
  { "r1", 0x01, REG_Rn },
  { "r2", 0x02, REG_Rn },
  { "r3", 0x03, REG_Rn },
  { "r4", 0x04, REG_Rn },
  { "r5", 0x05, REG_Rn },
  { "r6", 0x06, REG_Rn },
  { "r7", 0x07, REG_Rn },
  { "ar0",0x08, REG_ARn },
  { "ar1",0x09, REG_ARn },
  { "ar2",0x0A, REG_ARn },
  { "ar3",0x0B, REG_ARn },
  { "ar4",0x0C, REG_ARn },
  { "ar5",0x0D, REG_ARn },
  { "ar6",0x0E, REG_ARn },
  { "ar7",0x0F, REG_ARn },
  { "dp", 0x10, REG_DP },
  { "ir0",0x11, REG_OTHER },
  { "ir1",0x12, REG_OTHER },
  { "bk", 0x13, REG_OTHER },
  { "sp", 0x14, REG_OTHER },
  { "st", 0x15, REG_OTHER },
  { "ie", 0x16, REG_OTHER },
  { "if", 0x17, REG_OTHER },
  { "iof",0x18, REG_OTHER },
  { "rs", 0x19, REG_OTHER },
  { "re", 0x1A, REG_OTHER },
  { "rc", 0x1B, REG_OTHER },
  { "R0", 0x00, REG_Rn },
  { "R1", 0x01, REG_Rn },
  { "R2", 0x02, REG_Rn },
  { "R3", 0x03, REG_Rn },
  { "R4", 0x04, REG_Rn },
  { "R5", 0x05, REG_Rn },
  { "R6", 0x06, REG_Rn },
  { "R7", 0x07, REG_Rn },
  { "AR0",0x08, REG_ARn },
  { "AR1",0x09, REG_ARn },
  { "AR2",0x0A, REG_ARn },
  { "AR3",0x0B, REG_ARn },
  { "AR4",0x0C, REG_ARn },
  { "AR5",0x0D, REG_ARn },
  { "AR6",0x0E, REG_ARn },
  { "AR7",0x0F, REG_ARn },
  { "DP", 0x10, REG_DP },
  { "IR0",0x11, REG_OTHER },
  { "IR1",0x12, REG_OTHER },
  { "BK", 0x13, REG_OTHER },
  { "SP", 0x14, REG_OTHER },
  { "ST", 0x15, REG_OTHER },
  { "IE", 0x16, REG_OTHER },
  { "IF", 0x17, REG_OTHER },
  { "IOF",0x18, REG_OTHER },
  { "RS", 0x19, REG_OTHER },
  { "RE", 0x1A, REG_OTHER },
  { "RC", 0x1B, REG_OTHER },
  { "",   0, 0 }
};

static const reg *const tic30_regtab_end
  = tic30_regtab + sizeof(tic30_regtab)/sizeof(tic30_regtab[0]);

/* Indirect Addressing Modes Modification Fields */
/* Indirect Addressing with Displacement */
#define PreDisp_Add        0x00
#define PreDisp_Sub        0x01
#define PreDisp_Add_Mod    0x02
#define PreDisp_Sub_Mod    0x03
#define PostDisp_Add_Mod   0x04
#define PostDisp_Sub_Mod   0x05
#define PostDisp_Add_Circ  0x06
#define PostDisp_Sub_Circ  0x07
/* Indirect Addressing with Index Register IR0 */
#define PreIR0_Add         0x08
#define PreIR0_Sub         0x09
#define PreIR0_Add_Mod     0x0A
#define PreIR0_Sub_Mod     0x0B
#define PostIR0_Add_Mod    0x0C
#define PostIR0_Sub_Mod    0x0D
#define PostIR0_Add_Circ   0x0E
#define PostIR0_Sub_Circ   0x0F
/* Indirect Addressing with Index Register IR1 */
#define PreIR1_Add         0x10
#define PreIR1_Sub         0x11
#define PreIR1_Add_Mod     0x12
#define PreIR1_Sub_Mod     0x13
#define PostIR1_Add_Mod    0x14
#define PostIR1_Sub_Mod    0x15
#define PostIR1_Add_Circ   0x16
#define PostIR1_Sub_Circ   0x17
/* Indirect Addressing (Special Cases) */
#define IndirectOnly       0x18
#define PostIR0_Add_BitRev 0x19

typedef struct {
  const char *syntax;
  unsigned char modfield;
  unsigned char displacement;
} ind_addr_type;

#define IMPLIED_DISP  0x01
#define DISP_REQUIRED 0x02
#define NO_DISP       0x03

static const ind_addr_type tic30_indaddr_tab[] = {
  { "*+ar",       PreDisp_Add,        IMPLIED_DISP },
  { "*-ar",       PreDisp_Sub,        IMPLIED_DISP },
  { "*++ar",      PreDisp_Add_Mod,    IMPLIED_DISP },
  { "*--ar",      PreDisp_Sub_Mod,    IMPLIED_DISP },
  { "*ar++",      PostDisp_Add_Mod,   IMPLIED_DISP },
  { "*ar--",      PostDisp_Sub_Mod,   IMPLIED_DISP },
  { "*ar++%",     PostDisp_Add_Circ,  IMPLIED_DISP },
  { "*ar--%",     PostDisp_Sub_Circ,  IMPLIED_DISP },
  { "*+ar()",     PreDisp_Add,        DISP_REQUIRED },
  { "*-ar()",     PreDisp_Sub,        DISP_REQUIRED },
  { "*++ar()",    PreDisp_Add_Mod,    DISP_REQUIRED },
  { "*--ar()",    PreDisp_Sub_Mod,    DISP_REQUIRED },
  { "*ar++()",    PostDisp_Add_Mod,   DISP_REQUIRED },
  { "*ar--()",    PostDisp_Sub_Mod,   DISP_REQUIRED },
  { "*ar++()%",   PostDisp_Add_Circ,  DISP_REQUIRED },
  { "*ar--()%",   PostDisp_Sub_Circ,  DISP_REQUIRED },
  { "*+ar(ir0)",  PreIR0_Add,         NO_DISP },
  { "*-ar(ir0)",  PreIR0_Sub,         NO_DISP },
  { "*++ar(ir0)", PreIR0_Add_Mod,     NO_DISP },
  { "*--ar(ir0)", PreIR0_Sub_Mod,     NO_DISP },
  { "*ar++(ir0)", PostIR0_Add_Mod,    NO_DISP },
  { "*ar--(ir0)", PostIR0_Sub_Mod,    NO_DISP },
  { "*ar++(ir0)%",PostIR0_Add_Circ,   NO_DISP },
  { "*ar--(ir0)%",PostIR0_Sub_Circ,   NO_DISP },
  { "*+ar(ir1)",  PreIR1_Add,         NO_DISP },
  { "*-ar(ir1)",  PreIR1_Sub,         NO_DISP },
  { "*++ar(ir1)", PreIR1_Add_Mod,     NO_DISP },
  { "*--ar(ir1)", PreIR1_Sub_Mod,     NO_DISP },
  { "*ar++(ir1)", PostIR1_Add_Mod,    NO_DISP },
  { "*ar--(ir1)", PostIR1_Sub_Mod,    NO_DISP },
  { "*ar++(ir1)%",PostIR1_Add_Circ,   NO_DISP },
  { "*ar--(ir1)%",PostIR1_Sub_Circ,   NO_DISP },
  { "*ar",        IndirectOnly,       NO_DISP },
  { "*ar++(ir0)b",PostIR0_Add_BitRev, NO_DISP },
  { "",           0,0 }
};

static const ind_addr_type *const tic30_indaddrtab_end
  = tic30_indaddr_tab + sizeof(tic30_indaddr_tab)/sizeof(tic30_indaddr_tab[0]);

/* Possible operand types */
/* Register types */
#define Rn       0x0001
#define ARn      0x0002
#define DPReg    0x0004
#define OtherReg 0x0008
/* Addressing mode types */
#define Direct   0x0010
#define Indirect 0x0020
#define Imm16    0x0040
#define Disp     0x0080
#define Imm24    0x0100
#define Abs24    0x0200
/* 3 operand addressing mode types */
#define op3T1    0x0400
#define op3T2    0x0800
/* Interrupt vector */
#define IVector  0x1000
/* Not required */
#define NotReq   0x2000

#define GAddr1   Rn | Direct | Indirect | Imm16
#define GAddr2   GAddr1 | AllReg
#define TAddr1   op3T1 | Rn | Indirect
#define TAddr2   op3T2 | Rn | Indirect
#define Reg      Rn | ARn
#define AllReg   Reg | DPReg | OtherReg

typedef struct _template
{
  const char *name;
  unsigned int operands; /* how many operands */
  unsigned int base_opcode; /* base_opcode is the fundamental opcode byte */
  /* the bits in opcode_modifier are used to generate the final opcode from
     the base_opcode.  These bits also are used to detect alternate forms of
     the same instruction */
  unsigned int opcode_modifier;

  /* opcode_modifier bits: */
#define AddressMode 0x00600000
#define PCRel       0x02000000
#define StackOp     0x001F0000
#define Rotate      StackOp
  
  /* operand_types[i] describes the type of operand i.  This is made
     by OR'ing together all of the possible type masks.  (e.g.
     'operand_types[i] = Reg|Imm' specifies that operand i can be
     either a register or an immediate operand */
  unsigned int operand_types[3];
  /* This defines the number type of an immediate argument to an instruction. */
  int imm_arg_type;
#define Imm_None  0
#define Imm_Float 1
#define Imm_SInt  2
#define Imm_UInt  3
}
insn_template;

static const insn_template tic30_optab[] = {
  { "absf"   ,2,0x00000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "absi"   ,2,0x00800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "addc"   ,2,0x01000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "addc3"  ,3,0x20000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "addf"   ,2,0x01800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "addf3"  ,3,0x20800000,AddressMode, { TAddr1, TAddr2, Rn }, Imm_None },
  { "addi"   ,2,0x02000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "addi3"  ,3,0x21000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "and"    ,2,0x02800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "and3"   ,3,0x21800000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "andn"   ,2,0x03000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "andn3"  ,3,0x22000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "ash"    ,2,0x03800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ash3"   ,3,0x22800000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "b"      ,1,0x68000000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bu"     ,1,0x68000000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blo"    ,1,0x68010000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bls"    ,1,0x68020000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bhi"    ,1,0x68030000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bhs"    ,1,0x68040000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "beq"    ,1,0x68050000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bne"    ,1,0x68060000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blt"    ,1,0x68070000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "ble"    ,1,0x68080000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bgt"    ,1,0x68090000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bge"    ,1,0x680A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bz"     ,1,0x68050000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnz"    ,1,0x68060000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bp"     ,1,0x68090000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bn"     ,1,0x68070000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnn"    ,1,0x680A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnv"    ,1,0x680C0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bv"     ,1,0x680D0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnuf"   ,1,0x680E0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "buf"    ,1,0x680F0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnc"    ,1,0x68040000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bc"     ,1,0x68010000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnlv"   ,1,0x68100000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blv"    ,1,0x68110000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnluf"  ,1,0x68120000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bluf"   ,1,0x68130000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bzuf"   ,1,0x68140000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bd"     ,1,0x68200000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bud"    ,1,0x68200000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blod"   ,1,0x68210000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blsd"   ,1,0x68220000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bhid"   ,1,0x68230000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bhsd"   ,1,0x68240000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "beqd"   ,1,0x68250000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bned"   ,1,0x68260000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bltd"   ,1,0x68270000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bled"   ,1,0x68280000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bgtd"   ,1,0x68290000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bged"   ,1,0x682A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bzd"    ,1,0x68250000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnzd"   ,1,0x68260000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bpd"    ,1,0x68290000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnd"    ,1,0x68270000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnnd"   ,1,0x682A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnvd"   ,1,0x682C0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bvd"    ,1,0x682D0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnufd"  ,1,0x682E0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bufd"   ,1,0x682F0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bncd"   ,1,0x68240000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bcd"    ,1,0x68210000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnlvd"  ,1,0x68300000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blvd"   ,1,0x68310000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bnlufd" ,1,0x68320000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "blufd"  ,1,0x68330000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "bzufd"  ,1,0x68340000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_None },
  { "br"     ,1,0x60000000,0,           { Imm24, 0, 0 }, Imm_UInt },
  { "brd"    ,1,0x61000000,0,           { Imm24, 0, 0 }, Imm_UInt },
  { "call"   ,1,0x62000000,0,           { Imm24, 0, 0 }, Imm_UInt },
  { "callu"  ,1,0x70000000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calllo" ,1,0x70010000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callls" ,1,0x70020000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callhi" ,1,0x70030000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callhs" ,1,0x70040000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calleq" ,1,0x70050000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callne" ,1,0x70060000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calllt" ,1,0x70070000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callle" ,1,0x70080000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callgt" ,1,0x70090000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callge" ,1,0x700A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callz"  ,1,0x70050000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnz" ,1,0x70060000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callp"  ,1,0x70090000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calln"  ,1,0x70070000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnn" ,1,0x700A0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnv" ,1,0x700C0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callv"  ,1,0x700D0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnuf",1,0x700E0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calluf" ,1,0x700F0000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnc" ,1,0x70040000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callc"  ,1,0x70010000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnlv",1,0x70100000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "calllv" ,1,0x70110000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callnluf",1,0x70120000,PCRel,      { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callluf",1,0x70130000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "callzuf",1,0x70140000,PCRel,       { AllReg|Disp, 0, 0 }, Imm_UInt },
  { "cmpf"   ,2,0x04000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "cmpf3"  ,2,0x23000000,AddressMode, { TAddr1, TAddr2, 0 }, Imm_None },
  { "cmpi"   ,2,0x04800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "cmpi3"  ,2,0x23800000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, 0 }, Imm_None },
  { "db"     ,2,0x6C000000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbu"    ,2,0x6C000000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblo"   ,2,0x6C010000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbls"   ,2,0x6C020000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbhi"   ,2,0x6C030000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbhs"   ,2,0x6C040000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbeq"   ,2,0x6C050000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbne"   ,2,0x6C060000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblt"   ,2,0x6C070000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dble"   ,2,0x6C080000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbgt"   ,2,0x6C090000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbge"   ,2,0x6C0A0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbz"    ,2,0x6C050000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnz"   ,2,0x6C060000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbp"    ,2,0x6C090000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbn"    ,2,0x6C070000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnn"   ,2,0x6C0A0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnv"   ,2,0x6C0C0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbv"    ,2,0x6C0D0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnuf"  ,2,0x6C0E0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbuf"   ,2,0x6C0F0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnc"   ,2,0x6C040000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbc"    ,2,0x6C010000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnlv"  ,2,0x6C100000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblv"   ,2,0x6C110000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnluf" ,2,0x6C120000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbluf"  ,2,0x6C130000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbzuf"  ,2,0x6C140000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbd"    ,2,0x6C200000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbud"   ,2,0x6C200000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblod"  ,2,0x6C210000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblsd"  ,2,0x6C220000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbhid"  ,2,0x6C230000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbhsd"  ,2,0x6C240000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbeqd"  ,2,0x6C250000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbned"  ,2,0x6C260000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbltd"  ,2,0x6C270000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbled"  ,2,0x6C280000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbgtd"  ,2,0x6C290000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbged"  ,2,0x6C2A0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbzd"   ,2,0x6C250000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnzd"  ,2,0x6C260000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbpd"   ,2,0x6C290000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnd"   ,2,0x6C270000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnnd"  ,2,0x6C2A0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnvd"  ,2,0x6C2C0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbvd"   ,2,0x6C2D0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnufd" ,2,0x6C2E0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbufd"  ,2,0x6C2F0000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbncd"  ,2,0x6C240000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbcd"   ,2,0x6C210000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnlvd" ,2,0x6C300000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblvd"  ,2,0x6C310000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbnlufd",2,0x6C320000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dblufd" ,2,0x6C330000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "dbzufd" ,2,0x6C340000,PCRel,       { ARn, AllReg|Disp, 0 }, Imm_None },
  { "fix"    ,2,0x05000000,AddressMode, { GAddr1, AllReg, 0 }, Imm_Float },
  { "float"  ,2,0x05800000,AddressMode, { GAddr2, Rn, 0 }, Imm_SInt },
  { "iack"   ,1,0x1B000000,AddressMode, { Direct|Indirect, 0, 0 }, Imm_None },
  { "idle"   ,0,0x06000000,0,           { 0, 0, 0 }, Imm_None },
  { "idle2"  ,0,0x06000001,0,           { 0, 0, 0 }, Imm_None }, /* LC31 Only */
  { "lde"    ,2,0x06800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldf"    ,2,0x07000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfu"   ,2,0x40000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldflo"  ,2,0x40800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfls"  ,2,0x41000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfhi"  ,2,0x41800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfhs"  ,2,0x42000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfeq"  ,2,0x42800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfne"  ,2,0x43000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldflt"  ,2,0x43800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfle"  ,2,0x44000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfgt"  ,2,0x44800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfge"  ,2,0x45000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfz"   ,2,0x42800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnz"  ,2,0x43000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfp"   ,2,0x44800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfn"   ,2,0x43800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnn"  ,2,0x45000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnv"  ,2,0x46000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfv"   ,2,0x46800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnuf" ,2,0x47000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfuf"  ,2,0x47800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnc"  ,2,0x42000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfc"   ,2,0x40800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnlv" ,2,0x48000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldflv"  ,2,0x48800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfnluf",2,0x49000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfluf" ,2,0x49800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfzuf" ,2,0x4A000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldfi"   ,2,0x07800000,AddressMode, { Direct|Indirect, Rn, 0 }, Imm_None },
  { "ldi"    ,2,0x08000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldiu"   ,2,0x50000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldilo"  ,2,0x50800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldils"  ,2,0x51000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldihi"  ,2,0x51800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldihs"  ,2,0x52000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldieq"  ,2,0x52800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldine"  ,2,0x53000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldilt"  ,2,0x53800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldile"  ,2,0x54000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldigt"  ,2,0x54800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldige"  ,2,0x55000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldiz"   ,2,0x52800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinz"  ,2,0x53000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldip"   ,2,0x54800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldin"   ,2,0x53800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinn"  ,2,0x55000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinv"  ,2,0x56000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldiv"   ,2,0x56800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinuf" ,2,0x57000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldiuf"  ,2,0x57800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinc"  ,2,0x52000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldic"   ,2,0x50800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinlv" ,2,0x58000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldilv"  ,2,0x58800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldinluf",2,0x59000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldiluf" ,2,0x59800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldizuf" ,2,0x5A000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "ldii"   ,2,0x08800000,AddressMode, { Direct|Indirect, AllReg, 0 }, Imm_None },
  { "ldm"    ,2,0x09000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "ldp"    ,2,0x08700000,0,           { Abs24|Direct, DPReg|NotReq, 0 }, Imm_UInt },
  { "lopower",0,0x10800001,0,           { 0, 0, 0 }, Imm_None }, /* LC31 Only */
  { "lsh"    ,2,0x09800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "lsh3"   ,3,0x24000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "maxspeed",0,0x10800000,0,          { 0, 0, 0 }, Imm_None }, /* LC31 Only */
  { "mpyf"   ,2,0x0A000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "mpyf3"  ,3,0x24800000,AddressMode, { TAddr1, TAddr2, Rn }, Imm_None },
  { "mpyi"   ,2,0x0A800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "mpyi3"  ,3,0x25000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "negb"   ,2,0x0B000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "negf"   ,2,0x0B800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "negi"   ,2,0x0C000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "nop"    ,1,0x0C800000,AddressMode, { AllReg|Indirect|NotReq, 0, 0 }, Imm_None },
  { "norm"   ,2,0x0D000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float }, /*Check another source*/
  { "not"    ,2,0x0D800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "or"     ,2,0x10000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "or3"    ,3,0x25800000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "pop"    ,1,0x0E200000,StackOp,     { AllReg, 0, 0 }, Imm_None },
  { "popf"   ,1,0x0EA00000,StackOp,     { Rn, 0, 0 }, Imm_None },
  { "push"   ,1,0x0F200000,StackOp,     { AllReg, 0, 0 }, Imm_None },
  { "pushf"  ,1,0x0FA00000,StackOp,     { Rn, 0, 0 }, Imm_None },
  { "reti"   ,0,0x78000000,0,           { 0, 0, 0 }, Imm_None },
  { "retiu"  ,0,0x78000000,0,           { 0, 0, 0 }, Imm_None },
  { "retilo" ,0,0x78010000,0,           { 0, 0, 0 }, Imm_None },
  { "retils" ,0,0x78020000,0,           { 0, 0, 0 }, Imm_None },
  { "retihi" ,0,0x78030000,0,           { 0, 0, 0 }, Imm_None },
  { "retihs" ,0,0x78040000,0,           { 0, 0, 0 }, Imm_None },
  { "retieq" ,0,0x78050000,0,           { 0, 0, 0 }, Imm_None },
  { "retine" ,0,0x78060000,0,           { 0, 0, 0 }, Imm_None },
  { "retilt" ,0,0x78070000,0,           { 0, 0, 0 }, Imm_None },
  { "retile" ,0,0x78080000,0,           { 0, 0, 0 }, Imm_None },
  { "retigt" ,0,0x78090000,0,           { 0, 0, 0 }, Imm_None },
  { "retige" ,0,0x780A0000,0,           { 0, 0, 0 }, Imm_None },
  { "retiz"  ,0,0x78050000,0,           { 0, 0, 0 }, Imm_None },
  { "retinz" ,0,0x78060000,0,           { 0, 0, 0 }, Imm_None },
  { "retip"  ,0,0x78090000,0,           { 0, 0, 0 }, Imm_None },
  { "retin"  ,0,0x78070000,0,           { 0, 0, 0 }, Imm_None },
  { "retinn" ,0,0x780A0000,0,           { 0, 0, 0 }, Imm_None },
  { "retinv" ,0,0x780C0000,0,           { 0, 0, 0 }, Imm_None },
  { "retiv"  ,0,0x780D0000,0,           { 0, 0, 0 }, Imm_None },
  { "retinuf",0,0x780E0000,0,           { 0, 0, 0 }, Imm_None },
  { "retiuf" ,0,0x780F0000,0,           { 0, 0, 0 }, Imm_None },
  { "retinc" ,0,0x78040000,0,           { 0, 0, 0 }, Imm_None },
  { "retic"  ,0,0x78010000,0,           { 0, 0, 0 }, Imm_None },
  { "retinlv",0,0x78100000,0,           { 0, 0, 0 }, Imm_None },
  { "retilv" ,0,0x78110000,0,           { 0, 0, 0 }, Imm_None },
  { "retinluf",0,0x78120000,0,          { 0, 0, 0 }, Imm_None },
  { "retiluf",0,0x78130000,0,           { 0, 0, 0 }, Imm_None },
  { "retizuf",0,0x78140000,0,           { 0, 0, 0 }, Imm_None },
  { "rets"   ,0,0x78800000,0,           { 0, 0, 0 }, Imm_None },
  { "retsu"  ,0,0x78800000,0,           { 0, 0, 0 }, Imm_None },
  { "retslo" ,0,0x78810000,0,           { 0, 0, 0 }, Imm_None },
  { "retsls" ,0,0x78820000,0,           { 0, 0, 0 }, Imm_None },
  { "retshi" ,0,0x78830000,0,           { 0, 0, 0 }, Imm_None },
  { "retshs" ,0,0x78840000,0,           { 0, 0, 0 }, Imm_None },
  { "retseq" ,0,0x78850000,0,           { 0, 0, 0 }, Imm_None },
  { "retsne" ,0,0x78860000,0,           { 0, 0, 0 }, Imm_None },
  { "retslt" ,0,0x78870000,0,           { 0, 0, 0 }, Imm_None },
  { "retsle" ,0,0x78880000,0,           { 0, 0, 0 }, Imm_None },
  { "retsgt" ,0,0x78890000,0,           { 0, 0, 0 }, Imm_None },
  { "retsge" ,0,0x788A0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsz"  ,0,0x78850000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnz" ,0,0x78860000,0,           { 0, 0, 0 }, Imm_None },
  { "retsp"  ,0,0x78890000,0,           { 0, 0, 0 }, Imm_None },
  { "retsn"  ,0,0x78870000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnn" ,0,0x788A0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnv" ,0,0x788C0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsv"  ,0,0x788D0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnuf",0,0x788E0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsuf" ,0,0x788F0000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnc" ,0,0x78840000,0,           { 0, 0, 0 }, Imm_None },
  { "retsc"  ,0,0x78810000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnlv",0,0x78900000,0,           { 0, 0, 0 }, Imm_None },
  { "retslv" ,0,0x78910000,0,           { 0, 0, 0 }, Imm_None },
  { "retsnluf",0,0x78920000,0,          { 0, 0, 0 }, Imm_None },
  { "retsluf",0,0x78930000,0,           { 0, 0, 0 }, Imm_None },
  { "retszuf",0,0x78940000,0,           { 0, 0, 0 }, Imm_None },
  { "rnd"    ,2,0x11000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "rol"    ,1,0x11E00001,Rotate,      { AllReg, 0, 0 }, Imm_None },
  { "rolc"   ,1,0x12600001,Rotate,      { AllReg, 0, 0 }, Imm_None },
  { "ror"    ,1,0x12E0FFFF,Rotate,      { AllReg, 0, 0 }, Imm_None },
  { "rorc"   ,1,0x1360FFFF,Rotate,      { AllReg, 0, 0 }, Imm_None },
  { "rptb"   ,1,0x64000000,0,           { Imm24, 0, 0 }, Imm_UInt },
  { "rpts"   ,1,0x139B0000,AddressMode, { GAddr2, 0, 0 }, Imm_UInt },
  { "sigi"   ,0,0x16000000,0,           { 0, 0, 0 }, Imm_None },
  { "stf"    ,2,0x14000000,AddressMode, { Rn, Direct|Indirect, 0 }, Imm_Float },
  { "stfi"   ,2,0x14800000,AddressMode, { Rn, Direct|Indirect, 0 }, Imm_Float },
  { "sti"    ,2,0x15000000,AddressMode, { AllReg, Direct|Indirect, 0 }, Imm_SInt },
  { "stii"   ,2,0x15800000,AddressMode, { AllReg, Direct|Indirect, 0 }, Imm_SInt },
  { "subb"   ,2,0x16800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "subb3"  ,3,0x26000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "subc"   ,2,0x17000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "subf"   ,2,0x17800000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "subf3"  ,3,0x26800000,AddressMode, { TAddr1, TAddr2, Rn }, Imm_None },
  { "subi"   ,2,0x18000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "subi3"  ,3,0x27000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { "subrb"  ,2,0x18800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "subrf"  ,2,0x19000000,AddressMode, { GAddr1, Rn, 0 }, Imm_Float },
  { "subri"  ,2,0x19800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_SInt },
  { "swi"    ,0,0x66000000,0,           { 0, 0, 0 }, Imm_None },
  { "trap"   ,1,0x74800020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapu"  ,1,0x74800020,0,           { IVector, 0, 0 }, Imm_None },
  { "traplo" ,1,0x74810020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapls" ,1,0x74820020,0,           { IVector, 0, 0 }, Imm_None },
  { "traphi" ,1,0x74830020,0,           { IVector, 0, 0 }, Imm_None },
  { "traphs" ,1,0x74840020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapeq" ,1,0x74850020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapne" ,1,0x74860020,0,           { IVector, 0, 0 }, Imm_None },
  { "traplt" ,1,0x74870020,0,           { IVector, 0, 0 }, Imm_None },
  { "traple" ,1,0x74880020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapgt" ,1,0x74890020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapge" ,1,0x748A0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapz"  ,1,0x74850020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnz" ,1,0x74860020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapp"  ,1,0x74890020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapn"  ,1,0x74870020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnn" ,1,0x748A0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnv" ,1,0x748C0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapv"  ,1,0x748D0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnuf",1,0x748E0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapuf" ,1,0x748F0020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnc" ,1,0x74840020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapc"  ,1,0x74810020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnlv",1,0x74900020,0,           { IVector, 0, 0 }, Imm_None },
  { "traplv" ,1,0x74910020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapnluf",1,0x74920020,0,          { IVector, 0, 0 }, Imm_None },
  { "trapluf",1,0x74930020,0,           { IVector, 0, 0 }, Imm_None },
  { "trapzuf",1,0x74940020,0,           { IVector, 0, 0 }, Imm_None },
  { "tstb"   ,2,0x1A000000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "tstb3"  ,2,0x27800000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, 0 }, Imm_None },
  { "xor"    ,2,0x1A800000,AddressMode, { GAddr2, AllReg, 0 }, Imm_UInt },
  { "xor3"   ,3,0x28000000,AddressMode, { TAddr1|AllReg, TAddr2|AllReg, AllReg }, Imm_None },
  { ""       ,0,0x00000000,0,           { 0, 0, 0 }, 0 }
};

static const insn_template *const tic30_optab_end =
  tic30_optab + sizeof(tic30_optab)/sizeof(tic30_optab[0]);

typedef struct {
  const char *name;
  unsigned int operands_1;
  unsigned int operands_2;
  unsigned int base_opcode;
  unsigned int operand_types[2][3];
  /* Which operand fits into which part of the final opcode word. */
  int oporder;
} partemplate;

/* oporder defines - not very descriptive. */
#define OO_4op1   0
#define OO_4op2   1
#define OO_4op3   2
#define OO_5op1   3
#define OO_5op2   4
#define OO_PField 5

static const partemplate tic30_paroptab[] = {
  { "q_absf_stf",   2,2,0xC8000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_absi_sti",   2,2,0xCA000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_addf3_stf",  3,2,0xCC000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_addi3_sti",  3,2,0xCE000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_and3_sti",   3,2,0xD0000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_ash3_sti",   3,2,0xD2000000, { { Rn, Indirect, Rn }, { Rn, Indirect, 0 } },
	OO_5op2 },
  { "q_fix_sti",    2,2,0xD4000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_float_stf",  2,2,0xD6000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_ldf_ldf",    2,2,0xC4000000, { { Indirect, Rn, 0 }, { Indirect, Rn, 0 } },
	OO_4op2 },
  { "q_ldf_stf",    2,2,0xD8000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_ldi_ldi",    2,2,0xC6000000, { { Indirect, Rn, 0 }, { Indirect, Rn, 0 } },
	OO_4op2 },
  { "q_ldi_sti",    2,2,0xDA000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_lsh3_sti",   3,2,0xDC000000, { { Rn, Indirect, Rn }, { Rn, Indirect, 0 } },
	OO_5op2 },
  { "q_mpyf3_addf3",3,3,0x80000000, { { Rn | Indirect, Rn | Indirect, Rn },
 	                              { Rn | Indirect, Rn | Indirect, Rn } }, OO_PField },
  { "q_mpyf3_stf",  3,2,0xDE000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_mpyf3_subf3",3,3,0x84000000, { { Rn | Indirect, Rn | Indirect, Rn },
	                              { Rn | Indirect, Rn | Indirect, Rn } }, OO_PField },
  { "q_mpyi3_addi3",3,3,0x88000000, { { Rn | Indirect, Rn | Indirect, Rn },
	                              { Rn | Indirect, Rn | Indirect, Rn } }, OO_PField },
  { "q_mpyi3_sti",  3,2,0xE0000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_mpyi3_subi3",3,3,0x8C000000, { { Rn | Indirect, Rn | Indirect, Rn },
	                              { Rn | Indirect, Rn | Indirect, Rn } }, OO_PField },
  { "q_negf_stf",   2,2,0xE2000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_negi_sti",   2,2,0xE4000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_not_sti",    2,2,0xE6000000, { { Indirect, Rn, 0 }, { Rn, Indirect, 0 } },
	OO_4op1 },
  { "q_or3_sti",    3,2,0xE8000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "q_stf_stf",    2,2,0xC0000000, { { Rn, Indirect, 0 }, { Rn, Indirect, 0 } },
	OO_4op3 },
  { "q_sti_sti",    2,2,0xC2000000, { { Rn, Indirect, 0 }, { Rn, Indirect, 0 } },
	OO_4op3 },
  { "q_subf3_stf",  3,2,0xEA000000, { { Rn, Indirect, Rn }, { Rn, Indirect, 0 } },
	OO_5op2 },
  { "q_subi3_sti",  3,2,0xEC000000, { { Rn, Indirect, Rn }, { Rn, Indirect, 0 } },
	OO_5op2 },
  { "q_xor3_sti",   3,2,0xEE000000, { { Indirect, Rn, Rn }, { Rn, Indirect, 0 } },
	OO_5op1 },
  { "",             0,0,0x00000000, { { 0, 0, 0 }, { 0, 0, 0 } }, 0 }
};

static const partemplate *const tic30_paroptab_end =
  tic30_paroptab + sizeof(tic30_paroptab)/sizeof(tic30_paroptab[0]);

#endif
