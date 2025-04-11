/* Table of opcodes for the Texas Instruments TMS320C[34]X family.

   Copyright (C) 2002-2025 Free Software Foundation, Inc.
  
   Contributed by Michael P. Hayes (m.hayes@elec.canterbury.ac.nz)
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#define IS_CPU_TIC3X(v) ((v) == 30 || (v) == 31 || (v) == 32 || (v) == 33)
#define IS_CPU_TIC4X(v) ((v) ==  0 || (v) == 40 || (v) == 44)

/* Define some bitfield extraction/insertion macros.  */
#define EXTRU(inst, m, l) \
  (((inst) >> (l)) & ((2u << ((m) - (l))) - 1))
#define EXTRS(inst, m, l) \
  ((int) ((EXTRU (inst, m, l) ^ (1u << ((m) - (l)))) - (1u << ((m) - (l)))))
#define INSERTU(inst, val, m, l) \
  ((inst) |= ((val) & ((2u << ((m) - (l))) - 1)) << (l))
#define INSERTS INSERTU

/* Define register numbers.  */
typedef enum
  {
    REG_R0, REG_R1, REG_R2, REG_R3,
    REG_R4, REG_R5, REG_R6, REG_R7,
    REG_AR0, REG_AR1, REG_AR2, REG_AR3,
    REG_AR4, REG_AR5, REG_AR6, REG_AR7,
    REG_DP, REG_IR0, REG_IR1, REG_BK,
    REG_SP, REG_ST, REG_DIE, REG_IIE,
    REG_IIF, REG_RS, REG_RE, REG_RC,
    REG_R8, REG_R9, REG_R10, REG_R11,
    REG_IVTP, REG_TVTP
  }
c4x_reg_t;

/* Note that the actual register numbers for IVTP is 0 and TVTP is 1.  */

#define REG_IE REG_DIE		/* C3x only */
#define REG_IF REG_IIE		/* C3x only */
#define REG_IOF REG_IIF		/* C3x only */

#define TIC3X_REG_MAX REG_RC
#define TIC4X_REG_MAX REG_TVTP

/* Register table size including C4x expansion regs.  */
#define REG_TABLE_SIZE (TIC4X_REG_MAX + 1)

struct tic4x_register
{
  const char *  name;
  unsigned long regno;
};

typedef struct tic4x_register tic4x_register_t;

/* We could store register synonyms here.  */
static const tic4x_register_t tic3x_registers[] =
{
  {"f0",  REG_R0},
  {"r0",  REG_R0},
  {"f1",  REG_R1},
  {"r1",  REG_R1},
  {"f2",  REG_R2},
  {"r2",  REG_R2},
  {"f3",  REG_R3},
  {"r3",  REG_R3},
  {"f4",  REG_R4},
  {"r4",  REG_R4},
  {"f5",  REG_R5},
  {"r5",  REG_R5},
  {"f6",  REG_R6},
  {"r6",  REG_R6},
  {"f7",  REG_R7},
  {"r7",  REG_R7},
  {"ar0", REG_AR0},
  {"ar1", REG_AR1},
  {"ar2", REG_AR2},
  {"ar3", REG_AR3},
  {"ar4", REG_AR4},
  {"ar5", REG_AR5},
  {"ar6", REG_AR6},
  {"ar7", REG_AR7},
  {"dp",  REG_DP},
  {"ir0", REG_IR0},
  {"ir1", REG_IR1},
  {"bk",  REG_BK},
  {"sp",  REG_SP},
  {"st",  REG_ST},
  {"ie",  REG_IE},
  {"if",  REG_IF},
  {"iof", REG_IOF},
  {"rs",  REG_RS},
  {"re",  REG_RE},
  {"rc",  REG_RC},
  {"", 0}
};

const unsigned int tic3x_num_registers = (((sizeof tic3x_registers) / (sizeof tic3x_registers[0])) - 1);

/* Define C4x registers in addition to C3x registers.  */
static const tic4x_register_t tic4x_registers[] =
{
  {"die", REG_DIE},		/* Clobbers C3x REG_IE */
  {"iie", REG_IIE},		/* Clobbers C3x REG_IF */
  {"iif", REG_IIF},		/* Clobbers C3x REG_IOF */
  {"f8",  REG_R8},
  {"r8",  REG_R8},
  {"f9",  REG_R9},
  {"r9",  REG_R9},
  {"f10", REG_R10},
  {"r10", REG_R10},
  {"f11", REG_R11},
  {"r11", REG_R11},
  {"ivtp", REG_IVTP},
  {"tvtp", REG_TVTP},
  {"", 0}
};

const unsigned int tic4x_num_registers = (((sizeof tic4x_registers) / (sizeof tic4x_registers[0])) - 1);

struct tic4x_cond
{
  const char *  name;
  unsigned long cond;
};

typedef struct tic4x_cond tic4x_cond_t;

/* Define conditional branch/load suffixes.  Put desired form for
   disassembler last.  */
static const tic4x_cond_t tic4x_conds[] =
{
  { "u",    0x00 },
  { "c",    0x01 }, { "lo",  0x01 },
  { "ls",   0x02 },
  { "hi",   0x03 },
  { "nc",   0x04 }, { "hs",  0x04 },
  { "z",    0x05 }, { "eq",  0x05 },
  { "nz",   0x06 }, { "ne",  0x06 },
  { "n",    0x07 }, { "l",   0x07 }, { "lt",  0x07 },
  { "le",   0x08 },
  { "p",    0x09 }, { "gt",  0x09 },
  { "nn",   0x0a }, { "ge",  0x0a },
  { "nv",   0x0c },
  { "v",    0x0d },
  { "nuf",  0x0e },
  { "uf",   0x0f },
  { "nlv",  0x10 },
  { "lv",   0x11 },
  { "nluf", 0x12 },
  { "luf",  0x13 },
  { "zuf",  0x14 },
  /* Dummy entry, not included in num_conds.  This
     lets code examine entry i+1 without checking
     if we've run off the end of the table.  */
  { "",      0x0}
};

const unsigned int tic4x_num_conds = (((sizeof tic4x_conds) / (sizeof tic4x_conds[0])) - 1);

struct tic4x_indirect
{
  const char *  name;
  unsigned long modn;
};

typedef struct tic4x_indirect tic4x_indirect_t;

/* Define indirect addressing modes where:
   d displacement (signed)
   y ir0
   z ir1  */

static const tic4x_indirect_t tic4x_indirects[] =
{
  { "*+a(d)",   0x00 },
  { "*-a(d)",   0x01 },
  { "*++a(d)",  0x02 },
  { "*--a(d)",  0x03 },
  { "*a++(d)",  0x04 },
  { "*a--(d)",  0x05 },
  { "*a++(d)%", 0x06 },
  { "*a--(d)%", 0x07 },
  { "*+a(y)",   0x08 },
  { "*-a(y)",   0x09 },
  { "*++a(y)",  0x0a },
  { "*--a(y)",  0x0b },
  { "*a++(y)",  0x0c },
  { "*a--(y)",  0x0d },
  { "*a++(y)%", 0x0e },
  { "*a--(y)%", 0x0f },
  { "*+a(z)",   0x10 },
  { "*-a(z)",   0x11 },
  { "*++a(z)",  0x12 },
  { "*--a(z)",  0x13 },
  { "*a++(z)",  0x14 },
  { "*a--(z)",  0x15 },
  { "*a++(z)%", 0x16 },
  { "*a--(z)%", 0x17 },
  { "*a",       0x18 },
  { "*a++(y)b", 0x19 },
  /* Dummy entry, not included in num_indirects.  This
     lets code examine entry i+1 without checking
     if we've run off the end of the table.  */
  { "",      0x0}
};

#define TIC3X_MODN_MAX 0x19

const unsigned int tic4x_num_indirects = (((sizeof tic4x_indirects) / (sizeof tic4x_indirects[0])) - 1);

/* Instruction template.  */
struct tic4x_inst
{
  const char *  name;
  unsigned long opcode;
  unsigned long opmask;
  const char *        args;
  unsigned long oplevel;
};

typedef struct tic4x_inst tic4x_inst_t;

/* Opcode infix
   B  condition              16--20   U,C,Z,LO,HI, etc.
   C  condition              23--27   U,C,Z,LO,HI, etc.

   Arguments
   ,  required arg follows
   ;  optional arg follows

   Argument types             bits    [classes] - example
   -----------------------------------------------------------
   *  indirect (all)          0--15   [A,AB,AU,AF,A2,A3,A6,A7,AY,B,BA,BB,BI,B6,B7] - *+AR0(5), *++AR0(IR0)
   #  direct (for LDP)        0--15   [Z] - @start, start
   @  direct                  0--15   [A,AB,AU,AF,A3,A6,A7,AY,B,BA,BB,BI,B6,B7] - @start, start
   A  address register       22--24   [D] - AR0, AR7
   B  unsigned integer        0--23   [I,I2] - @start, start  (absolute on C3x, relative on C4x)
   C  indirect (disp - C4x)   0--7    [S,SC,S2,T,TC,T2,T2C] - *+AR0(5)
   E  register (all)          0--7    [T,TC,T2,T2C] - R0, R7, R11, AR0, DP
   e  register (0-11)         0--7    [S,SC,S2] - R0, R7, R11
   F  short float immediate   0--15   [AF,B,BA,BB] - 3.5, 0e-3.5e-1
   G  register (all)          8--15   [T,TC,T2,T2C] - R0, R7, R11, AR0, DP
   g  register (0-11)         0--7    [S,SC,S2] - R0, R7, R11
   H  register (0-7)         18--16   [LS,M,P,Q] - R0, R7
   I  indirect (no disp)      0--7    [S,SC,S2,T,TC,T2,T2C] - *+AR0(1), *+AR0(IR0)
   i  indirect (enhanced)     0--7    [LL,LS,M,P,Q,QC] - *+AR0(1), R5
   J  indirect (no disp)      8--15   [LL,LS,P,Q,QC,S,SC,S2,T,TC,T2,T2C] - *+AR0(1), *+AR0(IR0)
   j  indirect (enhanced)     8--15   [M] - *+AR0(1), R5
   K  register               19--21   [LL,M,Q,QC] - R0, R7
   L  register               22--24   [LL,LS,P,Q,QC] - R0, R7
   M  register (R2,R3)       22--22   [M] R2, R3
   N  register (R0,R1)       23--23   [M] R0, R1
   O  indirect(disp - C4x)    8--15   [S,SC,S2,T,TC,T2] - *+AR0(5)
   P  displacement (PC Rel)   0--15   [D,J,JS] - @start, start
   Q  register (all)          0--15   [A,AB,AU,A2,A3,AY,BA,BI,D,I2,J,JS] - R0, AR0, DP, SP
   q  register (0-11)         0--15   [AF,B,BB] - R0, R7, R11
   R  register (all)         16--20   [A,AB,AU,AF,A6,A7,R,T,TC] - R0, AR0, DP, SP
   r  register (0-11)        16--20   [B,BA,BB,BI,B6,B7,RF,S,SC] - R0, R1, R11
   S  short int immediate     0--15   [A,AB,AY,BI] - -5, 5
   T  integer (C4x)          16--20   [Z] - -5, 12
   U  unsigned integer        0--15   [AU,A3] - 0, 65535
   V  vector (C4x: 0--8)      0--4    [Z] - 25, 7
   W  short int (C4x)         0--7    [T,TC,T2,T2C] - -3, 5
   X  expansion reg (C4x)     0--4    [Z] - IVTP, TVTP
   Y  address reg (C4x)      16--20   [Z] - AR0, DP, SP, IR0
   Z  expansion reg (C4x)    16--20   [Z] - IVTP, TVTP
*/

#define TIC4X_OPERANDS_MAX 7	/* Max number of operands for an inst.  */
#define TIC4X_NAME_MAX 16	/* Max number of chars in parallel name.  */

/* Define the instruction level */
#define OP_C3X   0x1   /* C30 support - supported by all */
#define OP_C4X   0x2   /* C40 support - C40, C44 */
#define OP_ENH   0x4   /* Class LL,LS,M,P,Q,QC enhancements. Argument type
                          I and J is enhanced in these classes - C31>=6.0,
                          C32>=2.0, C33 */
#define OP_LPWR  0x8   /* Low power support (LOPOWER, MAXSPEED) - C30>=7.0,
                          LC31, C31>=5.0, C32 */
#define OP_IDLE2 0x10  /* Idle2 support (IDLE2) - C30>=7.0, LC31, C31>=5.0,
                          C32, C33, C40>=5.0, C44 */

/* The following class definition is a classification scheme for
   putting instructions with similar type of arguments together. It
   simplifies the op-code definitions significantly, as we then only
   need to use the class macroes for 95% of the DSP's opcodes.
*/

/* A: General 2-operand integer operations
   Syntax: <i> src, dst
      src = Register (Q), Direct (@), Indirect (*), Signed immediate (S)
      dst = Register (R)
   Instr: 15/8 - ABSI, ADDC, ADDI, ASH, CMPI, LDI, LSH, MPYI, NEGB, NEGI,
                SUBB, SUBC, SUBI, SUBRB, SUBRI, C4x: LBn, LHn, LWLn, LWRn,
                MBn, MHn, MPYSHI, MPYUHI
*/
#define A_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q;R", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,R", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,R", level }, \
  { name, opcode|0x00600000, 0xffe00000, "S,R", level }

/* AB: General 2-operand integer operation with condition
   Syntax: <i>c src, dst
       c   = Condition
       src = Register (Q), Direct (@), Indirect (*), Signed immediate (S)
       dst = Register (R)
   Instr: 1/0 - LDIc
*/
#define AB_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x40000000, 0xf0600000, "Q;R", level }, \
  { name, opcode|0x40200000, 0xf0600000, "@,R", level }, \
  { name, opcode|0x40400000, 0xf0600000, "*,R", level }, \
  { name, opcode|0x40600000, 0xf0600000, "S,R", level }

/* AU: General 2-operand unsigned integer operation
   Syntax: <i> src, dst
        src = Register (Q), Direct (@), Indirect (*), Unsigned immediate (U)
        dst = Register (R)
   Instr: 6/2 - AND, ANDN, NOT, OR, TSTB, XOR, C4x: LBUn, LHUn
*/
#define AU_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q;R", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,R", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,R", level }, \
  { name, opcode|0x00600000, 0xffe00000, "U,R", level }

/* AF: General 2-operand float to integer operation
   Syntax: <i> src, dst
        src = Register 0-11 (q), Direct (@), Indirect (*), Float immediate (F)
        dst = Register (R)
   Instr: 1/0 - FIX
*/
#define AF_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "q;R", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,R", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,R", level }, \
  { name, opcode|0x00600000, 0xffe00000, "F,R", level }

/* A2: Limited 1-operand (integer) operation
   Syntax: <i> src
       src = Register (Q), Indirect (*), None
   Instr: 1/0 - NOP
*/
#define A2_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*", level }, \
  { name, opcode|0x00000000, 0xffe00000, "" , level }

/* A3: General 1-operand unsigned integer operation
   Syntax: <i> src
        src = Register (Q), Direct (@), Indirect (*), Unsigned immediate (U)
   Instr: 1/0 - RPTS
*/
#define A3_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffff0000, "Q", level }, \
  { name, opcode|0x00200000, 0xffff0000, "@", level }, \
  { name, opcode|0x00400000, 0xffff0000, "*", level }, \
  { name, opcode|0x00600000, 0xffff0000, "U", level }

/* A6: Limited 2-operand integer operation
   Syntax: <i> src, dst
       src = Direct (@), Indirect (*)
       dst = Register (R)
   Instr: 1/1 - LDII, C4x: SIGI
*/
#define A6_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00200000, 0xffe00000, "@,R", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,R", level }

/* A7: Limited 2-operand integer store operation
   Syntax: <i> src, dst
       src = Register (R)
       dst = Direct (@), Indirect (*)
   Instr: 2/0 - STI, STII
*/
#define A7_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00200000, 0xffe00000, "R,@", level }, \
  { name, opcode|0x00400000, 0xffe00000, "R,*", level }

/* AY: General 2-operand signed address load operation
   Syntax: <i> src, dst
        src = Register (Q), Direct (@), Indirect (*), Signed immediate (S)
        dst = Address register - ARx, IRx, DP, BK, SP (Y)
   Instr: 0/1 - C4x: LDA
   Note: Q and Y should *never* be the same register
*/
#define AY_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q,Y", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,Y", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,Y", level }, \
  { name, opcode|0x00600000, 0xffe00000, "S,Y", level }

/* B: General 2-operand float operation
   Syntax: <i> src, dst
       src = Register 0-11 (q), Direct (@), Indirect (*), Float immediate (F)
       dst = Register 0-11 (r)
   Instr: 12/2 - ABSF, ADDF, CMPF, LDE, LDF, LDM, MPYF, NEGF, NORM, RND,
                 SUBF, SUBRF, C4x: RSQRF, TOIEEE
*/
#define B_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "q;r", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,r", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,r", level }, \
  { name, opcode|0x00600000, 0xffe00000, "F,r", level }

/* BA: General 2-operand integer to float operation
   Syntax: <i> src, dst
       src = Register (Q), Direct (@), Indirect (*), Float immediate (F)
       dst = Register 0-11 (r)
   Instr: 0/1 - C4x: CRCPF
*/
#define BA_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q;r", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,r", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,r", level }, \
  { name, opcode|0x00600000, 0xffe00000, "F,r", level }

/* BB: General 2-operand conditional float operation
   Syntax: <i>c src, dst
       c   = Condition
       src = Register 0-11 (q), Direct (@), Indirect (*), Float immediate (F)
       dst = Register 0-11 (r)
   Instr: 1/0 - LDFc
*/
#define BB_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x40000000, 0xf0600000, "q;r", level }, \
  { name, opcode|0x40200000, 0xf0600000, "@,r", level }, \
  { name, opcode|0x40400000, 0xf0600000, "*,r", level }, \
  { name, opcode|0x40600000, 0xf0600000, "F,r", level }

/* BI: General 2-operand integer to float operation (yet different to BA)
   Syntax: <i> src, dst
       src = Register (Q), Direct (@), Indirect (*), Signed immediate (S)
       dst = Register 0-11 (r)
   Instr: 1/0 - FLOAT
*/
#define BI_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00000000, 0xffe00000, "Q;r", level }, \
  { name, opcode|0x00200000, 0xffe00000, "@,r", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,r", level }, \
  { name, opcode|0x00600000, 0xffe00000, "S,r", level }

/* B6: Limited 2-operand float operation 
   Syntax: <i> src, dst
       src = Direct (@), Indirect (*)
       dst = Register 0-11 (r)
   Instr: 1/1 - LDFI, C4x: FRIEEE
*/
#define B6_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00200000, 0xffe00000, "@,r", level }, \
  { name, opcode|0x00400000, 0xffe00000, "*,r", level }

/* B7: Limited 2-operand float store operation
   Syntax: <i> src, dst
       src = Register 0-11 (r)
       dst = Direct (@), Indirect (*)
   Instr: 2/0 - STF, STFI
*/
#define B7_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x00200000, 0xffe00000, "r,@", level }, \
  { name, opcode|0x00400000, 0xffe00000, "r,*", level }

/* D: Decrement and brach operations
   Syntax: <i>c ARn, dst
       c   = condition
       ARn = AR register 0-7 (A)
       dst = Register (Q), PC-relative (P)
   Instr: 2/0 - DBc, DBcD
   Alias: <name1> <name2>
*/
#define D_CLASS_INSN(name1, name2, opcode, level) \
  { name1, opcode|0x00000000, 0xfe200000, "A,Q", level }, \
  { name1, opcode|0x02000000, 0xfe200000, "A,P", level }, \
  { name2, opcode|0x00000000, 0xfe200000, "A,Q", level }, \
  { name2, opcode|0x02000000, 0xfe200000, "A,P", level }

/* I: General branch operations
   Syntax: <i> dst
       dst = Address (B)
   Instr: 3/1 - BR, BRD, CALL, C4x: LAJ
*/

/* I2: General branch operations (C4x addition)
   Syntax: <i> dst
       dst = Address (B), C4x: Register (Q)
   Instr: 2/0 - RPTB, RPTBD
*/

/* J: General conditional branch operations
   Syntax: <i>c dst
       c   = Condition
       dst = Register (Q), PC-relative (P)
   Instr: 2/3 - Bc, BcD, C4x: BcAF, BcAT, LAJc
   Alias: <name1> <name2>
*/
#define J_CLASS_INSN(name1, name2, opcode, level) \
  { name1, opcode|0x00000000, 0xffe00000, "Q", level }, \
  { name1, opcode|0x02000000, 0xffe00000, "P", level }, \
  { name2, opcode|0x00000000, 0xffe00000, "Q", level }, \
  { name2, opcode|0x02000000, 0xffe00000, "P", level }

/* JS: General conditional branch operations
   Syntax: <i>c dst
       c   = Condition
       dst = Register (Q), PC-relative (P)
   Instr: 1/1 - CALLc, C4X: LAJc
*/

/* LL: Load-load parallell operation
   Syntax: <i> src2, dst2 || <i> src1, dst1
       src1 = Indirect 0,1,IR0,IR1 (J)
       dst1 = Register 0-7 (K)
       src2 = Indirect 0,1,IR0,IR1, ENH: Register (i)
       dst2 = Register 0-7 (L)
   Instr: 2/0 - LDF||LDF, LDI||LDI
   Alias: i||i, i1||i2, i2||i1
*/
#define LL_CLASS_INSN(name, opcode, level) \
  { name "_"  name    , opcode, 0xfe000000, "i;L|J,K", level }, \
  { name "2_" name "1", opcode, 0xfe000000, "i;L|J,K", level }, \
  { name "1_" name "2", opcode, 0xfe000000, "J,K|i;L", level }

/* LS: Store-store parallell operation
   Syntax: <i> src2, dst2 || <i> src1, dst1
       src1 = Register 0-7 (H)
       dst1 = Indirect 0,1,IR0,IR1 (J)
       src2 = Register 0-7 (L)
       dst2 = Indirect 0,1,IR0,IR1, ENH: register (i)
   Instr: 2/0 - STF||STF, STI||STI
   Alias: i||i, i1||i2, i2||i1.
*/
#define LS_CLASS_INSN(name, opcode, level) \
  { name "_"  name    , opcode, 0xfe000000, "L;i|H,J", level }, \
  { name "2_" name "1", opcode, 0xfe000000, "L;i|H,J", level }, \
  { name "1_" name "2", opcode, 0xfe000000, "H,J|L;i", level }

/* M: General multiply and add/sub operations
   Syntax: <ia> src3,src4,dst1 || <ib> src2,src1,dst2 [00] - Manual
           <ia> src3,src1,dst1 || <ib> src2,src4,dst2 [01] - Manual
           <ia> src1,src3,dst1 || <ib> src2,src4,dst2 [01]
           <ia> src1,src2,dst1 || <ib> src4,src3,dst2 [02] - Manual
           <ia> src3,src1,dst1 || <ib> src4,src2,dst2 [03] - Manual
           <ia> src1,src3,dst1 || <ib> src4,src2,dst2 [03]
       src1 = Register 0-7 (K)
       src2 = Register 0-7 (H)
       src3 = Indirect 0,1,IR0,IR1, ENH: register (j)
       src4 = Indirect 0,1,IR0,IR1, ENH: register (i)
       dst1 = Register 0-1 (N)
       dst2 = Register 2-3 (M)
   Instr: 4/0 - MPYF3||ADDF3, MPYF3||SUBF3, MPYI3||ADDI3, MPYI3||SUBI3
   Alias: a||b, a3||n, a||b3, a3||b3, b||a, b3||a, b||a3, b3||a3
*/
#define M_CLASS_INSN(namea, nameb, opcode, level) \
  { namea "_" nameb, opcode|0x00000000, 0xff000000, "i;j;N|H;K;M", level }, \
  { namea "_" nameb, opcode|0x01000000, 0xff000000, "j;K;N|H;i;M", level }, \
  { namea "_" nameb, opcode|0x01000000, 0xff000000, "K;j;N|H;i;M", level }, \
  { namea "_" nameb, opcode|0x02000000, 0xff000000, "H;K;N|i;j;M", level }, \
  { namea "_" nameb, opcode|0x03000000, 0xff000000, "j;K;N|i;H;M", level }, \
  { namea "_" nameb, opcode|0x03000000, 0xff000000, "K;j;N|i;H;M", level }, \
  { namea "3_" nameb, opcode|0x00000000, 0xff000000, "i;j;N|H;K;M", level }, \
  { namea "3_" nameb, opcode|0x01000000, 0xff000000, "j;K;N|H;i;M", level }, \
  { namea "3_" nameb, opcode|0x01000000, 0xff000000, "K;j;N|H;i;M", level }, \
  { namea "3_" nameb, opcode|0x02000000, 0xff000000, "H;K;N|i;j;M", level }, \
  { namea "3_" nameb, opcode|0x03000000, 0xff000000, "j;K;N|i;H;M", level }, \
  { namea "3_" nameb, opcode|0x03000000, 0xff000000, "K;j;N|i;H;M", level }, \
  { namea "_" nameb "3", opcode|0x00000000, 0xff000000, "i;j;N|H;K;M", level }, \
  { namea "_" nameb "3", opcode|0x01000000, 0xff000000, "j;K;N|H;i;M", level }, \
  { namea "_" nameb "3", opcode|0x01000000, 0xff000000, "K;j;N|H;i;M", level }, \
  { namea "_" nameb "3", opcode|0x02000000, 0xff000000, "H;K;N|i;j;M", level }, \
  { namea "_" nameb "3", opcode|0x03000000, 0xff000000, "j;K;N|i;H;M", level }, \
  { namea "_" nameb "3", opcode|0x03000000, 0xff000000, "K;j;N|i;H;M", level }, \
  { namea "3_" nameb "3", opcode|0x00000000, 0xff000000, "i;j;N|H;K;M", level }, \
  { namea "3_" nameb "3", opcode|0x01000000, 0xff000000, "j;K;N|H;i;M", level }, \
  { namea "3_" nameb "3", opcode|0x01000000, 0xff000000, "K;j;N|H;i;M", level }, \
  { namea "3_" nameb "3", opcode|0x02000000, 0xff000000, "H;K;N|i;j;M", level }, \
  { namea "3_" nameb "3", opcode|0x03000000, 0xff000000, "j;K;N|i;H;M", level }, \
  { namea "3_" nameb "3", opcode|0x03000000, 0xff000000, "K;j;N|i;H;M", level }, \
  { nameb "_" namea, opcode|0x00000000, 0xff000000, "H;K;M|i;j;N", level }, \
  { nameb "_" namea, opcode|0x01000000, 0xff000000, "H;i;M|j;K;N", level }, \
  { nameb "_" namea, opcode|0x01000000, 0xff000000, "H;i;M|K;j;N", level }, \
  { nameb "_" namea, opcode|0x02000000, 0xff000000, "i;j;M|H;K;N", level }, \
  { nameb "_" namea, opcode|0x03000000, 0xff000000, "i;H;M|j;K;N", level }, \
  { nameb "_" namea, opcode|0x03000000, 0xff000000, "i;H;M|K;j;N", level }, \
  { nameb "3_" namea, opcode|0x00000000, 0xff000000, "H;K;M|i;j;N", level }, \
  { nameb "3_" namea, opcode|0x01000000, 0xff000000, "H;i;M|j;K;N", level }, \
  { nameb "3_" namea, opcode|0x01000000, 0xff000000, "H;i;M|K;j;N", level }, \
  { nameb "3_" namea, opcode|0x02000000, 0xff000000, "i;j;M|H;K;N", level }, \
  { nameb "3_" namea, opcode|0x03000000, 0xff000000, "i;H;M|j;K;N", level }, \
  { nameb "3_" namea, opcode|0x03000000, 0xff000000, "i;H;M|K;j;N", level }, \
  { nameb "_" namea "3", opcode|0x00000000, 0xff000000, "H;K;M|i;j;N", level }, \
  { nameb "_" namea "3", opcode|0x01000000, 0xff000000, "H;i;M|j;K;N", level }, \
  { nameb "_" namea "3", opcode|0x01000000, 0xff000000, "H;i;M|K;j;N", level }, \
  { nameb "_" namea "3", opcode|0x02000000, 0xff000000, "i;j;M|H;K;N", level }, \
  { nameb "_" namea "3", opcode|0x03000000, 0xff000000, "i;H;M|j;K;N", level }, \
  { nameb "_" namea "3", opcode|0x03000000, 0xff000000, "i;H;M|K;j;N", level }, \
  { nameb "3_" namea "3", opcode|0x00000000, 0xff000000, "H;K;M|i;j;N", level }, \
  { nameb "3_" namea "3", opcode|0x01000000, 0xff000000, "H;i;M|j;K;N", level }, \
  { nameb "3_" namea "3", opcode|0x01000000, 0xff000000, "H;i;M|K;j;N", level }, \
  { nameb "3_" namea "3", opcode|0x02000000, 0xff000000, "i;j;M|H;K;N", level }, \
  { nameb "3_" namea "3", opcode|0x03000000, 0xff000000, "i;H;M|j;K;N", level }, \
  { nameb "3_" namea "3", opcode|0x03000000, 0xff000000, "i;H;M|K;j;N", level }

/* P: General 2-operand operation with parallell store
   Syntax: <ia> src2, dst1 || <ib> src3, dst2
       src2 = Indirect 0,1,IR0,IR1, ENH: register (i)
       dst1 = Register 0-7 (L)
       src3 = Register 0-7 (H)
       dst2 = Indirect 0,1,IR0,IR1 (J)
   Instr: 9/2 - ABSF||STF, ABSI||STI, FIX||STI, FLOAT||STF, LDF||STF,
                LDI||STI, NEGF||STF, NEGI||STI, NOT||STI, C4x: FRIEEE||STF,
                TOIEEE||STF
   Alias: a||b, b||a
*/
#define P_CLASS_INSN(namea, nameb, opcode, level) \
  { namea "_" nameb, opcode, 0xfe000000, "i;L|H,J", level }, \
  { nameb "_" namea, opcode, 0xfe000000, "H,J|i;L", level }

/* Q: General 3-operand operation with parallell store
   Syntax: <ia> src1, src2, dst1 || <ib> src3, dst2
       src1 = Register 0-7 (K)
       src2 = Indirect 0,1,IR0,IR1, ENH: register (i)
       dst1 = Register 0-7 (L)
       src3 = Register 0-7 (H)
       dst2 = Indirect 0,1,IR0,IR1 (J)
   Instr: 4/0 - ASH3||STI, LSH3||STI, SUBF3||STF, SUBI3||STI
   Alias: a||b, b||a, a3||b, b||a3
*/
#define Q_CLASS_INSN(namea, nameb, opcode, level) \
  { namea "_"  nameb    , opcode, 0xfe000000, "K,i;L|H,J", level }, \
  { nameb "_"  namea    , opcode, 0xfe000000, "H,J|K,i;L", level }, \
  { namea "3_" nameb    , opcode, 0xfe000000, "K,i;L|H,J", level }, \
  { nameb "_"  namea "3", opcode, 0xfe000000, "H,J|K,i;L", level }

/* QC: General commutative 3-operand operation with parallell store
   Syntax: <ia> src2, src1, dst1 || <ib> src3, dst2
           <ia> src1, src2, dst1 || <ib> src3, dst2 - Manual
       src1 = Register 0-7 (K)
       src2 = Indirect 0,1,IR0,IR1, ENH: register (i)
       dst1 = Register 0-7 (L)
       src3 = Register 0-7 (H)
       dst2 = Indirect 0,1,IR0,IR1 (J)
   Instr: 7/0 - ADDF3||STF, ADDI3||STI, AND3||STI, MPYF3||STF, MPYI3||STI,
                OR3||STI, XOR3||STI
   Alias: a||b, b||a, a3||b, b||a3
*/
#define QC_CLASS_INSN(namea, nameb, opcode, level) \
  { namea "_"  nameb    , opcode, 0xfe000000, "i;K;L|H,J", level }, \
  { namea "_"  nameb    , opcode, 0xfe000000, "K;i;L|H,J", level }, \
  { nameb "_"  namea    , opcode, 0xfe000000, "H,J|i;K;L", level }, \
  { nameb "_"  namea    , opcode, 0xfe000000, "H,J|K;i;L", level }, \
  { namea "3_" nameb    , opcode, 0xfe000000, "i;K;L|H,J", level }, \
  { namea "3_" nameb    , opcode, 0xfe000000, "K;i;L|H,J", level }, \
  { nameb "_"  namea "3", opcode, 0xfe000000, "H,J|i;K;L", level }, \
  { nameb "_"  namea "3", opcode, 0xfe000000, "H,J|K;i;L", level }

/* R: General register integer operation
   Syntax: <i> dst
       dst = Register (R)
   Instr: 6/0 - POP, PUSH, ROL, ROLC, ROR, RORC
*/
#define R_CLASS_INSN(name, opcode, level) \
  { name, opcode, 0xffe0ffff, "R", level }

/* RF: General register float operation
   Syntax: <i> dst
       dst = Register 0-11 (r)
   Instr: 2/0 - POPF, PUSHF
*/
#define RF_CLASS_INSN(name, opcode, level) \
  { name, opcode, 0xffe0ffff, "r", level }

/* S: General 3-operand float operation
   Syntax: <i> src2, src1, dst
       src2 = Register 0-11 (e), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C)
       src1 = Register 0-11 (g), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
       dst  = Register 0-11 (r)
   Instr: 1/0 - SUBF3
   Alias: i, i3
*/
#define S_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "e,g;r", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "e,J,r", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,g;r", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J,r", level  }, \
  { name, opcode|0x30200000, 0xffe00000, "C,g;r", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O,r", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "e,g;r", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "e,J,r", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,g;r", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J,r", level  }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,g;r", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O,r", OP_C4X }

/* SC: General commutative 3-operand float operation
   Syntax: <i> src2, src1, dst - Manual
           <i> src1, src2, dst
       src2 = Register 0-11 (e), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C)
       src1 = Register 0-11 (g), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
       dst  = Register 0-11 (r)
   Instr: 2/0 - ADDF3, MPYF3
   Alias: i, i3
*/
#define SC_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "e,g;r", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "e,J,r", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,g;r", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J,r", level  }, \
  { name, opcode|0x30200000, 0xffe00000, "C,g;r", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "g,C,r", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O,r", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "e,g;r", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "e,J,r", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,g;r", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J,r", level  }, \
  { name "3", opcode|0x30200000, 0xffe00000, "g,C,r", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,g;r", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O,r", OP_C4X }

/* S2: General 3-operand float operation with 2 args
   Syntax: <i> src2, src1
       src2 = Register 0-11 (e), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C)
       src1 = Register 0-11 (g), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
   Instr: 1/0 - CMPF3
   Alias: i, i3
*/
#define S2_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "e,g", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "e,J", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,g", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name, opcode|0x30200000, 0xffe00000, "C,g", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "e,g", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "e,J", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,g", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,g", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }

/* T: General 3-operand integer operand
   Syntax: <i> src2, src1, dst
       src2 = Register (E), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C), Immediate (W)
       src1 = Register (G), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
       dst  = Register (R)
   Instr: 5/0 - ANDN3, ASH3, LSH3, SUBB3, SUBI3
   Alias: i, i3
*/
#define T_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "E,G;R", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "E,J,R", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,G;R", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J,R", level  }, \
  { name, opcode|0x30000000, 0xffe00000, "W,G;R", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "C,G;R", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "W,O,R", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O,R", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "E,G;R", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "E,J,R", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,G;R", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J,R", level  }, \
  { name "3", opcode|0x30000000, 0xffe00000, "W,G;R", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,G;R", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "W,O,R", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O,R", OP_C4X }

/* TC: General commutative 3-operand integer operation
   Syntax: <i> src2, src1, dst
           <i> src1, src2, dst
       src2 = Register (E), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C), Immediate (W)
       src1 = Register (G), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
       dst  = Register (R)
   Instr: 6/2 - ADDC3, ADDI3, AND3, MPYI3, OR3, XOR3, C4x: MPYSHI, MPYUHI
   Alias: i, i3
*/
#define TC_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "E,G;R", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "E,J,R", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,G;R", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J,R", level  }, \
  { name, opcode|0x30000000, 0xffe00000, "W,G;R", OP_C4X }, \
  { name, opcode|0x30000000, 0xffe00000, "G,W,R", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "C,G;R", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "G,C,R", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "W,O,R", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "O,W,R", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O,R", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "E,G;R", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "E,J,R", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,G;R", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J,R", level  }, \
  { name "3", opcode|0x30000000, 0xffe00000, "W,G;R", OP_C4X }, \
  { name "3", opcode|0x30000000, 0xffe00000, "G,W,R", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,G;R", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "G,C,R", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "W,O,R", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "O,W,R", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O,R", OP_C4X }

/* T2: General 3-operand integer operation with 2 args
   Syntax: <i> src2, src1
       src2 = Register (E), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C), Immediate (W)
       src1 = Register (G), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (O)
   Instr: 1/0 - CMPI3
   Alias: i, i3
*/
#define T2_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "E,G", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "E,J", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,G", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name, opcode|0x30000000, 0xffe00000, "W,G", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "C,G", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "W,O", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "E,G", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "E,J", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,G", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name "3", opcode|0x30000000, 0xffe00000, "W,G", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,G", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "W,O", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }

/* T2C: General commutative 3-operand integer operation with 2 args 
   Syntax: <i> src2, src1 - Manual
           <i> src1, src2 
       src2 = Register (E), Indirect 0,1,IR0,IR1 (I), C4x T2: Indirect (C), Immediate (W)
       src1 = Register (G), Indirect 0,1,IR0,IR1 (J), C4x T2: Indirect (0)
   Instr: 1/0 - TSTB3
   Alias: i, i3
*/
#define T2C_CLASS_INSN(name, opcode, level) \
  { name, opcode|0x20000000, 0xffe00000, "E,G", level  }, \
  { name, opcode|0x20200000, 0xffe00000, "E,J", level  }, \
  { name, opcode|0x20400000, 0xffe00000, "I,G", level  }, \
  { name, opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name, opcode|0x30000000, 0xffe00000, "W,G", OP_C4X }, \
  { name, opcode|0x30000000, 0xffe00000, "G,W", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "C,G", OP_C4X }, \
  { name, opcode|0x30200000, 0xffe00000, "G,C", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "W,O", OP_C4X }, \
  { name, opcode|0x30400000, 0xffe00000, "O,W", OP_C4X }, \
  { name, opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }, \
  { name "3", opcode|0x20000000, 0xffe00000, "E,G", level  }, \
  { name "3", opcode|0x20200000, 0xffe00000, "E,J", level  }, \
  { name "3", opcode|0x20400000, 0xffe00000, "I,G", level  }, \
  { name "3", opcode|0x20600000, 0xffe00000, "I,J", level  }, \
  { name "3", opcode|0x30000000, 0xffe00000, "W,G", OP_C4X }, \
  { name "3", opcode|0x30000000, 0xffe00000, "G,W", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "C,G", OP_C4X }, \
  { name "3", opcode|0x30200000, 0xffe00000, "G,C", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "W,O", OP_C4X }, \
  { name "3", opcode|0x30400000, 0xffe00000, "O,W", OP_C4X }, \
  { name "3", opcode|0x30600000, 0xffe00000, "C,O", OP_C4X }

/* Z: Misc operations with or without arguments
   Syntax: <i> <arg1>,...
   Instr: 16 - RETIc, RETSc, SIGI(c3X), SWI, IDLE, IDLE2, RETIcD, 
               TRAPc, LATc, LDEP, LDEHI, LDEPE, LDPK, STIK, LDP, IACK
*/


/* Define tic4x opcodes for assembler and disassembler.  */
static const tic4x_inst_t tic4x_insts[] =
{
  /* Put synonyms after the desired forms in table so that they get
     overwritten in the lookup table.  The disassembler will thus
     print the `proper' mnemonics.  Note that the disassembler
     only decodes the 11 MSBs, so instructions like ldp @0x500 will
     be printed as ldiu 5, dp.  Note that with parallel instructions,
     the second part is executed before the first part, unless
     the sti1||sti2 form is used.  We also allow sti2||sti1
     which is equivalent to the default sti||sti form.
  */
  B_CLASS_INSN(  "absf",          0x00000000, OP_C3X   ),
  P_CLASS_INSN(  "absf",  "stf",  0xc8000000, OP_C3X   ),
  A_CLASS_INSN(  "absi",          0x00800000, OP_C3X   ),
  P_CLASS_INSN(  "absi",  "sti",  0xca000000, OP_C3X   ),
  A_CLASS_INSN(  "addc",          0x01000000, OP_C3X   ),
  TC_CLASS_INSN( "addc",          0x00000000, OP_C3X   ),
  B_CLASS_INSN(  "addf",          0x01800000, OP_C3X   ),
  SC_CLASS_INSN( "addf",          0x00800000, OP_C3X   ),
  QC_CLASS_INSN( "addf",  "stf",  0xcc000000, OP_C3X   ),
  A_CLASS_INSN(  "addi",          0x02000000, OP_C3X   ),
  TC_CLASS_INSN( "addi",          0x01000000, OP_C3X   ),
  QC_CLASS_INSN( "addi",  "sti",  0xce000000, OP_C3X   ),
  AU_CLASS_INSN( "and",           0x02800000, OP_C3X   ),
  TC_CLASS_INSN( "and",           0x01800000, OP_C3X   ),
  QC_CLASS_INSN( "and",   "sti",  0xd0000000, OP_C3X   ),
  AU_CLASS_INSN( "andn",          0x03000000, OP_C3X   ),
  T_CLASS_INSN(  "andn",          0x02000000, OP_C3X   ),
  A_CLASS_INSN(  "ash",           0x03800000, OP_C3X   ),
  T_CLASS_INSN(  "ash",           0x02800000, OP_C3X   ),
  Q_CLASS_INSN(  "ash",   "sti",  0xd2000000, OP_C3X   ),
  J_CLASS_INSN(  "bB",    "b",    0x68000000, OP_C3X   ),
  J_CLASS_INSN(  "bBd",   "bd",   0x68200000, OP_C3X   ),
  J_CLASS_INSN(  "bBaf",  "baf",  0x68a00000, OP_C4X   ),
  J_CLASS_INSN(  "bBat",  "bat",  0x68600000, OP_C4X   ),
  { "br",     0x60000000, 0xff000000, "B"   , OP_C3X   },  /* I_CLASS */
  { "brd",    0x61000000, 0xff000000, "B"   , OP_C3X   },  /* I_CLASS */
  { "call",   0x62000000, 0xff000000, "B"   , OP_C3X   },  /* I_CLASS */
  { "callB",  0x70000000, 0xffe00000, "Q"   , OP_C3X   },  /* JS_CLASS */
  { "callB",  0x72000000, 0xffe00000, "P"   , OP_C3X   },  /* JS_CLASS */
  B_CLASS_INSN(  "cmpf",          0x04000000, OP_C3X   ),
  S2_CLASS_INSN( "cmpf",          0x03000000, OP_C3X   ),
  A_CLASS_INSN(  "cmpi",          0x04800000, OP_C3X   ),
  T2_CLASS_INSN( "cmpi",          0x03800000, OP_C3X   ),
  D_CLASS_INSN(  "dbB",   "db",   0x6c000000, OP_C3X   ),
  D_CLASS_INSN(  "dbBd",  "dbd",  0x6c200000, OP_C3X   ),
  AF_CLASS_INSN( "fix",           0x05000000, OP_C3X   ),
  P_CLASS_INSN(  "fix",   "sti",  0xd4000000, OP_C3X   ),
  BI_CLASS_INSN( "float",         0x05800000, OP_C3X   ),
  P_CLASS_INSN(  "float", "stf",  0xd6000000, OP_C3X   ),
  B6_CLASS_INSN( "frieee",        0x1c000000, OP_C4X   ),
  P_CLASS_INSN(  "frieee","stf",  0xf2000000, OP_C4X   ),
  { "iack",   0x1b200000, 0xffe00000, "@"   , OP_C3X   },  /* Z_CLASS */
  { "iack",   0x1b400000, 0xffe00000, "*"   , OP_C3X   },  /* Z_CLASS */
  { "idle",   0x06000000, 0xffffffff, ""    , OP_C3X   },  /* Z_CLASS */
  { "idlez",  0x06000000, 0xffffffff, ""    , OP_C3X   },  /* Z_CLASS */
  { "idle2",  0x06000001, 0xffffffff, ""    , OP_IDLE2 },  /* Z_CLASS */
  { "laj",    0x63000000, 0xff000000, "B"   , OP_C4X   },  /* I_CLASS */
  { "lajB",   0x70200000, 0xffe00000, "Q"   , OP_C4X   },  /* JS_CLASS */
  { "lajB",   0x72200000, 0xffe00000, "P"   , OP_C4X   },  /* JS_CLASS */
  { "latB",   0x74800000, 0xffe00000, "V"   , OP_C4X   },  /* Z_CLASS */
  A_CLASS_INSN(  "lb0",           0xb0000000, OP_C4X   ),
  A_CLASS_INSN(  "lb1",           0xb0800000, OP_C4X   ),
  A_CLASS_INSN(  "lb2",           0xb1000000, OP_C4X   ),
  A_CLASS_INSN(  "lb3",           0xb1800000, OP_C4X   ),
  AU_CLASS_INSN( "lbu0",          0xb2000000, OP_C4X   ),
  AU_CLASS_INSN( "lbu1",          0xb2800000, OP_C4X   ),
  AU_CLASS_INSN( "lbu2",          0xb3000000, OP_C4X   ),
  AU_CLASS_INSN( "lbu3",          0xb3800000, OP_C4X   ),
  AY_CLASS_INSN( "lda",           0x1e800000, OP_C4X   ),
  B_CLASS_INSN(  "lde",           0x06800000, OP_C3X   ),
  { "ldep",   0x76000000, 0xffe00000, "X,R" , OP_C4X   },  /* Z_CLASS */
  B_CLASS_INSN(  "ldf",           0x07000000, OP_C3X   ),
  LL_CLASS_INSN( "ldf",           0xc4000000, OP_C3X   ),
  P_CLASS_INSN(  "ldf",   "stf",  0xd8000000, OP_C3X   ),
  BB_CLASS_INSN( "ldfC",          0x00000000, OP_C3X   ),
  B6_CLASS_INSN( "ldfi",          0x07800000, OP_C3X   ),
  { "ldhi",   0x1fe00000, 0xffe00000, "U,R" , OP_C4X   },  /* Z_CLASS */
  { "ldhi",   0x1fe00000, 0xffe00000, "#,R" , OP_C4X   },  /* Z_CLASS */
  A_CLASS_INSN(  "ldi",           0x08000000, OP_C3X   ),
  LL_CLASS_INSN( "ldi",           0xc6000000, OP_C3X   ),
  P_CLASS_INSN(  "ldi",   "sti",  0xda000000, OP_C3X   ),
  AB_CLASS_INSN( "ldiC",          0x10000000, OP_C3X   ),
  A6_CLASS_INSN( "ldii",          0x08800000, OP_C3X   ),
  { "ldp",    0x50700000, 0xffff0000, "#"   , OP_C3X   },  /* Z_CLASS - synonym for ldiu #,dp */
  B_CLASS_INSN(  "ldm",           0x09000000, OP_C3X   ),
  { "ldpe",   0x76800000, 0xffe00000, "Q,Z" , OP_C4X   },  /* Z_CLASS */
  { "ldpk",   0x1F700000, 0xffff0000, "#"   , OP_C4X   },  /* Z_CLASS */
  A_CLASS_INSN(  "lh0",           0xba000000, OP_C4X   ),
  A_CLASS_INSN(  "lh1",           0xba800000, OP_C4X   ),
  AU_CLASS_INSN( "lhu0",          0xbb000000, OP_C4X   ),
  AU_CLASS_INSN( "lhu1",          0xbb800000, OP_C4X   ),
  { "lopower", 0x10800001,0xffffffff, ""    , OP_LPWR  },  /* Z_CLASS */
  A_CLASS_INSN(  "lsh",           0x09800000, OP_C3X   ),
  T_CLASS_INSN(  "lsh",           0x04000000, OP_C3X   ),
  Q_CLASS_INSN(  "lsh",   "sti",  0xdc000000, OP_C3X   ),
  A_CLASS_INSN(  "lwl0",          0xb4000000, OP_C4X   ),
  A_CLASS_INSN(  "lwl1",          0xb4800000, OP_C4X   ),
  A_CLASS_INSN(  "lwl2",          0xb5000000, OP_C4X   ),
  A_CLASS_INSN(  "lwl3",          0xb5800000, OP_C4X   ),
  A_CLASS_INSN(  "lwr0",          0xb6000000, OP_C4X   ),
  A_CLASS_INSN(  "lwr1",          0xb6800000, OP_C4X   ),
  A_CLASS_INSN(  "lwr2",          0xb7000000, OP_C4X   ),
  A_CLASS_INSN(  "lwr3",          0xb7800000, OP_C4X   ),
  { "maxspeed",0x10800000,0xffffffff, ""    , OP_LPWR  },  /* Z_CLASS */
  A_CLASS_INSN(  "mb0",           0xb8000000, OP_C4X   ),
  A_CLASS_INSN(  "mb1",           0xb8800000, OP_C4X   ),
  A_CLASS_INSN(  "mb2",           0xb9000000, OP_C4X   ),
  A_CLASS_INSN(  "mb3",           0xb9800000, OP_C4X   ),
  A_CLASS_INSN(  "mh0",           0xbc000000, OP_C4X   ),
  A_CLASS_INSN(  "mh1",           0xbc800000, OP_C4X   ),
  A_CLASS_INSN(  "mh2",           0xbd000000, OP_C4X   ),
  A_CLASS_INSN(  "mh3",           0xbd800000, OP_C4X   ),
  B_CLASS_INSN(  "mpyf",          0x0a000000, OP_C3X   ),
  SC_CLASS_INSN( "mpyf",          0x04800000, OP_C3X   ),
  M_CLASS_INSN(  "mpyf",  "addf", 0x80000000, OP_C3X   ),
  QC_CLASS_INSN( "mpyf",  "stf",  0xde000000, OP_C3X   ),
  M_CLASS_INSN(  "mpyf",  "subf", 0x84000000, OP_C3X   ),
  A_CLASS_INSN(  "mpyi",          0x0a800000, OP_C3X   ),
  TC_CLASS_INSN( "mpyi",          0x05000000, OP_C3X   ),
  M_CLASS_INSN(  "mpyi",  "addi", 0x88000000, OP_C3X   ),
  QC_CLASS_INSN( "mpyi",  "sti",  0xe0000000, OP_C3X   ),
  M_CLASS_INSN(  "mpyi",  "subi", 0x8c000000, OP_C3X   ),
  A_CLASS_INSN(  "mpyshi",        0x1d800000, OP_C4X   ),
  TC_CLASS_INSN( "mpyshi",        0x28800000, OP_C4X   ),
  A_CLASS_INSN(  "mpyuhi",        0x1e000000, OP_C4X   ),
  TC_CLASS_INSN( "mpyuhi",        0x29000000, OP_C4X   ),
  A_CLASS_INSN(  "negb",          0x0b000000, OP_C3X   ),
  B_CLASS_INSN(  "negf",          0x0b800000, OP_C3X   ),
  P_CLASS_INSN(  "negf",  "stf",  0xe2000000, OP_C3X   ),
  A_CLASS_INSN(  "negi",          0x0c000000, OP_C3X   ),
  P_CLASS_INSN(  "negi",  "sti",  0xe4000000, OP_C3X   ),
  A2_CLASS_INSN( "nop",           0x0c800000, OP_C3X   ),
  B_CLASS_INSN(  "norm",          0x0d000000, OP_C3X   ),
  AU_CLASS_INSN( "not",           0x0d800000, OP_C3X   ),
  P_CLASS_INSN(  "not",   "sti",  0xe6000000, OP_C3X   ),
  AU_CLASS_INSN( "or",            0x10000000, OP_C3X   ),
  TC_CLASS_INSN( "or",            0x05800000, OP_C3X   ),
  QC_CLASS_INSN( "or",    "sti",  0xe8000000, OP_C3X   ),
  R_CLASS_INSN(  "pop",           0x0e200000, OP_C3X   ),
  RF_CLASS_INSN( "popf",          0x0ea00000, OP_C3X   ),
  R_CLASS_INSN(  "push",          0x0f200000, OP_C3X   ),
  RF_CLASS_INSN( "pushf",         0x0fa00000, OP_C3X   ),
  BA_CLASS_INSN( "rcpf",          0x1d000000, OP_C4X   ),
  { "retiB",  0x78000000, 0xffe00000, ""    , OP_C3X   },  /* Z_CLASS */
  { "reti",   0x78000000, 0xffe00000, ""    , OP_C3X   },  /* Z_CLASS  - Alias for retiu */
  { "retiBd", 0x78200000, 0xffe00000, ""    , OP_C4X   },  /* Z_CLASS */
  { "retid",  0x78200000, 0xffe00000, ""    , OP_C4X   },  /* Z_CLASS - Alias for retiud */
  { "retsB",  0x78800000, 0xffe00000, ""    , OP_C3X   },  /* Z_CLASS */
  { "rets",   0x78800000, 0xffe00000, ""    , OP_C3X   },  /* Z_CLASS  - Alias for retsu */
  B_CLASS_INSN(  "rnd",           0x11000000, OP_C3X   ),
  R_CLASS_INSN(  "rol",           0x11e00001, OP_C3X   ),
  R_CLASS_INSN(  "rolc",          0x12600001, OP_C3X   ),
  R_CLASS_INSN(  "ror",           0x12e0ffff, OP_C3X   ),
  R_CLASS_INSN(  "rorc",          0x1360ffff, OP_C3X   ),
  { "rptb",   0x64000000, 0xff000000, "B"   , OP_C3X   },  /* I2_CLASS */
  { "rptb",   0x79000000, 0xff000000, "Q"   , OP_C4X   },  /* I2_CLASS */
  { "rptbd",  0x65000000, 0xff000000, "B"   , OP_C4X   },  /* I2_CLASS */ 
  { "rptbd",  0x79800000, 0xff000000, "Q"   , OP_C4X   },  /* I2_CLASS */
  A3_CLASS_INSN( "rpts",          0x139b0000, OP_C3X   ),
  B_CLASS_INSN(  "rsqrf",         0x1c800000, OP_C4X   ),
  { "sigi",   0x16000000, 0xffe00000, ""    , OP_C3X   },  /* Z_CLASS */
  A6_CLASS_INSN( "sigi",          0x16000000, OP_C4X   ),
  B7_CLASS_INSN( "stf",           0x14000000, OP_C3X   ),
  LS_CLASS_INSN( "stf",           0xc0000000, OP_C3X   ),
  B7_CLASS_INSN( "stfi",          0x14800000, OP_C3X   ),
  A7_CLASS_INSN( "sti",           0x15000000, OP_C3X   ),
  { "sti",    0x15000000, 0xffe00000, "T,@" , OP_C4X   },  /* Class A7 - Alias for stik */
  { "sti",    0x15600000, 0xffe00000, "T,*" , OP_C4X   },  /* Class A7 */
  LS_CLASS_INSN( "sti",           0xc2000000, OP_C3X   ),
  A7_CLASS_INSN( "stii",          0x15800000, OP_C3X   ),
  { "stik",   0x15000000, 0xffe00000, "T,@" , OP_C4X   },  /* Z_CLASS */
  { "stik",   0x15600000, 0xffe00000, "T,*" , OP_C4X   },  /* Z_CLASS */
  A_CLASS_INSN(  "subb",          0x16800000, OP_C3X   ),
  T_CLASS_INSN(  "subb",          0x06000000, OP_C3X   ),
  A_CLASS_INSN(  "subc",          0x17000000, OP_C3X   ),
  B_CLASS_INSN(  "subf",          0x17800000, OP_C3X   ),
  S_CLASS_INSN(  "subf",          0x06800000, OP_C3X   ),
  Q_CLASS_INSN(  "subf",  "stf",  0xea000000, OP_C3X   ),
  A_CLASS_INSN(  "subi",          0x18000000, OP_C3X   ),
  T_CLASS_INSN(  "subi",          0x07000000, OP_C3X   ),
  Q_CLASS_INSN(  "subi",  "sti",  0xec000000, OP_C3X   ),
  A_CLASS_INSN(  "subrb",         0x18800000, OP_C3X   ),
  B_CLASS_INSN(  "subrf",         0x19000000, OP_C3X   ),
  A_CLASS_INSN(  "subri",         0x19800000, OP_C3X   ),
  { "swi",    0x66000000, 0xffffffff, ""    , OP_C3X   },  /* Z_CLASS */
  B_CLASS_INSN(  "toieee",        0x1b800000, OP_C4X   ),
  P_CLASS_INSN(  "toieee","stf",  0xf0000000, OP_C4X   ),
  { "trapB",  0x74000000, 0xffe00000, "V"   , OP_C3X   },  /* Z_CLASS */
  { "trap",   0x74000000, 0xffe00000, "V"   , OP_C3X   },  /* Z_CLASS - Alias for trapu */
  AU_CLASS_INSN( "tstb",          0x1a000000, OP_C3X   ),
  T2C_CLASS_INSN("tstb",          0x07800000, OP_C3X   ),
  AU_CLASS_INSN( "xor",           0x1a800000, OP_C3X   ),
  TC_CLASS_INSN( "xor",           0x08000000, OP_C3X   ),
  QC_CLASS_INSN( "xor",   "sti",  0xee000000, OP_C3X   ),

  /* Dummy entry, not included in tic4x_num_insts.  This
     lets code examine entry i + 1 without checking
     if we've run off the end of the table.  */
  { "",      0x0, 0x00, "", 0 }
};

const unsigned int tic4x_num_insts = (((sizeof tic4x_insts) / (sizeof tic4x_insts[0])) - 1);
