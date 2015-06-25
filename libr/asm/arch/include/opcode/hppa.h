/* Table of opcodes for the PA-RISC.
   Copyright (C) 1990-2014 Free Software Foundation, Inc.

   Contributed by the Center for Software Science at the
   University of Utah (pa-gdb-bugs@cs.utah.edu).

   This file is part of GAS, the GNU Assembler, and GDB, the GNU disassembler.

   GAS/GDB is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS/GDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS or GDB; see the file COPYING3.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#if !defined(__STDC__) && !defined(const)
#define const
#endif

/*
 * Structure of an opcode table entry.
 */

/* There are two kinds of delay slot nullification: normal which is
 * controled by the nullification bit, and conditional, which depends
 * on the direction of the branch and its success or failure.
 *
 * NONE is unfortunately #defined in the hiux system include files.  
 * #undef it away.
 */
#undef NONE
struct pa_opcode
{
    const char *name;
    unsigned long int match;	/* Bits that must be set...  */
    unsigned long int mask;	/* ... in these bits. */
    char *args;
    enum pa_arch arch;
    char flags;
};

/* Enables strict matching.  Opcodes with match errors are skipped
   when this bit is set.  */
#define FLAG_STRICT 0x1

/*
   All hppa opcodes are 32 bits.

   The match component is a mask saying which bits must match a
   particular opcode in order for an instruction to be an instance
   of that opcode.

   The args component is a string containing one character for each operand of
   the instruction.  Characters used as a prefix allow any second character to
   be used without conflicting with the main operand characters.

   Bit positions in this description follow HP usage of lsb = 31,
   "at" is lsb of field.

   In the args field, the following characters must match exactly:

	'+,() '

   In the args field, the following characters are unused:

	'  "         -  /   34 6789:;    '
	'@  C         M             [\]  '
	'`    e g                     }  '

   Here are all the characters:

	' !"#$%&'()*+-,./0123456789:;<=>?'
	'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'
	'`abcdefghijklmnopqrstuvwxyz{|}~ '

Kinds of operands:
   x    integer register field at 15.
   b    integer register field at 10.
   t    integer register field at 31.
   a	integer register field at 10 and 15 (for PERMH)
   5    5 bit immediate at 15.
   s    2 bit space specifier at 17.
   S    3 bit space specifier at 18.
   V    5 bit immediate value at 31
   i    11 bit immediate value at 31
   j    14 bit immediate value at 31
   k    21 bit immediate value at 31
   l    16 bit immediate value at 31 (wide mode only, unusual encoding).
   n	nullification for branch instructions
   N	nullification for spop and copr instructions
   w    12 bit branch displacement
   W    17 bit branch displacement (PC relative)
   X    22 bit branch displacement (PC relative)
   z    17 bit branch displacement (just a number, not an address)

Also these:

   .    2 bit shift amount at 25
   *    4 bit shift amount at 25
   p    5 bit shift count at 26 (to support the SHD instruction) encoded as
        31-p
   ~    6 bit shift count at 20,22:26 encoded as 63-~.
   P    5 bit bit position at 26
   q    6 bit bit position at 20,22:26
   T    5 bit field length at 31 (encoded as 32-T)
   %	6 bit field length at 23,27:31 (variable extract/deposit)
   |	6 bit field length at 19,27:31 (fixed extract/deposit)
   A    13 bit immediate at 18 (to support the BREAK instruction)
   ^	like b, but describes a control register
   !    sar (cr11) register
   D    26 bit immediate at 31 (to support the DIAG instruction)
   $    9 bit immediate at 28 (to support POPBTS)

   v    3 bit Special Function Unit identifier at 25
   O    20 bit Special Function Unit operation split between 15 bits at 20
        and 5 bits at 31
   o    15 bit Special Function Unit operation at 20
   2    22 bit Special Function Unit operation split between 17 bits at 20
        and 5 bits at 31
   1    15 bit Special Function Unit operation split between 10 bits at 20
        and 5 bits at 31
   0    10 bit Special Function Unit operation split between 5 bits at 20
        and 5 bits at 31
   u    3 bit coprocessor unit identifier at 25
   F    Source Floating Point Operand Format Completer encoded 2 bits at 20
   I    Source Floating Point Operand Format Completer encoded 1 bits at 20
	(for 0xe format FP instructions)
   G    Destination Floating Point Operand Format Completer encoded 2 bits at 18
   H    Floating Point Operand Format at 26 for 'fmpyadd' and 'fmpysub'
        (very similar to 'F')

   r	5 bit immediate value at 31 (for the break instruction)
	(very similar to V above, except the value is unsigned instead of
	low_sign_ext)
   R	5 bit immediate value at 15 (for the ssm, rsm, probei instructions)
	(same as r above, except the value is in a different location)
   U	10 bit immediate value at 15 (for SSM, RSM on pa2.0)
   Q	5 bit immediate value at 10 (a bit position specified in
	the bb instruction. It's the same as r above, except the
        value is in a different location)
   B	5 bit immediate value at 10 (a bit position specified in
	the bb instruction. Similar to Q, but 64 bit handling is
	different.
   Z    %r1 -- implicit target of addil instruction.
   L    ,%r2 completer for new syntax branch
   {    Source format completer for fcnv
   _    Destination format completer for fcnv
   h    cbit for fcmp
   =    gfx tests for ftest
   d    14 bit offset for single precision FP long load/store.
   #    14 bit offset for double precision FP load long/store.
   J    Yet another 14 bit offset for load/store with ma,mb completers.
   K    Yet another 14 bit offset for load/store with ma,mb completers.
   y    16 bit offset for word aligned load/store (PA2.0 wide).
   &    16 bit offset for dword aligned load/store (PA2.0 wide).
   <    16 bit offset for load/store with ma,mb completers (PA2.0 wide).
   >    16 bit offset for load/store with ma,mb completers (PA2.0 wide).
   Y    %sr0,%r31 -- implicit target of be,l instruction.
   @	implicit immediate value of 0

Completer operands all have 'c' as the prefix:

   cx   indexed load and store completer.
   cX   indexed load and store completer.  Like cx, but emits a space
	after in disassembler.
   cm   short load and store completer.
   cM   short load and store completer.  Like cm, but emits a space
        after in disassembler.
   cq   long load and store completer (like cm, but inserted into a
	different location in the target instruction).
   cs   store bytes short completer.
   cA   store bytes short completer.  Like cs, but emits a space
        after in disassembler.
   ce   long load/store completer for LDW/STW with a different encoding
	than the others
   cc   load cache control hint
   cd   load and clear cache control hint
   cC   store cache control hint
   co	ordered access

   cp	branch link and push completer
   cP	branch pop completer
   cl	branch link completer
   cg	branch gate completer

   cw	read/write completer for PROBE
   cW	wide completer for MFCTL
   cL	local processor completer for cache control
   cZ   System Control Completer (to support LPA, LHA, etc.)

   ci	correction completer for DCOR
   ca	add completer
   cy	32 bit add carry completer
   cY	64 bit add carry completer
   cv	signed overflow trap completer
   ct	trap on condition completer for ADDI, SUB
   cT	trap on condition completer for UADDCM
   cb	32 bit borrow completer for SUB
   cB	64 bit borrow completer for SUB

   ch	left/right half completer
   cH	signed/unsigned saturation completer
   cS	signed/unsigned completer at 21
   cz	zero/sign extension completer.
   c*	permutation completer

Condition operands all have '?' as the prefix:

   ?f   Floating point compare conditions (encoded as 5 bits at 31)

   ?a	add conditions
   ?A	64 bit add conditions
   ?@   add branch conditions followed by nullify
   ?d	non-negated add branch conditions
   ?D	negated add branch conditions
   ?w	wide mode non-negated add branch conditions
   ?W	wide mode negated add branch conditions

   ?s   compare/subtract conditions
   ?S	64 bit compare/subtract conditions
   ?t   non-negated compare and branch conditions
   ?n   32 bit compare and branch conditions followed by nullify
   ?N   64 bit compare and branch conditions followed by nullify
   ?Q	64 bit compare and branch conditions for CMPIB instruction

   ?l   logical conditions
   ?L	64 bit logical conditions

   ?b   branch on bit conditions
   ?B	64 bit branch on bit conditions

   ?x   shift/extract/deposit conditions
   ?X	64 bit shift/extract/deposit conditions
   ?y   shift/extract/deposit conditions followed by nullify for conditional
        branches

   ?u   unit conditions
   ?U   64 bit unit conditions

Floating point registers all have 'f' as a prefix:

   ft	target register at 31
   fT	target register with L/R halves at 31
   fa	operand 1 register at 10
   fA   operand 1 register with L/R halves at 10
   fX   Same as fA, except prints a space before register during disasm
   fb	operand 2 register at 15
   fB   operand 2 register with L/R halves at 15
   fC   operand 3 register with L/R halves at 16:18,21:23
   fe   Like fT, but encoding is different.
   fE   Same as fe, except prints a space before register during disasm.
   fx	target register at 15 (only for PA 2.0 long format FLDD/FSTD). 

Float registers for fmpyadd and fmpysub:

   fi	mult operand 1 register at 10
   fj	mult operand 2 register at 15
   fk	mult target register at 20
   fl	add/sub operand register at 25
   fm	add/sub target register at 31

*/


#if 0
/* List of characters not to put a space after.  Note that
   "," is included, as the "spopN" operations use literal
   commas in their completer sections.  */
static const char *const completer_chars = ",CcY<>?!@+&U~FfGHINnOoZMadu|/=0123%e$m}";
#endif

/* The order of the opcodes in this table is significant:

   * The assembler requires that all instances of the same mnemonic be
     consecutive.  If they aren't, the assembler will bomb at runtime.

   * Immediate fields use pa_get_absolute_expression to parse the
     string.  It will generate a "bad expression" error if passed
     a register name.  Thus, register index variants of an opcode
     need to precede immediate variants.

   * The disassembler does not care about the order of the opcodes
     except in cases where implicit addressing is used.

   Here are the rules for ordering the opcodes of a mnemonic:

   1) Opcodes with FLAG_STRICT should precede opcodes without
      FLAG_STRICT.

   2) Opcodes with FLAG_STRICT should be ordered as follows:
      register index opcodes, short immediate opcodes, and finally
      long immediate opcodes.  When both pa10 and pa11 variants
      of the same opcode are available, the pa10 opcode should
      come first for correct architectural promotion.

   3) When implicit addressing is available for an opcode, the
      implicit opcode should precede the explicit opcode.

   4) Opcodes without FLAG_STRICT should be ordered as follows:
      register index opcodes, long immediate opcodes, and finally
      short immediate opcodes.  */
	
static const struct pa_opcode pa_opcodes[] =
{

/* Pseudo-instructions.  */

{ "ldi",	0x34000000, 0xffe00000, "l,x", pa20w, 0},/* ldo val(r0),r */
{ "ldi",	0x34000000, 0xffe0c000, "j,x", pa10, 0},/* ldo val(r0),r */

{ "cmpib",	0xec000000, 0xfc000000, "?Qn5,b,w", pa20, FLAG_STRICT},
{ "cmpib", 	0x84000000, 0xf4000000, "?nn5,b,w", pa10, FLAG_STRICT},
{ "comib", 	0x84000000, 0xfc000000, "?nn5,b,w", pa10, 0}, /* comib{tf}*/
/* This entry is for the disassembler only.  It will never be used by
   assembler.  */
{ "comib", 	0x8c000000, 0xfc000000, "?nn5,b,w", pa10, 0}, /* comib{tf}*/
{ "cmpb",	0x9c000000, 0xdc000000, "?Nnx,b,w", pa20, FLAG_STRICT},
{ "cmpb",	0x80000000, 0xf4000000, "?nnx,b,w", pa10, FLAG_STRICT},
{ "comb",	0x80000000, 0xfc000000, "?nnx,b,w", pa10, 0}, /* comb{tf} */
/* This entry is for the disassembler only.  It will never be used by
   assembler.  */
{ "comb",	0x88000000, 0xfc000000, "?nnx,b,w", pa10, 0}, /* comb{tf} */
{ "addb",	0xa0000000, 0xf4000000, "?Wnx,b,w", pa20w, FLAG_STRICT},
{ "addb",	0xa0000000, 0xfc000000, "?@nx,b,w", pa10, 0}, /* addb{tf} */
/* This entry is for the disassembler only.  It will never be used by
   assembler.  */
{ "addb",	0xa8000000, 0xfc000000, "?@nx,b,w", pa10, 0},
{ "addib",	0xa4000000, 0xf4000000, "?Wn5,b,w", pa20w, FLAG_STRICT},
{ "addib",	0xa4000000, 0xfc000000, "?@n5,b,w", pa10, 0}, /* addib{tf}*/
/* This entry is for the disassembler only.  It will never be used by
   assembler.  */
{ "addib",	0xac000000, 0xfc000000, "?@n5,b,w", pa10, 0}, /* addib{tf}*/
{ "nop",	0x08000240, 0xffffffff, "", pa10, 0},      /* or 0,0,0 */
{ "copy",	0x08000240, 0xffe0ffe0, "x,t", pa10, 0},   /* or r,0,t */
{ "mtsar",	0x01601840, 0xffe0ffff, "x", pa10, 0}, /* mtctl r,cr11 */

/* Loads and Stores for integer registers.  */

{ "ldd",	0x0c0000c0, 0xfc00d3c0, "cxccx(b),t", pa20, FLAG_STRICT},
{ "ldd",	0x0c0000c0, 0xfc0013c0, "cxccx(s,b),t", pa20, FLAG_STRICT},
{ "ldd",	0x0c0010e0, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldd",	0x0c0010e0, 0xfc1f33e0, "cocc@(s,b),t", pa20, FLAG_STRICT},
{ "ldd",	0x0c0010c0, 0xfc00d3c0, "cmcc5(b),t", pa20, FLAG_STRICT},
{ "ldd",	0x0c0010c0, 0xfc0013c0, "cmcc5(s,b),t", pa20, FLAG_STRICT},
{ "ldd",	0x50000000, 0xfc000002, "cq&(b),x", pa20w, FLAG_STRICT},
{ "ldd",	0x50000000, 0xfc00c002, "cq#(b),x", pa20, FLAG_STRICT},
{ "ldd",	0x50000000, 0xfc000002, "cq#(s,b),x", pa20, FLAG_STRICT},
{ "ldw",	0x0c000080, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldw",	0x0c000080, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldw",	0x0c000080, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldw",	0x0c000080, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldw",	0x0c0010a0, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldw",	0x0c0010a0, 0xfc1f33e0, "cocc@(s,b),t", pa20, FLAG_STRICT},
{ "ldw",	0x0c001080, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldw",	0x0c001080, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldw",	0x0c001080, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldw",	0x0c001080, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldw",	0x4c000000, 0xfc000000, "ce<(b),x", pa20w, FLAG_STRICT},
{ "ldw",	0x5c000004, 0xfc000006, "ce>(b),x", pa20w, FLAG_STRICT},
{ "ldw",	0x48000000, 0xfc000000, "l(b),x", pa20w, FLAG_STRICT},
{ "ldw",	0x5c000004, 0xfc00c006, "ceK(b),x", pa20, FLAG_STRICT},
{ "ldw",	0x5c000004, 0xfc000006, "ceK(s,b),x", pa20, FLAG_STRICT},
{ "ldw",	0x4c000000, 0xfc00c000, "ceJ(b),x", pa10, FLAG_STRICT},
{ "ldw",	0x4c000000, 0xfc000000, "ceJ(s,b),x", pa10, FLAG_STRICT},
{ "ldw",	0x48000000, 0xfc00c000, "j(b),x", pa10, 0},
{ "ldw",	0x48000000, 0xfc000000, "j(s,b),x", pa10, 0},
{ "ldh",	0x0c000040, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldh",	0x0c000040, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldh",	0x0c000040, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldh",	0x0c000040, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldh",	0x0c001060, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldh",	0x0c001060, 0xfc1f33e0, "cocc@(s,b),t", pa20, FLAG_STRICT},
{ "ldh",	0x0c001040, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldh",	0x0c001040, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldh",	0x0c001040, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldh",	0x0c001040, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldh",	0x44000000, 0xfc000000, "l(b),x", pa20w, FLAG_STRICT},
{ "ldh",	0x44000000, 0xfc00c000, "j(b),x", pa10, 0},
{ "ldh",	0x44000000, 0xfc000000, "j(s,b),x", pa10, 0},
{ "ldb",	0x0c000000, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldb",	0x0c000000, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldb",	0x0c000000, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldb",	0x0c000000, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldb",	0x0c001020, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldb",	0x0c001020, 0xfc1f33e0, "cocc@(s,b),t", pa20, FLAG_STRICT},
{ "ldb",	0x0c001000, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldb",	0x0c001000, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldb",	0x0c001000, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldb",	0x0c001000, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldb",	0x40000000, 0xfc000000, "l(b),x", pa20w, FLAG_STRICT},
{ "ldb",	0x40000000, 0xfc00c000, "j(b),x", pa10, 0},
{ "ldb",	0x40000000, 0xfc000000, "j(s,b),x", pa10, 0},
{ "std",	0x0c0012e0, 0xfc00f3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "std",	0x0c0012e0, 0xfc0033ff, "cocCx,@(s,b)", pa20, FLAG_STRICT},
{ "std",	0x0c0012c0, 0xfc00d3c0, "cmcCx,V(b)", pa20, FLAG_STRICT},
{ "std",	0x0c0012c0, 0xfc0013c0, "cmcCx,V(s,b)", pa20, FLAG_STRICT},
{ "std",	0x70000000, 0xfc000002, "cqx,&(b)", pa20w, FLAG_STRICT},
{ "std",	0x70000000, 0xfc00c002, "cqx,#(b)", pa20, FLAG_STRICT},
{ "std",	0x70000000, 0xfc000002, "cqx,#(s,b)", pa20, FLAG_STRICT},
{ "stw",	0x0c0012a0, 0xfc00f3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "stw",	0x0c0012a0, 0xfc0033ff, "cocCx,@(s,b)", pa20, FLAG_STRICT},
{ "stw",	0x0c001280, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stw",	0x0c001280, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "stw",	0x0c001280, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stw",	0x0c001280, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "stw",	0x6c000000, 0xfc000000, "cex,<(b)", pa20w, FLAG_STRICT},
{ "stw",	0x7c000004, 0xfc000006, "cex,>(b)", pa20w, FLAG_STRICT},
{ "stw",	0x68000000, 0xfc000000, "x,l(b)", pa20w, FLAG_STRICT},
{ "stw",	0x7c000004, 0xfc00c006, "cex,K(b)", pa20, FLAG_STRICT},
{ "stw",	0x7c000004, 0xfc000006, "cex,K(s,b)", pa20, FLAG_STRICT},
{ "stw",	0x6c000000, 0xfc00c000, "cex,J(b)", pa10, FLAG_STRICT},
{ "stw",	0x6c000000, 0xfc000000, "cex,J(s,b)", pa10, FLAG_STRICT},
{ "stw",	0x68000000, 0xfc00c000, "x,j(b)", pa10, 0},
{ "stw",	0x68000000, 0xfc000000, "x,j(s,b)", pa10, 0},
{ "sth",	0x0c001260, 0xfc00f3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "sth",	0x0c001260, 0xfc0033ff, "cocCx,@(s,b)", pa20, FLAG_STRICT},
{ "sth",	0x0c001240, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "sth",	0x0c001240, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "sth",	0x0c001240, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "sth",	0x0c001240, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "sth",	0x64000000, 0xfc000000, "x,l(b)", pa20w, FLAG_STRICT},
{ "sth",	0x64000000, 0xfc00c000, "x,j(b)", pa10, 0},
{ "sth",	0x64000000, 0xfc000000, "x,j(s,b)", pa10, 0},
{ "stb",	0x0c001220, 0xfc00f3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "stb",	0x0c001220, 0xfc0033ff, "cocCx,@(s,b)", pa20, FLAG_STRICT},
{ "stb",	0x0c001200, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stb",	0x0c001200, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "stb",	0x0c001200, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stb",	0x0c001200, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "stb",	0x60000000, 0xfc000000, "x,l(b)", pa20w, FLAG_STRICT},
{ "stb",	0x60000000, 0xfc00c000, "x,j(b)", pa10, 0},
{ "stb",	0x60000000, 0xfc000000, "x,j(s,b)", pa10, 0},
{ "ldwm",	0x4c000000, 0xfc00c000, "j(b),x", pa10, 0},
{ "ldwm",	0x4c000000, 0xfc000000, "j(s,b),x", pa10, 0},
{ "stwm",	0x6c000000, 0xfc00c000, "x,j(b)", pa10, 0},
{ "stwm",	0x6c000000, 0xfc000000, "x,j(s,b)", pa10, 0},
{ "ldwx",	0x0c000080, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldwx",	0x0c000080, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldwx",	0x0c000080, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldwx",	0x0c000080, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldwx",	0x0c000080, 0xfc00dfc0, "cXx(b),t", pa10, 0},
{ "ldwx",	0x0c000080, 0xfc001fc0, "cXx(s,b),t", pa10, 0},
{ "ldhx",	0x0c000040, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldhx",	0x0c000040, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldhx",	0x0c000040, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldhx",	0x0c000040, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldhx",	0x0c000040, 0xfc00dfc0, "cXx(b),t", pa10, 0},
{ "ldhx",	0x0c000040, 0xfc001fc0, "cXx(s,b),t", pa10, 0},
{ "ldbx",	0x0c000000, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldbx",	0x0c000000, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldbx",	0x0c000000, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldbx",	0x0c000000, 0xfc0013c0, "cxccx(s,b),t", pa11, FLAG_STRICT},
{ "ldbx",	0x0c000000, 0xfc00dfc0, "cXx(b),t", pa10, 0},
{ "ldbx",	0x0c000000, 0xfc001fc0, "cXx(s,b),t", pa10, 0},
{ "ldwa",	0x0c000180, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldwa",	0x0c000180, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldwa",	0x0c0011a0, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldwa",	0x0c001180, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldwa",	0x0c001180, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldcw",	0x0c0001c0, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldcw",	0x0c0001c0, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldcw",	0x0c0001c0, 0xfc00d3c0, "cxcdx(b),t", pa11, FLAG_STRICT},
{ "ldcw",	0x0c0001c0, 0xfc0013c0, "cxcdx(s,b),t", pa11, FLAG_STRICT},
{ "ldcw",	0x0c0011c0, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldcw",	0x0c0011c0, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldcw",	0x0c0011c0, 0xfc00d3c0, "cmcd5(b),t", pa11, FLAG_STRICT},
{ "ldcw",	0x0c0011c0, 0xfc0013c0, "cmcd5(s,b),t", pa11, FLAG_STRICT},
{ "stwa",	0x0c0013a0, 0xfc00d3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "stwa",	0x0c001380, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stwa",	0x0c001380, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stby",	0x0c001300, 0xfc00dfc0, "cAx,V(b)", pa10, FLAG_STRICT},
{ "stby",	0x0c001300, 0xfc001fc0, "cAx,V(s,b)", pa10, FLAG_STRICT},
{ "stby",	0x0c001300, 0xfc00d3c0, "cscCx,V(b)", pa11, FLAG_STRICT},
{ "stby",	0x0c001300, 0xfc0013c0, "cscCx,V(s,b)", pa11, FLAG_STRICT},
{ "ldda",	0x0c000100, 0xfc00d3c0, "cxccx(b),t", pa20, FLAG_STRICT},
{ "ldda",	0x0c001120, 0xfc1ff3e0, "cocc@(b),t", pa20, FLAG_STRICT},
{ "ldda",	0x0c001100, 0xfc00d3c0, "cmcc5(b),t", pa20, FLAG_STRICT},
{ "ldcd",	0x0c000140, 0xfc00d3c0, "cxcdx(b),t", pa20, FLAG_STRICT},
{ "ldcd",	0x0c000140, 0xfc0013c0, "cxcdx(s,b),t", pa20, FLAG_STRICT},
{ "ldcd",	0x0c001140, 0xfc00d3c0, "cmcd5(b),t", pa20, FLAG_STRICT},
{ "ldcd",	0x0c001140, 0xfc0013c0, "cmcd5(s,b),t", pa20, FLAG_STRICT},
{ "stda",	0x0c0013e0, 0xfc00f3ff, "cocCx,@(b)", pa20, FLAG_STRICT},
{ "stda",	0x0c0013c0, 0xfc00d3c0, "cmcCx,V(b)", pa20, FLAG_STRICT},
{ "ldwax",	0x0c000180, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldwax",	0x0c000180, 0xfc00d3c0, "cxccx(b),t", pa11, FLAG_STRICT},
{ "ldwax",	0x0c000180, 0xfc00dfc0, "cXx(b),t", pa10, 0},
{ "ldcwx",	0x0c0001c0, 0xfc00dfc0, "cXx(b),t", pa10, FLAG_STRICT},
{ "ldcwx",	0x0c0001c0, 0xfc001fc0, "cXx(s,b),t", pa10, FLAG_STRICT},
{ "ldcwx",	0x0c0001c0, 0xfc00d3c0, "cxcdx(b),t", pa11, FLAG_STRICT},
{ "ldcwx",	0x0c0001c0, 0xfc0013c0, "cxcdx(s,b),t", pa11, FLAG_STRICT},
{ "ldcwx",	0x0c0001c0, 0xfc00dfc0, "cXx(b),t", pa10, 0},
{ "ldcwx",	0x0c0001c0, 0xfc001fc0, "cXx(s,b),t", pa10, 0},
{ "ldws",	0x0c001080, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldws",	0x0c001080, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldws",	0x0c001080, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldws",	0x0c001080, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldws",	0x0c001080, 0xfc00dfc0, "cM5(b),t", pa10, 0},
{ "ldws",	0x0c001080, 0xfc001fc0, "cM5(s,b),t", pa10, 0},
{ "ldhs",	0x0c001040, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldhs",	0x0c001040, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldhs",	0x0c001040, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldhs",	0x0c001040, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldhs",	0x0c001040, 0xfc00dfc0, "cM5(b),t", pa10, 0},
{ "ldhs",	0x0c001040, 0xfc001fc0, "cM5(s,b),t", pa10, 0},
{ "ldbs",	0x0c001000, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldbs",	0x0c001000, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldbs",	0x0c001000, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldbs",	0x0c001000, 0xfc0013c0, "cmcc5(s,b),t", pa11, FLAG_STRICT},
{ "ldbs",	0x0c001000, 0xfc00dfc0, "cM5(b),t", pa10, 0},
{ "ldbs",	0x0c001000, 0xfc001fc0, "cM5(s,b),t", pa10, 0},
{ "ldwas",	0x0c001180, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldwas",	0x0c001180, 0xfc00d3c0, "cmcc5(b),t", pa11, FLAG_STRICT},
{ "ldwas",	0x0c001180, 0xfc00dfc0, "cM5(b),t", pa10, 0},
{ "ldcws",	0x0c0011c0, 0xfc00dfc0, "cM5(b),t", pa10, FLAG_STRICT},
{ "ldcws",	0x0c0011c0, 0xfc001fc0, "cM5(s,b),t", pa10, FLAG_STRICT},
{ "ldcws",	0x0c0011c0, 0xfc00d3c0, "cmcd5(b),t", pa11, FLAG_STRICT},
{ "ldcws",	0x0c0011c0, 0xfc0013c0, "cmcd5(s,b),t", pa11, FLAG_STRICT},
{ "ldcws",	0x0c0011c0, 0xfc00dfc0, "cM5(b),t", pa10, 0},
{ "ldcws",	0x0c0011c0, 0xfc001fc0, "cM5(s,b),t", pa10, 0},
{ "stws",	0x0c001280, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stws",	0x0c001280, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "stws",	0x0c001280, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stws",	0x0c001280, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "stws",	0x0c001280, 0xfc00dfc0, "cMx,V(b)", pa10, 0},
{ "stws",	0x0c001280, 0xfc001fc0, "cMx,V(s,b)", pa10, 0},
{ "sths",	0x0c001240, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "sths",	0x0c001240, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "sths",	0x0c001240, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "sths",	0x0c001240, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "sths",	0x0c001240, 0xfc00dfc0, "cMx,V(b)", pa10, 0},
{ "sths",	0x0c001240, 0xfc001fc0, "cMx,V(s,b)", pa10, 0},
{ "stbs",	0x0c001200, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stbs",	0x0c001200, 0xfc001fc0, "cMx,V(s,b)", pa10, FLAG_STRICT},
{ "stbs",	0x0c001200, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stbs",	0x0c001200, 0xfc0013c0, "cmcCx,V(s,b)", pa11, FLAG_STRICT},
{ "stbs",	0x0c001200, 0xfc00dfc0, "cMx,V(b)", pa10, 0},
{ "stbs",	0x0c001200, 0xfc001fc0, "cMx,V(s,b)", pa10, 0},
{ "stwas",	0x0c001380, 0xfc00dfc0, "cMx,V(b)", pa10, FLAG_STRICT},
{ "stwas",	0x0c001380, 0xfc00d3c0, "cmcCx,V(b)", pa11, FLAG_STRICT},
{ "stwas",	0x0c001380, 0xfc00dfc0, "cMx,V(b)", pa10, 0},
{ "stdby",	0x0c001340, 0xfc00d3c0, "cscCx,V(b)", pa20, FLAG_STRICT},
{ "stdby",	0x0c001340, 0xfc0013c0, "cscCx,V(s,b)", pa20, FLAG_STRICT},
{ "stbys",	0x0c001300, 0xfc00dfc0, "cAx,V(b)", pa10, FLAG_STRICT},
{ "stbys",	0x0c001300, 0xfc001fc0, "cAx,V(s,b)", pa10, FLAG_STRICT},
{ "stbys",	0x0c001300, 0xfc00d3c0, "cscCx,V(b)", pa11, FLAG_STRICT},
{ "stbys",	0x0c001300, 0xfc0013c0, "cscCx,V(s,b)", pa11, FLAG_STRICT},
{ "stbys",	0x0c001300, 0xfc00dfc0, "cAx,V(b)", pa10, 0},
{ "stbys",	0x0c001300, 0xfc001fc0, "cAx,V(s,b)", pa10, 0},

/* Immediate instructions.  */
{ "ldo",	0x34000000, 0xfc000000, "l(b),x", pa20w, 0},
{ "ldo",	0x34000000, 0xfc00c000, "j(b),x", pa10, 0},
{ "ldil",	0x20000000, 0xfc000000, "k,b", pa10, 0},
{ "addil",	0x28000000, 0xfc000000, "k,b,Z", pa10, 0},
{ "addil",	0x28000000, 0xfc000000, "k,b", pa10, 0},

/* Branching instructions.  */
{ "b",		0xe8008000, 0xfc00e000, "cpnXL", pa20, FLAG_STRICT},
{ "b",		0xe800a000, 0xfc00e000, "clnXL", pa20, FLAG_STRICT},
{ "b",		0xe8000000, 0xfc00e000, "clnW,b", pa10, FLAG_STRICT},
{ "b",		0xe8002000, 0xfc00e000, "cgnW,b", pa10, FLAG_STRICT},
{ "b",		0xe8000000, 0xffe0e000, "nW", pa10, 0},  /* b,l foo,r0 */
{ "bl",		0xe8000000, 0xfc00e000, "nW,b", pa10, 0},
{ "gate",	0xe8002000, 0xfc00e000, "nW,b", pa10, 0},
{ "blr",	0xe8004000, 0xfc00e001, "nx,b", pa10, 0},
{ "bv",		0xe800c000, 0xfc00fffd, "nx(b)", pa10, 0},
{ "bv",		0xe800c000, 0xfc00fffd, "n(b)", pa10, 0},
{ "bve",	0xe800f001, 0xfc1ffffd, "cpn(b)L", pa20, FLAG_STRICT},
{ "bve",	0xe800f000, 0xfc1ffffd, "cln(b)L", pa20, FLAG_STRICT},
{ "bve",	0xe800d001, 0xfc1ffffd, "cPn(b)", pa20, FLAG_STRICT},
{ "bve",	0xe800d000, 0xfc1ffffd, "n(b)", pa20, FLAG_STRICT},
{ "be",		0xe4000000, 0xfc000000, "clnz(S,b),Y", pa10, FLAG_STRICT},
{ "be",		0xe4000000, 0xfc000000, "clnz(b),Y", pa10, FLAG_STRICT},
{ "be",		0xe0000000, 0xfc000000, "nz(S,b)", pa10, 0},
{ "be",		0xe0000000, 0xfc000000, "nz(b)", pa10, 0},
{ "ble",	0xe4000000, 0xfc000000, "nz(S,b)", pa10, 0},
{ "movb",	0xc8000000, 0xfc000000, "?ynx,b,w", pa10, 0},
{ "movib",	0xcc000000, 0xfc000000, "?yn5,b,w", pa10, 0},
{ "combt",	0x80000000, 0xfc000000, "?tnx,b,w", pa10, 0},
{ "combf",	0x88000000, 0xfc000000, "?tnx,b,w", pa10, 0},
{ "comibt",	0x84000000, 0xfc000000, "?tn5,b,w", pa10, 0},
{ "comibf",	0x8c000000, 0xfc000000, "?tn5,b,w", pa10, 0},
{ "addbt",	0xa0000000, 0xfc000000, "?dnx,b,w", pa10, 0},
{ "addbf",	0xa8000000, 0xfc000000, "?dnx,b,w", pa10, 0},
{ "addibt",	0xa4000000, 0xfc000000, "?dn5,b,w", pa10, 0},
{ "addibf",	0xac000000, 0xfc000000, "?dn5,b,w", pa10, 0},
{ "bb",		0xc0006000, 0xffe06000, "?Bnx,!,w", pa20, FLAG_STRICT}, 
{ "bb",		0xc0004000, 0xffe06000, "?bnx,!,w", pa10, FLAG_STRICT}, 
{ "bb",		0xc4004000, 0xfc004000, "?Bnx,B,w", pa20, FLAG_STRICT}, 
{ "bb",		0xc4004000, 0xfc006000, "?bnx,Q,w", pa10, FLAG_STRICT}, 
{ "bb",		0xc4004000, 0xfc006000, "?bnx,Q,w", pa10, 0}, 
{ "bvb",	0xc0004000, 0xffe04000, "?bnx,w", pa10, 0},
{ "clrbts",	0xe8004005, 0xffffffff, "", pa20, FLAG_STRICT},
{ "popbts",	0xe8004005, 0xfffff007, "$", pa20, FLAG_STRICT},
{ "pushnom",	0xe8004001, 0xffffffff, "", pa20, FLAG_STRICT},
{ "pushbts",	0xe8004001, 0xffe0ffff, "x", pa20, FLAG_STRICT},

/* Computation Instructions.  */

{ "cmpclr",	0x080008a0, 0xfc000fe0, "?Sx,b,t", pa20, FLAG_STRICT},
{ "cmpclr",	0x08000880, 0xfc000fe0, "?sx,b,t", pa10, FLAG_STRICT},
{ "comclr",	0x08000880, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "or",		0x08000260, 0xfc000fe0, "?Lx,b,t", pa20, FLAG_STRICT},
{ "or",		0x08000240, 0xfc000fe0, "?lx,b,t", pa10, 0},
{ "xor",	0x080002a0, 0xfc000fe0, "?Lx,b,t", pa20, FLAG_STRICT},
{ "xor",	0x08000280, 0xfc000fe0, "?lx,b,t", pa10, 0},
{ "and",	0x08000220, 0xfc000fe0, "?Lx,b,t", pa20, FLAG_STRICT},
{ "and",	0x08000200, 0xfc000fe0, "?lx,b,t", pa10, 0},
{ "andcm",	0x08000020, 0xfc000fe0, "?Lx,b,t", pa20, FLAG_STRICT},
{ "andcm",	0x08000000, 0xfc000fe0, "?lx,b,t", pa10, 0},
{ "uxor",	0x080003a0, 0xfc000fe0, "?Ux,b,t", pa20, FLAG_STRICT},
{ "uxor",	0x08000380, 0xfc000fe0, "?ux,b,t", pa10, 0},
{ "uaddcm",	0x080009a0, 0xfc000fa0, "cT?Ux,b,t", pa20, FLAG_STRICT},
{ "uaddcm",	0x08000980, 0xfc000fa0, "cT?ux,b,t", pa10, FLAG_STRICT},
{ "uaddcm",	0x08000980, 0xfc000fe0, "?ux,b,t", pa10, 0},
{ "uaddcmt",	0x080009c0, 0xfc000fe0, "?ux,b,t", pa10, 0},
{ "dcor",	0x08000ba0, 0xfc1f0fa0, "ci?Ub,t", pa20, FLAG_STRICT},
{ "dcor",	0x08000b80, 0xfc1f0fa0, "ci?ub,t", pa10, FLAG_STRICT},
{ "dcor",	0x08000b80, 0xfc1f0fe0, "?ub,t",   pa10, 0},
{ "idcor",	0x08000bc0, 0xfc1f0fe0, "?ub,t",   pa10, 0},
{ "addi",	0xb0000000, 0xfc000000, "ct?ai,b,x", pa10, FLAG_STRICT},
{ "addi",	0xb4000000, 0xfc000000, "cv?ai,b,x", pa10, FLAG_STRICT},
{ "addi",	0xb4000000, 0xfc000800, "?ai,b,x", pa10, 0},
{ "addio",	0xb4000800, 0xfc000800, "?ai,b,x", pa10, 0},
{ "addit",	0xb0000000, 0xfc000800, "?ai,b,x", pa10, 0},
{ "addito",	0xb0000800, 0xfc000800, "?ai,b,x", pa10, 0},
{ "add",	0x08000720, 0xfc0007e0, "cY?Ax,b,t", pa20, FLAG_STRICT},
{ "add",	0x08000700, 0xfc0007e0, "cy?ax,b,t", pa10, FLAG_STRICT},
{ "add",	0x08000220, 0xfc0003e0, "ca?Ax,b,t", pa20, FLAG_STRICT},
{ "add",	0x08000200, 0xfc0003e0, "ca?ax,b,t", pa10, FLAG_STRICT},
{ "add",	0x08000600, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "addl",	0x08000a00, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "addo",	0x08000e00, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "addc",	0x08000700, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "addco",	0x08000f00, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sub",	0x080004e0, 0xfc0007e0, "ct?Sx,b,t", pa20, FLAG_STRICT},
{ "sub",	0x080004c0, 0xfc0007e0, "ct?sx,b,t", pa10, FLAG_STRICT},
{ "sub",	0x08000520, 0xfc0007e0, "cB?Sx,b,t", pa20, FLAG_STRICT},
{ "sub",	0x08000500, 0xfc0007e0, "cb?sx,b,t", pa10, FLAG_STRICT},
{ "sub",	0x08000420, 0xfc0007e0, "cv?Sx,b,t", pa20, FLAG_STRICT},
{ "sub",	0x08000400, 0xfc0007e0, "cv?sx,b,t", pa10, FLAG_STRICT},
{ "sub",	0x08000400, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subo",	0x08000c00, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subb",	0x08000500, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subbo",	0x08000d00, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subt",	0x080004c0, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subto",	0x08000cc0, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "ds",		0x08000440, 0xfc000fe0, "?sx,b,t", pa10, 0},
{ "subi",	0x94000000, 0xfc000000, "cv?si,b,x", pa10, FLAG_STRICT},
{ "subi",	0x94000000, 0xfc000800, "?si,b,x", pa10, 0},
{ "subio",	0x94000800, 0xfc000800, "?si,b,x", pa10, 0},
{ "cmpiclr",	0x90000800, 0xfc000800, "?Si,b,x", pa20, FLAG_STRICT},
{ "cmpiclr",	0x90000000, 0xfc000800, "?si,b,x", pa10, FLAG_STRICT},
{ "comiclr",	0x90000000, 0xfc000800, "?si,b,x", pa10, 0},
{ "shladd",	0x08000220, 0xfc000320, "ca?Ax,.,b,t", pa20, FLAG_STRICT},
{ "shladd",	0x08000200, 0xfc000320, "ca?ax,.,b,t", pa10, FLAG_STRICT},
{ "sh1add",	0x08000640, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh1addl",	0x08000a40, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh1addo",	0x08000e40, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh2add",	0x08000680, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh2addl",	0x08000a80, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh2addo",	0x08000e80, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh3add",	0x080006c0, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh3addl",	0x08000ac0, 0xfc000fe0, "?ax,b,t", pa10, 0},
{ "sh3addo",	0x08000ec0, 0xfc000fe0, "?ax,b,t", pa10, 0},

/* Subword Operation Instructions.  */

{ "hadd",	0x08000300, 0xfc00ff20, "cHx,b,t", pa20, FLAG_STRICT},
{ "havg",	0x080002c0, 0xfc00ffe0, "x,b,t", pa20, FLAG_STRICT},
{ "hshl",	0xf8008800, 0xffe0fc20, "x,*,t", pa20, FLAG_STRICT},
{ "hshladd",	0x08000700, 0xfc00ff20, "x,.,b,t", pa20, FLAG_STRICT},
{ "hshr",	0xf800c800, 0xfc1ff820, "cSb,*,t", pa20, FLAG_STRICT},
{ "hshradd",	0x08000500, 0xfc00ff20, "x,.,b,t", pa20, FLAG_STRICT},
{ "hsub",	0x08000100, 0xfc00ff20, "cHx,b,t", pa20, FLAG_STRICT},
{ "mixh",	0xf8008400, 0xfc009fe0, "chx,b,t", pa20, FLAG_STRICT},
{ "mixw",	0xf8008000, 0xfc009fe0, "chx,b,t", pa20, FLAG_STRICT},
{ "permh",	0xf8000000, 0xfc009020, "c*a,t", pa20, FLAG_STRICT},


/* Extract and Deposit Instructions.  */

{ "shrpd",	0xd0000200, 0xfc001fe0, "?Xx,b,!,t", pa20, FLAG_STRICT},
{ "shrpd",	0xd0000400, 0xfc001400, "?Xx,b,~,t", pa20, FLAG_STRICT},
{ "shrpw",	0xd0000000, 0xfc001fe0, "?xx,b,!,t", pa10, FLAG_STRICT},
{ "shrpw",	0xd0000800, 0xfc001c00, "?xx,b,p,t", pa10, FLAG_STRICT},
{ "vshd",	0xd0000000, 0xfc001fe0, "?xx,b,t", pa10, 0},
{ "shd",	0xd0000800, 0xfc001c00, "?xx,b,p,t", pa10, 0},
{ "extrd",	0xd0001200, 0xfc001ae0, "cS?Xb,!,%,x", pa20, FLAG_STRICT},
{ "extrd",	0xd8000000, 0xfc000000, "cS?Xb,q,|,x", pa20, FLAG_STRICT},
{ "extrw",	0xd0001000, 0xfc001be0, "cS?xb,!,T,x", pa10, FLAG_STRICT},
{ "extrw",	0xd0001800, 0xfc001800, "cS?xb,P,T,x", pa10, FLAG_STRICT},
{ "vextru",	0xd0001000, 0xfc001fe0, "?xb,T,x", pa10, 0},
{ "vextrs",	0xd0001400, 0xfc001fe0, "?xb,T,x", pa10, 0},
{ "extru",	0xd0001800, 0xfc001c00, "?xb,P,T,x", pa10, 0},
{ "extrs",	0xd0001c00, 0xfc001c00, "?xb,P,T,x", pa10, 0},
{ "depd",	0xd4000200, 0xfc001ae0, "cz?Xx,!,%,b", pa20, FLAG_STRICT},
{ "depd",	0xf0000000, 0xfc000000, "cz?Xx,~,|,b", pa20, FLAG_STRICT},
{ "depdi",	0xd4001200, 0xfc001ae0, "cz?X5,!,%,b", pa20, FLAG_STRICT},
{ "depdi",	0xf4000000, 0xfc000000, "cz?X5,~,|,b", pa20, FLAG_STRICT},
{ "depw",	0xd4000000, 0xfc001be0, "cz?xx,!,T,b", pa10, FLAG_STRICT},
{ "depw",	0xd4000800, 0xfc001800, "cz?xx,p,T,b", pa10, FLAG_STRICT},
{ "depwi",	0xd4001000, 0xfc001be0, "cz?x5,!,T,b", pa10, FLAG_STRICT},
{ "depwi",	0xd4001800, 0xfc001800, "cz?x5,p,T,b", pa10, FLAG_STRICT},
{ "zvdep",	0xd4000000, 0xfc001fe0, "?xx,T,b", pa10, 0},
{ "vdep",	0xd4000400, 0xfc001fe0, "?xx,T,b", pa10, 0},
{ "zdep",	0xd4000800, 0xfc001c00, "?xx,p,T,b", pa10, 0},
{ "dep",	0xd4000c00, 0xfc001c00, "?xx,p,T,b", pa10, 0},
{ "zvdepi",	0xd4001000, 0xfc001fe0, "?x5,T,b", pa10, 0},
{ "vdepi",	0xd4001400, 0xfc001fe0, "?x5,T,b", pa10, 0},
{ "zdepi",	0xd4001800, 0xfc001c00, "?x5,p,T,b", pa10, 0},
{ "depi",	0xd4001c00, 0xfc001c00, "?x5,p,T,b", pa10, 0},

/* System Control Instructions.  */

{ "break",	0x00000000, 0xfc001fe0, "r,A", pa10, 0},
{ "rfi",	0x00000c00, 0xffffff1f, "cr", pa10, FLAG_STRICT},
{ "rfi",	0x00000c00, 0xffffffff, "", pa10, 0},
{ "rfir",	0x00000ca0, 0xffffffff, "", pa11, 0},
{ "ssm",	0x00000d60, 0xfc00ffe0, "U,t", pa20, FLAG_STRICT},
{ "ssm",	0x00000d60, 0xffe0ffe0, "R,t", pa10, 0},
{ "rsm",	0x00000e60, 0xfc00ffe0, "U,t", pa20, FLAG_STRICT},
{ "rsm",	0x00000e60, 0xffe0ffe0, "R,t", pa10, 0},
{ "mtsm",	0x00001860, 0xffe0ffff, "x", pa10, 0},
{ "ldsid",	0x000010a0, 0xfc1fffe0, "(b),t", pa10, 0},
{ "ldsid",	0x000010a0, 0xfc1f3fe0, "(s,b),t", pa10, 0},
{ "mtsp",	0x00001820, 0xffe01fff, "x,S", pa10, 0},
{ "mtctl",	0x00001840, 0xfc00ffff, "x,^", pa10, 0},
{ "mtsarcm",	0x016018C0, 0xffe0ffff, "x", pa20, FLAG_STRICT},
{ "mfia",	0x000014A0, 0xffffffe0, "t", pa20, FLAG_STRICT},
{ "mfsp",	0x000004a0, 0xffff1fe0, "S,t", pa10, 0},
{ "mfctl",	0x016048a0, 0xffffffe0, "cW!,t", pa20, FLAG_STRICT},
{ "mfctl",	0x000008a0, 0xfc1fffe0, "^,t", pa10, 0},
{ "sync",	0x00000400, 0xffffffff, "", pa10, 0},
{ "syncdma",	0x00100400, 0xffffffff, "", pa10, 0},
{ "probe",	0x04001180, 0xfc00ffa0, "cw(b),x,t", pa10, FLAG_STRICT},
{ "probe",	0x04001180, 0xfc003fa0, "cw(s,b),x,t", pa10, FLAG_STRICT},
{ "probei",	0x04003180, 0xfc00ffa0, "cw(b),R,t", pa10, FLAG_STRICT},
{ "probei",	0x04003180, 0xfc003fa0, "cw(s,b),R,t", pa10, FLAG_STRICT},
{ "prober",	0x04001180, 0xfc00ffe0, "(b),x,t", pa10, 0},
{ "prober",	0x04001180, 0xfc003fe0, "(s,b),x,t", pa10, 0},
{ "proberi",	0x04003180, 0xfc00ffe0, "(b),R,t", pa10, 0},
{ "proberi",	0x04003180, 0xfc003fe0, "(s,b),R,t", pa10, 0},
{ "probew",	0x040011c0, 0xfc00ffe0, "(b),x,t", pa10, 0},
{ "probew",	0x040011c0, 0xfc003fe0, "(s,b),x,t", pa10, 0},
{ "probewi",	0x040031c0, 0xfc00ffe0, "(b),R,t", pa10, 0},
{ "probewi",	0x040031c0, 0xfc003fe0, "(s,b),R,t", pa10, 0},
{ "lpa",	0x04001340, 0xfc00ffc0, "cZx(b),t", pa10, 0},
{ "lpa",	0x04001340, 0xfc003fc0, "cZx(s,b),t", pa10, 0},
{ "lci",	0x04001300, 0xfc00ffe0, "x(b),t", pa11, 0},
{ "lci",	0x04001300, 0xfc003fe0, "x(s,b),t", pa11, 0},
{ "pdtlb",	0x04001600, 0xfc00ffdf, "cLcZx(b)", pa20, FLAG_STRICT},
{ "pdtlb",	0x04001600, 0xfc003fdf, "cLcZx(s,b)", pa20, FLAG_STRICT},
{ "pdtlb",	0x04001600, 0xfc1fffdf, "cLcZ@(b)", pa20, FLAG_STRICT},
{ "pdtlb",	0x04001600, 0xfc1f3fdf, "cLcZ@(s,b)", pa20, FLAG_STRICT},
{ "pdtlb",	0x04001200, 0xfc00ffdf, "cZx(b)", pa10, 0},
{ "pdtlb",	0x04001200, 0xfc003fdf, "cZx(s,b)", pa10, 0},
{ "pitlb",	0x04000600, 0xfc001fdf, "cLcZx(S,b)", pa20, FLAG_STRICT},
{ "pitlb",	0x04000600, 0xfc1f1fdf, "cLcZ@(S,b)", pa20, FLAG_STRICT},
{ "pitlb",	0x04000200, 0xfc001fdf, "cZx(S,b)", pa10, 0},
{ "pdtlbe",	0x04001240, 0xfc00ffdf, "cZx(b)", pa10, 0},
{ "pdtlbe",	0x04001240, 0xfc003fdf, "cZx(s,b)", pa10, 0},
{ "pitlbe",	0x04000240, 0xfc001fdf, "cZx(S,b)", pa10, 0},
{ "idtlba",	0x04001040, 0xfc00ffff, "x,(b)", pa10, 0},
{ "idtlba",	0x04001040, 0xfc003fff, "x,(s,b)", pa10, 0},
{ "iitlba",	0x04000040, 0xfc001fff, "x,(S,b)", pa10, 0},
{ "idtlbp",	0x04001000, 0xfc00ffff, "x,(b)", pa10, 0},
{ "idtlbp",	0x04001000, 0xfc003fff, "x,(s,b)", pa10, 0},
{ "iitlbp",	0x04000000, 0xfc001fff, "x,(S,b)", pa10, 0},
{ "pdc",	0x04001380, 0xfc00ffdf, "cZx(b)", pa10, 0},
{ "pdc",	0x04001380, 0xfc003fdf, "cZx(s,b)", pa10, 0},
{ "fdc",	0x04001280, 0xfc00ffdf, "cZx(b)", pa10, FLAG_STRICT},
{ "fdc",	0x04001280, 0xfc003fdf, "cZx(s,b)", pa10, FLAG_STRICT},
{ "fdc",	0x04003280, 0xfc00ffff, "5(b)", pa20, FLAG_STRICT},
{ "fdc",	0x04003280, 0xfc003fff, "5(s,b)", pa20, FLAG_STRICT},
{ "fdc",	0x04001280, 0xfc00ffdf, "cZx(b)", pa10, 0},
{ "fdc",	0x04001280, 0xfc003fdf, "cZx(s,b)", pa10, 0},
{ "fic",	0x040013c0, 0xfc00dfdf, "cZx(b)", pa20, FLAG_STRICT},
{ "fic",	0x04000280, 0xfc001fdf, "cZx(S,b)", pa10, 0},
{ "fdce",	0x040012c0, 0xfc00ffdf, "cZx(b)", pa10, 0},
{ "fdce",	0x040012c0, 0xfc003fdf, "cZx(s,b)", pa10, 0},
{ "fice",	0x040002c0, 0xfc001fdf, "cZx(S,b)", pa10, 0},
{ "diag",	0x14000000, 0xfc000000, "D", pa10, 0},
{ "idtlbt",	0x04001800, 0xfc00ffff, "x,b", pa20, FLAG_STRICT},
{ "iitlbt",	0x04000800, 0xfc00ffff, "x,b", pa20, FLAG_STRICT},

/* These may be specific to certain versions of the PA.  Joel claimed
   they were 72000 (7200?) specific.  However, I'm almost certain the
   mtcpu/mfcpu were undocumented, but available in the older 700 machines.  */
{ "mtcpu",	0x14001600, 0xfc00ffff, "x,^", pa10, 0},
{ "mfcpu",	0x14001A00, 0xfc00ffff, "^,x", pa10, 0},
{ "tocen",	0x14403600, 0xffffffff, "", pa10, 0},
{ "tocdis",	0x14401620, 0xffffffff, "", pa10, 0},
{ "shdwgr",	0x14402600, 0xffffffff, "", pa10, 0},
{ "grshdw",	0x14400620, 0xffffffff, "", pa10, 0},

/* gfw and gfr are not in the HP PA 1.1 manual, but they are in either
   the Timex FPU or the Mustang ERS (not sure which) manual.  */
{ "gfw",	0x04001680, 0xfc00ffdf, "cZx(b)", pa11, 0},
{ "gfw",	0x04001680, 0xfc003fdf, "cZx(s,b)", pa11, 0},
{ "gfr",	0x04001a80, 0xfc00ffdf, "cZx(b)", pa11, 0},
{ "gfr",	0x04001a80, 0xfc003fdf, "cZx(s,b)", pa11, 0},

/* Floating Point Coprocessor Instructions.  */
 
{ "fldw",	0x24000000, 0xfc00df80, "cXx(b),fT", pa10, FLAG_STRICT},
{ "fldw",	0x24000000, 0xfc001f80, "cXx(s,b),fT", pa10, FLAG_STRICT},
{ "fldw",	0x24000000, 0xfc00d380, "cxccx(b),fT", pa11, FLAG_STRICT},
{ "fldw",	0x24000000, 0xfc001380, "cxccx(s,b),fT", pa11, FLAG_STRICT},
{ "fldw",	0x24001020, 0xfc1ff3a0, "cocc@(b),fT", pa20, FLAG_STRICT},
{ "fldw",	0x24001020, 0xfc1f33a0, "cocc@(s,b),fT", pa20, FLAG_STRICT},
{ "fldw",	0x24001000, 0xfc00df80, "cM5(b),fT", pa10, FLAG_STRICT},
{ "fldw",	0x24001000, 0xfc001f80, "cM5(s,b),fT", pa10, FLAG_STRICT},
{ "fldw",	0x24001000, 0xfc00d380, "cmcc5(b),fT", pa11, FLAG_STRICT},
{ "fldw",	0x24001000, 0xfc001380, "cmcc5(s,b),fT", pa11, FLAG_STRICT},
{ "fldw",	0x5c000000, 0xfc000004, "y(b),fe", pa20w, FLAG_STRICT},
{ "fldw",	0x58000000, 0xfc000000, "cJy(b),fe", pa20w, FLAG_STRICT},
{ "fldw",	0x5c000000, 0xfc00c004, "d(b),fe", pa20, FLAG_STRICT},
{ "fldw",	0x5c000000, 0xfc000004, "d(s,b),fe", pa20, FLAG_STRICT},
{ "fldw",	0x58000000, 0xfc00c000, "cJd(b),fe", pa20, FLAG_STRICT},
{ "fldw",	0x58000000, 0xfc000000, "cJd(s,b),fe", pa20, FLAG_STRICT},
{ "fldd",	0x2c000000, 0xfc00dfc0, "cXx(b),ft", pa10, FLAG_STRICT},
{ "fldd",	0x2c000000, 0xfc001fc0, "cXx(s,b),ft", pa10, FLAG_STRICT},
{ "fldd",	0x2c000000, 0xfc00d3c0, "cxccx(b),ft", pa11, FLAG_STRICT},
{ "fldd",	0x2c000000, 0xfc0013c0, "cxccx(s,b),ft", pa11, FLAG_STRICT},
{ "fldd",	0x2c001020, 0xfc1ff3e0, "cocc@(b),ft", pa20, FLAG_STRICT},
{ "fldd",	0x2c001020, 0xfc1f33e0, "cocc@(s,b),ft", pa20, FLAG_STRICT},
{ "fldd",	0x2c001000, 0xfc00dfc0, "cM5(b),ft", pa10, FLAG_STRICT},
{ "fldd",	0x2c001000, 0xfc001fc0, "cM5(s,b),ft", pa10, FLAG_STRICT},
{ "fldd",	0x2c001000, 0xfc00d3c0, "cmcc5(b),ft", pa11, FLAG_STRICT},
{ "fldd",	0x2c001000, 0xfc0013c0, "cmcc5(s,b),ft", pa11, FLAG_STRICT},
{ "fldd",	0x50000002, 0xfc000002, "cq&(b),fx", pa20w, FLAG_STRICT},
{ "fldd",	0x50000002, 0xfc00c002, "cq#(b),fx", pa20, FLAG_STRICT},
{ "fldd",	0x50000002, 0xfc000002, "cq#(s,b),fx", pa20, FLAG_STRICT},
{ "fstw",	0x24000200, 0xfc00df80, "cXfT,x(b)", pa10, FLAG_STRICT},
{ "fstw",	0x24000200, 0xfc001f80, "cXfT,x(s,b)", pa10, FLAG_STRICT},
{ "fstw",	0x24000200, 0xfc00d380, "cxcCfT,x(b)", pa11, FLAG_STRICT},
{ "fstw",	0x24000200, 0xfc001380, "cxcCfT,x(s,b)", pa11, FLAG_STRICT},
{ "fstw",	0x24001220, 0xfc1ff3a0, "cocCfT,@(b)", pa20, FLAG_STRICT},
{ "fstw",	0x24001220, 0xfc1f33a0, "cocCfT,@(s,b)", pa20, FLAG_STRICT},
{ "fstw",	0x24001200, 0xfc00df80, "cMfT,5(b)", pa10, FLAG_STRICT},
{ "fstw",	0x24001200, 0xfc001f80, "cMfT,5(s,b)", pa10, FLAG_STRICT},
{ "fstw",	0x24001200, 0xfc00df80, "cMfT,5(b)", pa10, FLAG_STRICT},
{ "fstw",	0x24001200, 0xfc001f80, "cMfT,5(s,b)", pa10, FLAG_STRICT},
{ "fstw",	0x7c000000, 0xfc000004, "fE,y(b)", pa20w, FLAG_STRICT},
{ "fstw",	0x78000000, 0xfc000000, "cJfE,y(b)", pa20w, FLAG_STRICT},
{ "fstw",	0x7c000000, 0xfc00c004, "fE,d(b)", pa20, FLAG_STRICT},
{ "fstw",	0x7c000000, 0xfc000004, "fE,d(s,b)", pa20, FLAG_STRICT},
{ "fstw",	0x78000000, 0xfc00c000, "cJfE,d(b)", pa20, FLAG_STRICT},
{ "fstw",	0x78000000, 0xfc000000, "cJfE,d(s,b)", pa20, FLAG_STRICT},
{ "fstd",	0x2c000200, 0xfc00dfc0, "cXft,x(b)", pa10, FLAG_STRICT},
{ "fstd",	0x2c000200, 0xfc001fc0, "cXft,x(s,b)", pa10, FLAG_STRICT},
{ "fstd",	0x2c000200, 0xfc00d3c0, "cxcCft,x(b)", pa11, FLAG_STRICT},
{ "fstd",	0x2c000200, 0xfc0013c0, "cxcCft,x(s,b)", pa11, FLAG_STRICT},
{ "fstd",	0x2c001220, 0xfc1ff3e0, "cocCft,@(b)", pa20, FLAG_STRICT},
{ "fstd",	0x2c001220, 0xfc1f33e0, "cocCft,@(s,b)", pa20, FLAG_STRICT},
{ "fstd",	0x2c001200, 0xfc00dfc0, "cMft,5(b)", pa10, FLAG_STRICT},
{ "fstd",	0x2c001200, 0xfc001fc0, "cMft,5(s,b)", pa10, FLAG_STRICT},
{ "fstd",	0x2c001200, 0xfc00d3c0, "cmcCft,5(b)", pa11, FLAG_STRICT},
{ "fstd",	0x2c001200, 0xfc0013c0, "cmcCft,5(s,b)", pa11, FLAG_STRICT},
{ "fstd",	0x70000002, 0xfc000002, "cqfx,&(b)", pa20w, FLAG_STRICT},
{ "fstd",	0x70000002, 0xfc00c002, "cqfx,#(b)", pa20, FLAG_STRICT},
{ "fstd",	0x70000002, 0xfc000002, "cqfx,#(s,b)", pa20, FLAG_STRICT},
{ "fldwx",	0x24000000, 0xfc00df80, "cXx(b),fT", pa10, FLAG_STRICT},
{ "fldwx",	0x24000000, 0xfc001f80, "cXx(s,b),fT", pa10, FLAG_STRICT},
{ "fldwx",	0x24000000, 0xfc00d380, "cxccx(b),fT", pa11, FLAG_STRICT},
{ "fldwx",	0x24000000, 0xfc001380, "cxccx(s,b),fT", pa11, FLAG_STRICT},
{ "fldwx",	0x24000000, 0xfc00df80, "cXx(b),fT", pa10, 0},
{ "fldwx",	0x24000000, 0xfc001f80, "cXx(s,b),fT", pa10, 0},
{ "flddx",	0x2c000000, 0xfc00dfc0, "cXx(b),ft", pa10, FLAG_STRICT},
{ "flddx",	0x2c000000, 0xfc001fc0, "cXx(s,b),ft", pa10, FLAG_STRICT},
{ "flddx",	0x2c000000, 0xfc00d3c0, "cxccx(b),ft", pa11, FLAG_STRICT},
{ "flddx",	0x2c000000, 0xfc0013c0, "cxccx(s,b),ft", pa11, FLAG_STRICT},
{ "flddx",	0x2c000000, 0xfc00dfc0, "cXx(b),ft", pa10, 0},
{ "flddx",	0x2c000000, 0xfc001fc0, "cXx(s,b),ft", pa10, 0},
{ "fstwx",	0x24000200, 0xfc00df80, "cxfT,x(b)", pa10, FLAG_STRICT},
{ "fstwx",	0x24000200, 0xfc001f80, "cxfT,x(s,b)", pa10, FLAG_STRICT},
{ "fstwx",	0x24000200, 0xfc00d380, "cxcCfT,x(b)", pa11, FLAG_STRICT},
{ "fstwx",	0x24000200, 0xfc001380, "cxcCfT,x(s,b)", pa11, FLAG_STRICT},
{ "fstwx",	0x24000200, 0xfc00df80, "cxfT,x(b)", pa10, 0},
{ "fstwx",	0x24000200, 0xfc001f80, "cxfT,x(s,b)", pa10, 0},
{ "fstdx",	0x2c000200, 0xfc00dfc0, "cxft,x(b)", pa10, FLAG_STRICT},
{ "fstdx",	0x2c000200, 0xfc001fc0, "cxft,x(s,b)", pa10, FLAG_STRICT},
{ "fstdx",	0x2c000200, 0xfc00d3c0, "cxcCft,x(b)", pa11, FLAG_STRICT},
{ "fstdx",	0x2c000200, 0xfc0013c0, "cxcCft,x(s,b)", pa11, FLAG_STRICT},
{ "fstdx",	0x2c000200, 0xfc00dfc0, "cxft,x(b)", pa10, 0},
{ "fstdx",	0x2c000200, 0xfc001fc0, "cxft,x(s,b)", pa10, 0},
{ "fstqx",	0x3c000200, 0xfc00dfc0, "cXft,x(b)", pa10, 0},
{ "fstqx",	0x3c000200, 0xfc001fc0, "cXft,x(s,b)", pa10, 0},
{ "fldws",	0x24001000, 0xfc00df80, "cm5(b),fT", pa10, FLAG_STRICT},
{ "fldws",	0x24001000, 0xfc001f80, "cm5(s,b),fT", pa10, FLAG_STRICT},
{ "fldws",	0x24001000, 0xfc00d380, "cmcc5(b),fT", pa11, FLAG_STRICT},
{ "fldws",	0x24001000, 0xfc001380, "cmcc5(s,b),fT", pa11, FLAG_STRICT},
{ "fldws",	0x24001000, 0xfc00df80, "cm5(b),fT", pa10, 0},
{ "fldws",	0x24001000, 0xfc001f80, "cm5(s,b),fT", pa10, 0},
{ "fldds",	0x2c001000, 0xfc00dfc0, "cm5(b),ft", pa10, FLAG_STRICT},
{ "fldds",	0x2c001000, 0xfc001fc0, "cm5(s,b),ft", pa10, FLAG_STRICT},
{ "fldds",	0x2c001000, 0xfc00d3c0, "cmcc5(b),ft", pa11, FLAG_STRICT},
{ "fldds",	0x2c001000, 0xfc0013c0, "cmcc5(s,b),ft", pa11, FLAG_STRICT},
{ "fldds",	0x2c001000, 0xfc00dfc0, "cm5(b),ft", pa10, 0},
{ "fldds",	0x2c001000, 0xfc001fc0, "cm5(s,b),ft", pa10, 0},
{ "fstws",	0x24001200, 0xfc00df80, "cmfT,5(b)", pa10, FLAG_STRICT},
{ "fstws",	0x24001200, 0xfc001f80, "cmfT,5(s,b)", pa10, FLAG_STRICT},
{ "fstws",	0x24001200, 0xfc00d380, "cmcCfT,5(b)", pa11, FLAG_STRICT},
{ "fstws",	0x24001200, 0xfc001380, "cmcCfT,5(s,b)", pa11, FLAG_STRICT},
{ "fstws",	0x24001200, 0xfc00df80, "cmfT,5(b)", pa10, 0},
{ "fstws",	0x24001200, 0xfc001f80, "cmfT,5(s,b)", pa10, 0},
{ "fstds",	0x2c001200, 0xfc00dfc0, "cmft,5(b)", pa10, FLAG_STRICT},
{ "fstds",	0x2c001200, 0xfc001fc0, "cmft,5(s,b)", pa10, FLAG_STRICT},
{ "fstds",	0x2c001200, 0xfc00d3c0, "cmcCft,5(b)", pa11, FLAG_STRICT},
{ "fstds",	0x2c001200, 0xfc0013c0, "cmcCft,5(s,b)", pa11, FLAG_STRICT},
{ "fstds",	0x2c001200, 0xfc00dfc0, "cmft,5(b)", pa10, 0},
{ "fstds",	0x2c001200, 0xfc001fc0, "cmft,5(s,b)", pa10, 0},
{ "fstqs",	0x3c001200, 0xfc00dfc0, "cMft,5(b)", pa10, 0},
{ "fstqs",	0x3c001200, 0xfc001fc0, "cMft,5(s,b)", pa10, 0},
{ "fadd",	0x30000600, 0xfc00e7e0, "Ffa,fb,fT", pa10, 0},
{ "fadd",	0x38000600, 0xfc00e720, "IfA,fB,fT", pa10, 0},
{ "fsub",	0x30002600, 0xfc00e7e0, "Ffa,fb,fT", pa10, 0},
{ "fsub",	0x38002600, 0xfc00e720, "IfA,fB,fT", pa10, 0},
{ "fmpy",	0x30004600, 0xfc00e7e0, "Ffa,fb,fT", pa10, 0},
{ "fmpy",	0x38004600, 0xfc00e720, "IfA,fB,fT", pa10, 0},
{ "fdiv",	0x30006600, 0xfc00e7e0, "Ffa,fb,fT", pa10, 0},
{ "fdiv",	0x38006600, 0xfc00e720, "IfA,fB,fT", pa10, 0},
{ "fsqrt",	0x30008000, 0xfc1fe7e0, "Ffa,fT", pa10, 0},
{ "fsqrt",	0x38008000, 0xfc1fe720, "FfA,fT", pa10, 0},
{ "fabs",	0x30006000, 0xfc1fe7e0, "Ffa,fT", pa10, 0},
{ "fabs",	0x38006000, 0xfc1fe720, "FfA,fT", pa10, 0},
{ "frem",	0x30008600, 0xfc00e7e0, "Ffa,fb,fT", pa10, 0},
{ "frem",	0x38008600, 0xfc00e720, "FfA,fB,fT", pa10, 0},
{ "frnd",	0x3000a000, 0xfc1fe7e0, "Ffa,fT", pa10, 0},
{ "frnd",	0x3800a000, 0xfc1fe720, "FfA,fT", pa10, 0},
{ "fcpy",	0x30004000, 0xfc1fe7e0, "Ffa,fT", pa10, 0},
{ "fcpy",	0x38004000, 0xfc1fe720, "FfA,fT", pa10, 0},
{ "fcnvff",	0x30000200, 0xfc1f87e0, "FGfa,fT", pa10, 0},
{ "fcnvff",	0x38000200, 0xfc1f8720, "FGfA,fT", pa10, 0},
{ "fcnvxf",	0x30008200, 0xfc1f87e0, "FGfa,fT", pa10, 0},
{ "fcnvxf",	0x38008200, 0xfc1f8720, "FGfA,fT", pa10, 0},
{ "fcnvfx",	0x30010200, 0xfc1f87e0, "FGfa,fT", pa10, 0},
{ "fcnvfx",	0x38010200, 0xfc1f8720, "FGfA,fT", pa10, 0},
{ "fcnvfxt",	0x30018200, 0xfc1f87e0, "FGfa,fT", pa10, 0},
{ "fcnvfxt",	0x38018200, 0xfc1f8720, "FGfA,fT", pa10, 0},
{ "fmpyfadd",	0xb8000000, 0xfc000020, "IfA,fB,fC,fT", pa20, FLAG_STRICT},
{ "fmpynfadd",	0xb8000020, 0xfc000020, "IfA,fB,fC,fT", pa20, FLAG_STRICT},
{ "fneg",	0x3000c000, 0xfc1fe7e0, "Ffa,fT", pa20, FLAG_STRICT},
{ "fneg",	0x3800c000, 0xfc1fe720, "IfA,fT", pa20, FLAG_STRICT},
{ "fnegabs",	0x3000e000, 0xfc1fe7e0, "Ffa,fT", pa20, FLAG_STRICT},
{ "fnegabs",	0x3800e000, 0xfc1fe720, "IfA,fT", pa20, FLAG_STRICT},
{ "fcnv",	0x30000200, 0xfc1c0720, "{_fa,fT", pa20, FLAG_STRICT},
{ "fcnv",	0x38000200, 0xfc1c0720, "FGfA,fT", pa20, FLAG_STRICT},
{ "fcmp",	0x30000400, 0xfc00e7e0, "F?ffa,fb", pa10, FLAG_STRICT},
{ "fcmp",	0x38000400, 0xfc00e720, "I?ffA,fB", pa10, FLAG_STRICT},
{ "fcmp",	0x30000400, 0xfc0007e0, "F?ffa,fb,h", pa20, FLAG_STRICT},
{ "fcmp",	0x38000400, 0xfc000720, "I?ffA,fB,h", pa20, FLAG_STRICT},
{ "fcmp",	0x30000400, 0xfc00e7e0, "F?ffa,fb", pa10, 0},
{ "fcmp",	0x38000400, 0xfc00e720, "I?ffA,fB", pa10, 0},
{ "xmpyu",	0x38004700, 0xfc00e720, "fX,fB,fT", pa11, 0},
{ "fmpyadd",	0x18000000, 0xfc000000, "Hfi,fj,fk,fl,fm", pa11, 0},
{ "fmpysub",	0x98000000, 0xfc000000, "Hfi,fj,fk,fl,fm", pa11, 0},
{ "ftest",	0x30002420, 0xffffffff, "", pa10, FLAG_STRICT},
{ "ftest",	0x30002420, 0xffffffe0, ",=", pa20, FLAG_STRICT},
{ "ftest",	0x30000420, 0xffff1fff, "m", pa20, FLAG_STRICT},
{ "fid",	0x30000000, 0xffffffff, "", pa11, 0},

/* Performance Monitor Instructions.  */

{ "pmdis",	0x30000280, 0xffffffdf, "N", pa20, FLAG_STRICT},
{ "pmenb",	0x30000680, 0xffffffff, "", pa20, FLAG_STRICT},

/* Assist Instructions.  */

{ "spop0",	0x10000000, 0xfc000600, "v,ON", pa10, 0},
{ "spop1",	0x10000200, 0xfc000600, "v,oNt", pa10, 0},
{ "spop2",	0x10000400, 0xfc000600, "v,1Nb", pa10, 0},
{ "spop3",	0x10000600, 0xfc000600, "v,0Nx,b", pa10, 0},
{ "copr",	0x30000000, 0xfc000000, "u,2N", pa10, 0},
{ "cldw",	0x24000000, 0xfc00de00, "ucXx(b),t", pa10, FLAG_STRICT},
{ "cldw",	0x24000000, 0xfc001e00, "ucXx(s,b),t", pa10, FLAG_STRICT},
{ "cldw",	0x24000000, 0xfc00d200, "ucxccx(b),t", pa11, FLAG_STRICT},
{ "cldw",	0x24000000, 0xfc001200, "ucxccx(s,b),t", pa11, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc00d200, "ucocc@(b),t", pa20, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc001200, "ucocc@(s,b),t", pa20, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc00de00, "ucM5(b),t", pa10, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc001e00, "ucM5(s,b),t", pa10, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc00d200, "ucmcc5(b),t", pa11, FLAG_STRICT},
{ "cldw",	0x24001000, 0xfc001200, "ucmcc5(s,b),t", pa11, FLAG_STRICT},
{ "cldd",	0x2c000000, 0xfc00de00, "ucXx(b),t", pa10, FLAG_STRICT},
{ "cldd",	0x2c000000, 0xfc001e00, "ucXx(s,b),t", pa10, FLAG_STRICT},
{ "cldd",	0x2c000000, 0xfc00d200, "ucxccx(b),t", pa11, FLAG_STRICT},
{ "cldd",	0x2c000000, 0xfc001200, "ucxccx(s,b),t", pa11, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc00d200, "ucocc@(b),t", pa20, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc001200, "ucocc@(s,b),t", pa20, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc00de00, "ucM5(b),t", pa10, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc001e00, "ucM5(s,b),t", pa10, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc00d200, "ucmcc5(b),t", pa11, FLAG_STRICT},
{ "cldd",	0x2c001000, 0xfc001200, "ucmcc5(s,b),t", pa11, FLAG_STRICT},
{ "cstw",	0x24000200, 0xfc00de00, "ucXt,x(b)", pa10, FLAG_STRICT},
{ "cstw",	0x24000200, 0xfc001e00, "ucXt,x(s,b)", pa10, FLAG_STRICT},
{ "cstw",	0x24000200, 0xfc00d200, "ucxcCt,x(b)", pa11, FLAG_STRICT},
{ "cstw",	0x24000200, 0xfc001200, "ucxcCt,x(s,b)", pa11, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc00d200, "ucocCt,@(b)", pa20, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc001200, "ucocCt,@(s,b)", pa20, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc00de00, "ucMt,5(b)", pa10, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc001e00, "ucMt,5(s,b)", pa10, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc00d200, "ucmcCt,5(b)", pa11, FLAG_STRICT},
{ "cstw",	0x24001200, 0xfc001200, "ucmcCt,5(s,b)", pa11, FLAG_STRICT},
{ "cstd",	0x2c000200, 0xfc00de00, "ucXt,x(b)", pa10, FLAG_STRICT},
{ "cstd",	0x2c000200, 0xfc001e00, "ucXt,x(s,b)", pa10, FLAG_STRICT},
{ "cstd",	0x2c000200, 0xfc00d200, "ucxcCt,x(b)", pa11, FLAG_STRICT},
{ "cstd",	0x2c000200, 0xfc001200, "ucxcCt,x(s,b)", pa11, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc00d200, "ucocCt,@(b)", pa20, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc001200, "ucocCt,@(s,b)", pa20, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc00de00, "ucMt,5(b)", pa10, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc001e00, "ucMt,5(s,b)", pa10, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc00d200, "ucmcCt,5(b)", pa11, FLAG_STRICT},
{ "cstd",	0x2c001200, 0xfc001200, "ucmcCt,5(s,b)", pa11, FLAG_STRICT},
{ "cldwx",	0x24000000, 0xfc00de00, "ucXx(b),t", pa10, FLAG_STRICT},
{ "cldwx",	0x24000000, 0xfc001e00, "ucXx(s,b),t", pa10, FLAG_STRICT},
{ "cldwx",	0x24000000, 0xfc00d200, "ucxccx(b),t", pa11, FLAG_STRICT},
{ "cldwx",	0x24000000, 0xfc001200, "ucxccx(s,b),t", pa11, FLAG_STRICT},
{ "cldwx",	0x24000000, 0xfc00de00, "ucXx(b),t", pa10, 0},
{ "cldwx",	0x24000000, 0xfc001e00, "ucXx(s,b),t", pa10, 0},
{ "clddx",	0x2c000000, 0xfc00de00, "ucXx(b),t", pa10, FLAG_STRICT},
{ "clddx",	0x2c000000, 0xfc001e00, "ucXx(s,b),t", pa10, FLAG_STRICT},
{ "clddx",	0x2c000000, 0xfc00d200, "ucxccx(b),t", pa11, FLAG_STRICT},
{ "clddx",	0x2c000000, 0xfc001200, "ucxccx(s,b),t", pa11, FLAG_STRICT},
{ "clddx",	0x2c000000, 0xfc00de00, "ucXx(b),t", pa10, 0},
{ "clddx",	0x2c000000, 0xfc001e00, "ucXx(s,b),t", pa10, 0},
{ "cstwx",	0x24000200, 0xfc00de00, "ucXt,x(b)", pa10, FLAG_STRICT},
{ "cstwx",	0x24000200, 0xfc001e00, "ucXt,x(s,b)", pa10, FLAG_STRICT},
{ "cstwx",	0x24000200, 0xfc00d200, "ucxcCt,x(b)", pa11, FLAG_STRICT},
{ "cstwx",	0x24000200, 0xfc001200, "ucxcCt,x(s,b)", pa11, FLAG_STRICT},
{ "cstwx",	0x24000200, 0xfc00de00, "ucXt,x(b)", pa10, 0},
{ "cstwx",	0x24000200, 0xfc001e00, "ucXt,x(s,b)", pa10, 0},
{ "cstdx",	0x2c000200, 0xfc00de00, "ucXt,x(b)", pa10, FLAG_STRICT},
{ "cstdx",	0x2c000200, 0xfc001e00, "ucXt,x(s,b)", pa10, FLAG_STRICT},
{ "cstdx",	0x2c000200, 0xfc00d200, "ucxcCt,x(b)", pa11, FLAG_STRICT},
{ "cstdx",	0x2c000200, 0xfc001200, "ucxcCt,x(s,b)", pa11, FLAG_STRICT},
{ "cstdx",	0x2c000200, 0xfc00de00, "ucXt,x(b)", pa10, 0},
{ "cstdx",	0x2c000200, 0xfc001e00, "ucXt,x(s,b)", pa10, 0},
{ "cldws",	0x24001000, 0xfc00de00, "ucM5(b),t", pa10, FLAG_STRICT},
{ "cldws",	0x24001000, 0xfc001e00, "ucM5(s,b),t", pa10, FLAG_STRICT},
{ "cldws",	0x24001000, 0xfc00d200, "ucmcc5(b),t", pa11, FLAG_STRICT},
{ "cldws",	0x24001000, 0xfc001200, "ucmcc5(s,b),t", pa11, FLAG_STRICT},
{ "cldws",	0x24001000, 0xfc00de00, "ucM5(b),t", pa10, 0},
{ "cldws",	0x24001000, 0xfc001e00, "ucM5(s,b),t", pa10, 0},
{ "cldds",	0x2c001000, 0xfc00de00, "ucM5(b),t", pa10, FLAG_STRICT},
{ "cldds",	0x2c001000, 0xfc001e00, "ucM5(s,b),t", pa10, FLAG_STRICT},
{ "cldds",	0x2c001000, 0xfc00d200, "ucmcc5(b),t", pa11, FLAG_STRICT},
{ "cldds",	0x2c001000, 0xfc001200, "ucmcc5(s,b),t", pa11, FLAG_STRICT},
{ "cldds",	0x2c001000, 0xfc00de00, "ucM5(b),t", pa10, 0},
{ "cldds",	0x2c001000, 0xfc001e00, "ucM5(s,b),t", pa10, 0},
{ "cstws",	0x24001200, 0xfc00de00, "ucMt,5(b)", pa10, FLAG_STRICT},
{ "cstws",	0x24001200, 0xfc001e00, "ucMt,5(s,b)", pa10, FLAG_STRICT},
{ "cstws",	0x24001200, 0xfc00d200, "ucmcCt,5(b)", pa11, FLAG_STRICT},
{ "cstws",	0x24001200, 0xfc001200, "ucmcCt,5(s,b)", pa11, FLAG_STRICT},
{ "cstws",	0x24001200, 0xfc00de00, "ucMt,5(b)", pa10, 0},
{ "cstws",	0x24001200, 0xfc001e00, "ucMt,5(s,b)", pa10, 0},
{ "cstds",	0x2c001200, 0xfc00de00, "ucMt,5(b)", pa10, FLAG_STRICT},
{ "cstds",	0x2c001200, 0xfc001e00, "ucMt,5(s,b)", pa10, FLAG_STRICT},
{ "cstds",	0x2c001200, 0xfc00d200, "ucmcCt,5(b)", pa11, FLAG_STRICT},
{ "cstds",	0x2c001200, 0xfc001200, "ucmcCt,5(s,b)", pa11, FLAG_STRICT},
{ "cstds",	0x2c001200, 0xfc00de00, "ucMt,5(b)", pa10, 0},
{ "cstds",	0x2c001200, 0xfc001e00, "ucMt,5(s,b)", pa10, 0},

/* More pseudo instructions which must follow the main table.  */
{ "call",	0xe800f000, 0xfc1ffffd, "n(b)", pa20, FLAG_STRICT},
{ "call",	0xe800a000, 0xffe0e000, "nW", pa10, FLAG_STRICT},
{ "ret",	0xe840d000, 0xfffffffd, "n", pa20, FLAG_STRICT},

};

#define NUMOPCODES ((sizeof pa_opcodes)/(sizeof pa_opcodes[0]))

/* SKV 12/18/92. Added some denotations for various operands.  */

#define PA_IMM11_AT_31 'i'
#define PA_IMM14_AT_31 'j'
#define PA_IMM21_AT_31 'k'
#define PA_DISP12 'w'
#define PA_DISP17 'W'

#define N_HPPA_OPERAND_FORMATS 5
