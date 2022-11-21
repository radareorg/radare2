/*
** $Id: lopcodes.h,v 1.149 2016/07/19 17:12:21 roberto Exp $
** Opcodes for Lua virtual machine
*/

/******************************************************************************
* Copyright (C) 1994-2017 Lua.org, PUC-Rio.
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#ifndef lopcodes_h
#define lopcodes_h


#include <limits.h>
#include <stddef.h>

/*===========================================================================
  We assume that instructions are unsigned numbers.
  All instructions have an opcode in the first 6 bits.
  Instructions can have the following fields:
        'A' : 8 bits
        'B' : 9 bits
        'C' : 9 bits
        'Ax' : 26 bits ('A', 'B', and 'C' together)
        'Bx' : 18 bits ('B' and 'C' together)
        'sBx' : signed Bx

  A signed argument is represented in excess K; that is, the number
  value is the unsigned value minus K. K is exactly the maximum value
  for that argument (so that -max is represented by 0, and +max is
  represented by 2*max), which is half the maximum for the corresponding
  unsigned argument.
===========================================================================*/


enum OpMode {
	iABC, iABx, iAsBx, iAx
};					/* basic instruction format */

#define cast(x, y)               ((x)(y))

/*
** size and position of opcode arguments.
*/
#define SIZE_C          9
#define SIZE_B          9
#define SIZE_Bx         (SIZE_C + SIZE_B)
#define SIZE_A          8
#define SIZE_Ax         (SIZE_C + SIZE_B + SIZE_A)

#define SIZE_OP         6

#define POS_OP          0
#define POS_A           (POS_OP + SIZE_OP)
#define POS_C           (POS_A + SIZE_A)
#define POS_B           (POS_C + SIZE_C)
#define POS_Bx          POS_C
#define POS_Ax          POS_A

#define MAX_INT         INT_MAX	/* maximum value of an int */

#define LUAI_BITSINT 32

/*
** limits for opcode arguments.
** we use (signed) int to manipulate most arguments,
** so they must fit in LUAI_BITSINT-1 bits (-1 for sign)
*/
#if SIZE_Bx < LUAI_BITSINT - 1
#define MAXARG_Bx        ((1 << SIZE_Bx) - 1)
#define MAXARG_sBx        (MAXARG_Bx >> 1)		/* 'sBx' is signed */
#else
#define MAXARG_Bx        MAX_INT
#define MAXARG_sBx        MAX_INT
#endif

#if SIZE_Ax < LUAI_BITSINT - 1
#define MAXARG_Ax       ((1 << SIZE_Ax) - 1)
#else
#define MAXARG_Ax       MAX_INT
#endif


#define MAXARG_A        ((1 << SIZE_A) - 1)
#define MAXARG_B        ((1 << SIZE_B) - 1)
#define MAXARG_C        ((1 << SIZE_C) - 1)

/* creates a mask with 'n' 1 bits at position 'p' */
#define MASK1(n, p)      ((~((~(ut32)0) << (ut32)(n))) << (ut32)(p))

/* creates a mask with 'n' 0 bits at position 'p' */
#define MASK0(n, p)      (~MASK1(n, p))

static ut32 getInstruction(const ut8 *data);
static void setInstruction(ut32 opcode, ut8 *data);


/*
** the following macros help to manipulate instructions
*/

#define GET_OPCODE(i)   (cast (OpCode, ((i) >> POS_OP) & MASK1 (SIZE_OP, 0)))
#define SET_OPCODE(i, o) ((i) = (((i) & MASK0 (SIZE_OP, POS_OP)) |\
				 ((cast (ut32, o) << POS_OP) & MASK1 (SIZE_OP, POS_OP))))

#define getarg(i, pos, size)      (cast (int, ((i) >> pos) & MASK1 (size, 0)))
#define setarg(i, v, pos, size)    ((i) = (((i) & MASK0 (size, pos)) |\
					   ((cast (ut32, v) << pos) & MASK1 (size, pos))))

#define GETARG_A(i)     getarg (i, POS_A, SIZE_A)
#define SETARG_A(i, v)   setarg (i, v, POS_A, SIZE_A)

#define GETARG_B(i)     getarg (i, POS_B, SIZE_B)
#define SETARG_B(i, v)   setarg (i, v, POS_B, SIZE_B)

#define GETARG_C(i)     getarg (i, POS_C, SIZE_C)
#define SETARG_C(i, v)   setarg (i, v, POS_C, SIZE_C)

#define GETARG_Bx(i)    getarg (i, POS_Bx, SIZE_Bx)
#define SETARG_Bx(i, v)  setarg (i, v, POS_Bx, SIZE_Bx)

#define GETARG_Ax(i)    getarg (i, POS_Ax, SIZE_Ax)
#define SETARG_Ax(i, v)  setarg (i, v, POS_Ax, SIZE_Ax)

#define GETARG_sBx(i)   (GETARG_Bx (i) - MAXARG_sBx)
#define SETARG_sBx(i, b) SETARG_Bx ((i), cast (unsigned int, (b) + MAXARG_sBx))


#define CREATE_ABC(o, a, b, c)     ((cast (ut32, o) << POS_OP)	\
				    | (cast (ut32, a) << POS_A)	\
				    | (cast (ut32, b) << POS_B)	\
				    | (cast (ut32, c) << POS_C))

#define CREATE_ABx(o, a, bc)      ((cast (ut32, o) << POS_OP)\
				   | (cast (ut32, a) << POS_A)\
				   | (cast (ut32, bc) << POS_Bx))

#define CREATE_Ax(o, a)          ((cast (ut32) << POS_OP)\
				  | (cast (ut32, a) << POS_Ax))



typedef enum {
/*----------------------------------------------------------------------
name            args    description
------------------------------------------------------------------------*/
	OP_MOVE,/*      A B     R(A) := R(B)                                    */
	OP_LOADK,/*     A Bx    R(A) := Kst(Bx)                                 */
	OP_LOADKX,	/*    A       R(A) := Kst(extra arg)                          */
	OP_LOADBOOL,	/*  A B C   R(A) := (Bool)B; if (C) pc++                    */
	OP_LOADNIL,	/*   A B     R(A), R(A+1), ..., R(A+B) := nil                */
	OP_GETUPVAL,	/*  A B     R(A) := UpValue[B]                              */

	OP_GETTABUP,	/*  A B C   R(A) := UpValue[B][RK(C)]                       */
	OP_GETTABLE,	/*  A B C   R(A) := R(B)[RK(C)]                             */

	OP_SETTABUP,	/*  A B C   UpValue[A][RK(B)] := RK(C)                      */
	OP_SETUPVAL,	/*  A B     UpValue[B] := R(A)                              */
	OP_SETTABLE,	/*  A B C   R(A)[RK(B)] := RK(C)                            */

	OP_NEWTABLE,	/*  A B C   R(A) := {} (size = B,C)                         */

	OP_SELF,/*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */

	OP_ADD,	/*       A B C   R(A) := RK(B) + RK(C)                           */
	OP_SUB,	/*       A B C   R(A) := RK(B) - RK(C)                           */
	OP_MUL,	/*       A B C   R(A) := RK(B) * RK(C)                           */
	OP_MOD,	/*       A B C   R(A) := RK(B) % RK(C)                           */
	OP_POW,	/*       A B C   R(A) := RK(B) ^ RK(C)                           */
	OP_DIV,	/*       A B C   R(A) := RK(B) / RK(C)                           */
	OP_IDIV,/*      A B C   R(A) := RK(B) // RK(C)                          */
	OP_BAND,/*      A B C   R(A) := RK(B) & RK(C)                           */
	OP_BOR,	/*       A B C   R(A) := RK(B) | RK(C)                           */
	OP_BXOR,/*      A B C   R(A) := RK(B) ~ RK(C)                           */
	OP_SHL,	/*       A B C   R(A) := RK(B) << RK(C)                          */
	OP_SHR,	/*       A B C   R(A) := RK(B) >> RK(C)                          */
	OP_UNM,	/*       A B     R(A) := -R(B)                                   */
	OP_BNOT,/*      A B     R(A) := ~R(B)                                   */
	OP_NOT,	/*       A B     R(A) := not R(B)                                */
	OP_LEN,	/*       A B     R(A) := length of R(B)                          */

	OP_CONCAT,	/*    A B C   R(A) := R(B).. ... ..R(C)                       */

	OP_JMP,	/*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
	OP_EQ,	/*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	OP_LT,	/*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	OP_LE,	/*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */

	OP_TEST,/*      A C     if not (R(A) <=> C) then pc++                   */
	OP_TESTSET,	/*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */

	OP_CALL,/*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	OP_TAILCALL,	/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
	OP_RETURN,	/*    A B     return R(A), ... ,R(A+B-2)      (see note)      */

	OP_FORLOOP,	/*   A sBx   R(A)+=R(A+2);
			if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
	OP_FORPREP,	/*   A sBx   R(A)-=R(A+2); pc+=sBx                           */

	OP_TFORCALL,	/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
	OP_TFORLOOP,	/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/

	OP_SETLIST,	/*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */

	OP_CLOSURE,	/*   A Bx    R(A) := closure(KPROTO[Bx])                     */

	OP_VARARG,	/*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */

	OP_EXTRAARG	/*   Ax      extra (larger) argument for previous opcode     */
} OpCode;

#endif
