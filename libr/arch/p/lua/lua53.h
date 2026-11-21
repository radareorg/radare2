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

#ifndef R_LUA53_H
#define R_LUA53_H

#define MAXARG_A 255
#define MAXARG_B 511
#define MAXARG_C 511
#define MAXARG_Bx 262143
#define MAXARG_sBx 131071
#define MAXARG_Ax 67108863
#define GET_OPCODE(i) ((OpCode)((i) & 63))
#define GETARG_A(i) (((i) >> 6) & 255)
#define GETARG_B(i) (((i) >> 23) & 511)
#define GETARG_C(i) (((i) >> 14) & 511)
#define GETARG_sBx(i) ((int)((i) >> 14) - MAXARG_sBx)

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

static const char * const instruction_names[] = {
	"move", "loadk", "loadkx", "loadbool", "loadnil", "getupval", "gettabup", "gettable", "settabup", "setupval", "settable", "newtable", "self", "add", "sub", "mul", "mod",
	"pow", "div", "idiv", "band", "bor", "bxor", "shl", "shr", "unm", "bnot", "not", "len", "concat", "jmp", "eq", "lt", "le",
	"test", "testset", "call", "tailcall", "return", "forloop", "forprep", "tforcall", "tforloop", "setlist", "closure", "vararg", "extraarg", 0
};

static inline bool lua53_rkb(OpCode op) {
	return op == OP_SETTABUP || op == OP_SETTABLE || (op >= OP_ADD && op <= OP_SHR) || (op >= OP_EQ && op <= OP_LE);
}

static inline bool lua53_rkc(OpCode op) {
	return lua53_rkb (op) || op == OP_GETTABUP || op == OP_GETTABLE || op == OP_SELF;
}

static inline int lua53_nargs(OpCode op) {
	if (op == OP_EXTRAARG) {
		return 1;
	}
	return lua53_rkc (op) || op == OP_LOADBOOL || op == OP_NEWTABLE || op == OP_CONCAT
		|| op == OP_TESTSET || op == OP_CALL || op == OP_TAILCALL || op == OP_SETLIST? 3: 2;
}

#endif
