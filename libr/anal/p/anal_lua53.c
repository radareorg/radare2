
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>
#include "../../asm/arch/lua53/lua53.c"

static int lua53_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

	if (!op)
		return 0;
	
	memset (op, '\0', sizeof (RAnalOp));
	
	const ut32 instruction = getInstruction (data);
	ut32 extraArg = 0;
	
	op->addr = addr;
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_UNK;
	
	switch( GET_OPCODE (instruction) ){
	case OP_MOVE:/*      A B     R(A) := R(B)                                    */
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case OP_LOADK:/*     A Bx    R(A) := Kst(Bx)                                 */
		break;
	case OP_LOADKX:/*    A       R(A) := Kst(extra arg)                          */
		extraArg = getInstruction (data + 4);
		if(GET_OPCODE (extraArg) == OP_EXTRAARG){
			op->size = 8;
		}
		break;
	case OP_LOADBOOL:/*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->val = !!GETARG_B (instruction);
		break;
	case OP_LOADNIL:/*   A B     R(A), R(A+1), ..., R(A+B) := nil                */
		break;
	case OP_GETUPVAL:/*  A B     R(A) := UpValue[B]                              */
	case OP_GETTABUP:/*  A B C   R(A) := UpValue[B][RK(C)]                       */
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case OP_GETTABLE:/*  A B C   R(A) := R(B)[RK(C)]                             */
		break;

	case OP_SETTABUP:/*  A B C   UpValue[A][RK(B)] := RK(C)                      */
	case OP_SETUPVAL:/*  A B     UpValue[B] := R(A)                              */
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case OP_SETTABLE:/*  A B C   R(A)[RK(B)] := RK(C)                            */
		break;

	case OP_NEWTABLE:/*  A B C   R(A) := {} (size = B,C)                         */
		op->type = R_ANAL_OP_TYPE_NEW;
		break;

	case OP_SELF:/*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		break;

	case OP_ADD:/*       A B C   R(A) := RK(B) + RK(C)                           */
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case OP_SUB:/*       A B C   R(A) := RK(B) - RK(C)                           */
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case OP_MUL:/*       A B C   R(A) := RK(B) * RK(C)                           */
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case OP_MOD:/*       A B C   R(A) := RK(B) % RK(C)                           */
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case OP_POW:/*       A B C   R(A) := RK(B) ^ RK(C)                           */
		break;
	case OP_DIV:/*       A B C   R(A) := RK(B) / RK(C)                           */
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_IDIV:/*      A B C   R(A) := RK(B) // RK(C)                          */
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_BAND:/*      A B C   R(A) := RK(B) & RK(C)                           */
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case OP_BOR:/*       A B C   R(A) := RK(B) | RK(C)                           */
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case OP_BXOR:/*      A B C   R(A) := RK(B) ~ RK(C)                           */
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case OP_SHL:/*       A B C   R(A) := RK(B) << RK(C)                          */
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case OP_SHR:/*       A B C   R(A) := RK(B) >> RK(C)                          */
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case OP_UNM:/*       A B     R(A) := -R(B)                                   */
		break;
	case OP_BNOT:/*      A B     R(A) := ~R(B)                                   */
		op->type = R_ANAL_OP_TYPE_CPL;
		break;
	case OP_NOT:/*       A B     R(A) := not R(B)                                */
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case OP_LEN:/*       A B     R(A) := length of R(B)                          */
		break;

	case OP_CONCAT:/*    A B C   R(A) := R(B).. ... ..R(C)                       */
		break;

	case OP_JMP:/*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case OP_EQ:/*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case OP_LT:/*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case OP_LE:/*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;

	case OP_TEST:/*      A C     if not (R(A) <=> C) then pc++                   */
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case OP_TESTSET:/*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;

	case OP_CALL:/*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL:/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN:/*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		break;

	case OP_FORLOOP:/*   A sBx   R(A)+=R(A+2);
							if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case OP_FORPREP:/*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		op->type = R_ANAL_OP_TYPE_JMP;
		break;

	case OP_TFORCALL:/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TFORLOOP:/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;

	case OP_SETLIST:/*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
		op->type = R_ANAL_OP_TYPE_STORE;
		break;

	case OP_CLOSURE:/*   A Bx    R(A) := closure(KPROTO[Bx])                     */

	case OP_VARARG:/*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
	
	case OP_EXTRAARG:/*   Ax      extra (larger) argument for previous opcode     */
		break;
	}
	
	return op->size;
}

RAnalPlugin r_anal_plugin_lua53 = {
	.name = "LUA 5.3",
	.arch = "lua53",
	.license = "---",
	.bits = 32,
	.desc = "LUA 5.3 VM code analysis plugin",
	.op = &lua53_anal_op,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_lua53,
	.version = R2_VERSION
};
#endif
