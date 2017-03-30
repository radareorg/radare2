
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>
#include "../../asm/arch/lua53/lua53.c"
#include "../arch/lua53/lua53_parser.c"

static int lua53_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	
	if (!op)
		return 0;
	memset (op, 0, sizeof (RAnalOp));
	
	const ut32 instruction = getInstruction (data);
	ut32 extraArg = 0;
	
	op->addr = addr;
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->eob = false;
	switch( GET_OPCODE (instruction) ){
	case OP_MOVE:/*      A B     R(A) := R(B)                                    */
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case OP_LOADK:/*     A Bx    R(A) := Kst(Bx)                                 */
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case OP_LOADKX:/*    A       R(A) := Kst(extra arg)                          */
		op->type = R_ANAL_OP_TYPE_LOAD;
		extraArg = getInstruction (data + 4);
		if(GET_OPCODE (extraArg) == OP_EXTRAARG){
			op->size = 8;
		}
		break;
	case OP_LOADBOOL:/*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->val = !!GETARG_B (instruction);
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
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
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4*(GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_EQ:/*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LT:/*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LE:/*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;

	case OP_TEST:/*      A C     if not (R(A) <=> C) then pc++                   */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TESTSET:/*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		op->type = R_ANAL_OP_TYPE_CMOV;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;

	case OP_CALL:/*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL:/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->type2 = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN:/*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4;
		break;

	case OP_FORLOOP:/*   A sBx   R(A)+=R(A+2);
							if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4*(GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_FORPREP:/*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4*(GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;

	case OP_TFORCALL:/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TFORLOOP:/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4*(GETARG_sBx (instruction));
		op->fail = op->addr + 4;
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
void addFunction (LuaFunction* func, ParseStruct* parseStruct){
	if(!func->parent_func){
		RAnalFunction *afunc = parseStruct->data;
		afunc->addr += func->code_offset + lua53_data.intSize;
		printf("%08llx\n",afunc->addr);
		printf("%08llx\n",func->code_offset + lua53_data.intSize);
		if(afunc->addr != func->code_offset + lua53_data.intSize){
			afunc->name = malloc(func->name_size + 1);
			memcpy(afunc->name,func->name_ptr,func->name_size);
			afunc->name[func->name_size] = '\0';
			
			afunc->stack = 0;
		}
	}
}
int lua53_anal_fcn(RAnal *a, RAnalFunction *fcn, ut64 addr, const ut8 *data, int len, int reftype){
	
	Dprintf ("Analyze Function: 0x%llx\n",addr);
	LuaFunction* function = findLuaFunctionByCodeAddr (addr);
	if(function){
		fcn->maxstack = function->maxStackSize;
		fcn->nargs = function->numParams;
	}
	fcn->addr = addr;
	return 0;
}

RAnalOp * op_from_buffer(RAnal *a, ut64 addr, const ut8* buf, ut64 len){
	
	fprintf(stderr,"OP\n");
	RAnalOp* analOp = R_NEW0 (RAnalOp);
	if(analOp == NULL)
		return NULL;
	lua53_anal_op (a,analOp,addr,buf,len);
	return analOp;
}
RAnalFunction * fn_from_buffer(RAnal *a, ut64 addr, const ut8* buf, ut64 len){
	
	fprintf(stderr,"FUNC\n");
	RAnalFunction* analFn = R_NEW0 (RAnalFunction);
	if(analFn == NULL)
		return NULL;
	lua53_anal_fcn (a,analFn,addr,buf,len,0);
	
	return analFn;
}

int finit(void *user) {
	if(lua53_data.functionList){
		r_list_free (lua53_data.functionList);
		lua53_data.functionList = 0;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_lua53 = {
	.name = "lua53",
	.desc = "LUA 5.3 analysis plugin",
	.arch = "lua53",
	.license = "MIT",	
	.bits = 32,
	.desc = "LUA 5.3 VM code analysis plugin",
	.op = &lua53_anal_op,
	.fcn = &lua53_anal_fcn,
	.esil = false,
	.fini = &finit,

};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_lua53,
	.version = R2_VERSION
};
#endif
