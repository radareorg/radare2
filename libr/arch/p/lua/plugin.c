/* radare2 - BSD - Copyright 2017-2024 - pancake */

#include <r_arch.h>
#include <r_lib.h>

// XXX should be dynlink
#include "lua53.c"

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	PluginData *pd = as->data;

	int parsed = 0;
	ut32 instruction;
	pd->current_write_prt = &instruction;
	pd->current_write_index = 0;
	doParse0 (pd, parsed, parseNextInstruction, op->mnemonic);

	free (op->bytes);
	op->size = 4;
	op->bytes = malloc (4);
	if (!op->bytes) {
		return false;
	}
	setInstruction (instruction, op->bytes);

	R_LOG_DEBUG ("parsed: %d instruction: %d", parsed, instruction);
	return true;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (!op) {
		return 0;
	}
	const ut8 *data = op->bytes;
	const int len = op->size;

	const ut32 instruction = getInstruction (data);
	ut32 extraArg = 0;
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->eob = false;
	if (GET_OPCODE (instruction) > OP_EXTRAARG) {
		return op->size;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		PluginData *pd = as->data;
		(void)lua53dissasm (pd, op, data, len);
	}
	op->mnemonic = strdup (instruction_names[GET_OPCODE (instruction)]);
	switch (GET_OPCODE (instruction)) {
	case OP_MOVE:	/*   A B     R(A) := R(B)              */
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case OP_LOADK:	/*   A Bx    R(A) := Kst(Bx)           */
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case OP_LOADKX:	/*   A       R(A) := Kst(extra arg)    */
		op->type = R_ANAL_OP_TYPE_LOAD;
		extraArg = getInstruction (data + 4);
		if (GET_OPCODE (extraArg) == OP_EXTRAARG) {
			op->size = 8;
		}
		break;
	case OP_LOADBOOL:/*  A B C   R(A) := (Bool)B; if (C) pc++  */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->val = !!GETARG_B (instruction);
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LOADNIL:/*   A B     R(A), R(A+1), ..., R(A+B) := nil  */
		break;
	case OP_GETUPVAL:/*  A B     R(A) := UpValue[B]                */
	case OP_GETTABUP:/*  A B C   R(A) := UpValue[B][RK(C)]         */
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case OP_GETTABLE:/*  A B C   R(A) := R(B)[RK(C)]               */
		break;

	case OP_SETTABUP:/*  A B C   UpValue[A][RK(B)] := RK(C)        */
	case OP_SETUPVAL:/*  A B     UpValue[B] := R(A)                */
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case OP_SETTABLE:/*  A B C   R(A)[RK(B)] := RK(C)              */
		break;
	case OP_NEWTABLE:/*  A B C   R(A) := {} (size = B,C)           */
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case OP_SELF:	/*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		break;
	case OP_ADD:	/*       A B C   R(A) := RK(B) + RK(C)     */
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case OP_SUB:	/*       A B C   R(A) := RK(B) - RK(C)     */
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case OP_MUL:	/*       A B C   R(A) := RK(B) * RK(C)     */
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case OP_MOD:	/*       A B C   R(A) := RK(B) % RK(C)     */
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case OP_POW:	/*       A B C   R(A) := RK(B) ^ RK(C)     */
		break;
	case OP_DIV:	/*       A B C   R(A) := RK(B) / RK(C)     */
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_IDIV:	/*      A B C   R(A) := RK(B) // RK(C)     */
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_BAND:	/*      A B C   R(A) := RK(B) & RK(C)      */
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case OP_BOR:	/*       A B C   R(A) := RK(B) | RK(C)     */
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case OP_BXOR:	/*      A B C   R(A) := RK(B) ~ RK(C)      */
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case OP_SHL:	/*       A B C   R(A) := RK(B) << RK(C)    */
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case OP_SHR:	/*       A B C   R(A) := RK(B) >> RK(C)    */
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case OP_UNM:	/*       A B     R(A) := -R(B)             */
		break;
	case OP_BNOT:	/*      A B     R(A) := ~R(B)              */
		op->type = R_ANAL_OP_TYPE_CPL;
		break;
	case OP_NOT:	/*       A B     R(A) := not R(B)          */
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case OP_LEN:	/*       A B     R(A) := length of R(B)    */
		break;
	case OP_CONCAT:	/*    A B C   R(A) := R(B).. ... ..R(C)    */
		break;
	case OP_JMP:	/*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4 * (GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_EQ:	/*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LT:	/*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LE:	/*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TEST:	/*      A C     if not (R(A) <=> C) then pc++                   */
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TESTSET:/*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		op->type = R_ANAL_OP_TYPE_CMOV;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_CALL:	/*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL:/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->type2 = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN:	/*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_FORLOOP:/*   A sBx   R(A)+=R(A+2);
			                                if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_FORPREP:/*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_TFORCALL:/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case OP_TFORLOOP:/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx (instruction));
		op->fail = op->addr + 4;
		break;
	case OP_SETLIST:/*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case OP_CLOSURE:/*   A Bx    R(A) := closure(KPROTO[Bx])                     */
	case OP_VARARG:	/*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
	case OP_EXTRAARG:/*   Ax      extra (larger) argument for previous opcode     */
		break;
	}
	return op->size;
}

#if 0
static int lua53_anal_fcn(RAnal *a, RAnalFunction *fcn, ut64 addr, const ut8 *data, int len, int reftype){
	Dprintf ("Analyze Function: 0x%"PFMT64x "\n", addr);
	LuaFunction *function = lua53findLuaFunctionByCodeAddr (addr);
	if (function) {
		fcn->maxstack = function->maxStackSize;
		fcn->nargs = function->numParams;
	}
	fcn->addr = addr;
	return 0;
}

static int finit(void *user) {
	if (lua53_data.functionList) {
		r_list_free (lua53_data.functionList);
		lua53_data.functionList = 0;
	}
	return 0;
}

#endif

static int archinfo(RArchSession *cfg, ut32 q) {
	if (q == R_ARCH_INFO_ISVM) {
		return true;
	}
	return 4;
}

static char *regs(RArchSession *s) {
	static const char * const p =
		"=PC    pc\n"
		"=SP    sp\n"
		"=A0    a\n"
		"=A1    b\n"
		"=A2    c\n"
		"=R0    a\n"
		"=R1    b\n"
		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	a	.32	8	0\n"
		"gpr	b	.32	12	0\n"
		"gpr	c	.32	16	0\n"
	;
	return strdup (p);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "LUA Bytecode (5.3)",
		.license = "MIT",
		.author = "pancake",
	},
	.arch = "lua",
	.bits = R_SYS_BITS_PACK (32),
	.addr_bits = R_SYS_BITS_PACK (32),
	.info = archinfo,
	.encode = encode,
	.decode = decode,
	.regs = regs,
	.init = init,
	.fini = fini,
	.cpus = "5.3", // ,5.4"
	.endian = R_SYS_ENDIAN_LITTLE,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_lua,
	.version = R2_VERSION
};
#endif
