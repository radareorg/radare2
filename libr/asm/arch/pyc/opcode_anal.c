#include "opcode.h"

// The actual code of one opcode varies across the versions.
// That's why I specify one opcode by its name, not its code.

static inline void anal_push(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg, ut32 type, st32 push_cnt) {
	op->type = type;
	op->stackop = R_ANAL_STACK_INC;
	op->stackptr = OBJECT_SIZE_ON_STACK * push_cnt;
}

static inline void anal_pop(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg, ut32 type, st32 push_cnt) {
	op->type = type;
	op->stackop = R_ANAL_STACK_INC;
	op->stackptr = -(OBJECT_SIZE_ON_STACK * push_cnt);
}

static void anal_BEFORE_ASYNC_WITH(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_BEGIN_FINALLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_BINARY_ADD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_ADD, 1);
}

static void anal_BINARY_AND(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_AND, 1);
}

static void anal_BINARY_CALL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_BINARY_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_DIV, 1);
}

static void anal_BINARY_FLOOR_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_DIV, 1);
}

static void anal_BINARY_LSHIFT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_SHL, 1);
}

static void anal_BINARY_MATRIX_MULTIPLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_BINARY_MODULO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_MOD, 1);
}

static void anal_BINARY_MULTIPLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_MUL, 1);
}

static void anal_BINARY_OR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_OR, 1);
}

static void anal_BINARY_POWER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_BINARY_RSHIFT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_SHR, 1);
}

static void anal_BINARY_SUBSCR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_BINARY_SUBTRACT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_SUB, 1);
}

static void anal_BINARY_TRUE_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_DIV, 1);
}

static void anal_BINARY_XOR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_XOR, 1);
}

static void anal_BREAK_LOOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	//op->type = R_ANAL_OP_TYPE_CJMP;
	// This is actually a jump, but require further analysis
	op->type = R_ANAL_OP_TYPE_UNK;
	op->jump = -1;
	op->fail = -1;
}

static void anal_BUILD_CLASS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, 2);
}

static void anal_BUILD_CONST_KEY_MAP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg);
}

static void anal_BUILD_FUNCTION(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_NEW;
}

static void anal_BUILD_LIST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg);
}

static void anal_BUILD_LIST_UNPACK(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_MAP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, 2 * oparg - 1);
}

static void anal_BUILD_MAP_UNPACK(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_MAP_UNPACK_WITH_CALL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg);
}

static void anal_BUILD_SET(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_SET_UNPACK(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_SLICE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_STRING(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_TUPLE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_TUPLE_UNPACK(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg - 1);
}

static void anal_BUILD_TUPLE_UNPACK_WITH_CALL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_NEW, oparg);
}

static void anal_CALL_FUNCTION(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// TODO
	// Get callee function from stack
	// Parse oparg by version info
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_CALL_FUNCTION_EX(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_CALL_FUNCTION_KW(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_CALL_FUNCTION_VAR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_CALL_FUNCTION_VAR_KW(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_CALL_METHOD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ICALL;
	op->jump = -1;
}

static void anal_DELETE_ATTR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_DEREF(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_FAST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_GLOBAL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_NAME(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_SLICE_0(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_SLICE_1(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_SLICE_2(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_SLICE_3(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DELETE_SUBSCR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_DUP_TOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UPUSH, 1);
}

static void anal_DUP_TOPX(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UPUSH, 1);
}

static void anal_DUP_TOP_TWO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UPUSH, 2);
}

static void anal_END_ASYNC_FOR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// If TOS is StopAsyncIteration pop 7 values from the stack and restore the exception state using the second three of them.
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_END_FINALLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	//op->type = R_ANAL_OP_TYPE_CJMP;
	// This is actually a jump, but require further analysis
	op->type = R_ANAL_OP_TYPE_UNK;
	op->jump = -1;
	op->fail = -1;
}

static void anal_EXEC_STMT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_EXTENDED_ARG(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_FORMAT_VALUE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
	if ((oparg & 0x04) == 0x04) {
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -OBJECT_SIZE_ON_STACK;
	}
}

static void anal_FOR_LOOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/b2b1ed17819ecb24a78d07d3ff1e8e6bc6137721/Python/ceval.c#L1499
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_GET_AITER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_GET_ANEXT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_GET_AWAITABLE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_GET_ITER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_GET_YIELD_FROM_ITER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_IMPORT_FROM(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_IMPORT_NAME(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_IMPORT_STAR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_INPLACE_ADD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_ADD;
}

static void anal_INPLACE_AND(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_AND;
}

static void anal_INPLACE_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_DIV;
}

static void anal_INPLACE_FLOOR_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_DIV;
}

static void anal_INPLACE_LSHIFT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_SHL;
}

static void anal_INPLACE_MATRIX_MULTIPLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_INPLACE_MODULO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_MOD;
}

static void anal_INPLACE_MULTIPLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_MUL;
}

static void anal_INPLACE_OR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_OR;
}

static void anal_INPLACE_POWER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_INPLACE_RSHIFT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_SHR;
}

static void anal_INPLACE_SUBTRACT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_SUB;
}

static void anal_INPLACE_TRUE_DIVIDE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_DIV;
}

static void anal_INPLACE_XOR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_XOR;
}

static void anal_LIST_APPEND(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_ASSERTION_ERROR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_ATTR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_LOAD_BUILD_CLASS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_CLASSDEREF(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_CLOSURE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_CONST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_DEREF(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_FAST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_GLOBAL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_GLOBALS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/24260ec91623c18569225229d5becb852010ae2c/Include/opcode.h#L80
	// Can't find this opcode
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_LOAD_LOCAL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_LOCALS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_METHOD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_LOAD_NAME(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_MAKE_CLOSURE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg);
}

static void anal_MAKE_FUNCTION(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg);
}

static void anal_MAP_ADD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_NOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_NOP;
}

static void anal_POP_BLOCK(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_POP, 1);
}

static void anal_POP_EXCEPT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_POP, 1);
}

static void anal_POP_FINALLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// FIXME
	// POP_FINALLY will pop 6 elements if TOS is an exception type
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_POP, 1);
}

static void anal_POP_TOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_POP, 1);
}

static void anal_PRINT_EXPR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_PRINT_ITEM(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_PRINT_ITEM_TO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 2);
}

static void anal_PRINT_NEWLINE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_PRINT_NEWLINE_TO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_RAISE_EXCEPTION(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/6c3a3aa17b028f6b93067083d32c7eaa4338757c/Include/opcode.h#L89
	// Can't find this opcode
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_RAISE_VARARGS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg);
}

static void anal_RERAISE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 3);
}

static void anal_RESERVE_FAST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/6c3a3aa17b028f6b93067083d32c7eaa4338757c/Include/opcode.h#L134
	// Can't find this opcode
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_RETURN_VALUE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_RET;
	op->stackop = R_ANAL_STACK_INC;
	op->stackptr = -OBJECT_SIZE_ON_STACK;
	op->eob = true;
}

static void anal_ROT_FOUR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Lifts second, third and forth stack items one position up, moves top down to position four.
	op->type = R_ANAL_OP_TYPE_XCHG;
}

static void anal_ROT_THREE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Lifts second and third stack item one position up, moves top down to position three.
	op->type = R_ANAL_OP_TYPE_XCHG;
}

static void anal_ROT_TWO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Swaps the two top-most stack items.
	op->type = R_ANAL_OP_TYPE_XCHG;
}

static void anal_SETUP_ANNOTATIONS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_SET_ADD(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_SET_FUNC_ARGS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4/Python/ceval.c
	// Can't find this opcode
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_SET_LINENO(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_SLICE_0(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_SLICE_1(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_SLICE_2(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_SLICE_3(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 2);
}

static void anal_STOP_CODE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_TRAP;
}

static void anal_STORE_ANNOTATION(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_STORE_ATTR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_STORE_DEREF(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_STORE_FAST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_STORE_GLOBAL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_STORE_LOCALS(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_STORE_MAP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 2);
}

static void anal_STORE_NAME(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_STORE_SLICE_0(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 2);
}

static void anal_STORE_SLICE_1(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 3);
}

static void anal_STORE_SLICE_2(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 3);
}

static void anal_STORE_SLICE_3(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 4);
}

static void anal_STORE_SUBSCR(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 3);
}

static void anal_UNARY_CALL(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_UNARY_CONVERT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_UNARY_INVERT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_NOT;
}

static void anal_UNARY_NEGATIVE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_UNARY_NOT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_NOT;
}

static void anal_UNARY_POSITIVE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_UNPACK_ARG(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg - 1);
}

static void anal_UNPACK_EX(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, (oparg & 0xFF) + (oparg >> 8));
}

static void anal_UNPACK_LIST(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg - 1);
}

static void anal_UNPACK_SEQUENCE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg - 1);
}

static void anal_UNPACK_TUPLE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, oparg - 1);
}

static void anal_UNPACK_VARARG(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// https://github.com/python/cpython/blob/v1.4b3/Include/opcode.h
	// I can not find this opcode even in v1.4 version source code.
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_WITH_CLEANUP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Need the value on stack
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_WITH_CLEANUP_FINISH(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 2);
}

static void anal_WITH_CLEANUP_START(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	// Need the value on stack
	op->type = R_ANAL_OP_TYPE_UNK;
}

static void anal_WITH_EXCEPT_START(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_push (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_YIELD_FROM(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_YIELD_VALUE(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	anal_pop (op, op_obj, oparg, R_ANAL_OP_TYPE_UNK, 1);
}

static void anal_FOR_ITER(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static void anal_SETUP_LOOP(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static void anal_SETUP_EXCEPT(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static void anal_SETUP_FINALLY(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static void anal_SETUP_WITH(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static void anal_SETUP_ASYNC_WITH(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	ut64 mid = op->jump;
	op->jump = op->fail;
	op->fail = mid;
}

static op_anal_func op_anal[] = {
	{ "BEFORE_ASYNC_WITH", anal_BEFORE_ASYNC_WITH },
	{ "BEGIN_FINALLY", anal_BEGIN_FINALLY },
	{ "BINARY_ADD", anal_BINARY_ADD },
	{ "BINARY_AND", anal_BINARY_AND },
	{ "BINARY_CALL", anal_BINARY_CALL },
	{ "BINARY_DIVIDE", anal_BINARY_DIVIDE },
	{ "BINARY_FLOOR_DIVIDE", anal_BINARY_FLOOR_DIVIDE },
	{ "BINARY_LSHIFT", anal_BINARY_LSHIFT },
	{ "BINARY_MATRIX_MULTIPLY", anal_BINARY_MATRIX_MULTIPLY },
	{ "BINARY_MODULO", anal_BINARY_MODULO },
	{ "BINARY_MULTIPLY", anal_BINARY_MULTIPLY },
	{ "BINARY_OR", anal_BINARY_OR },
	{ "BINARY_POWER", anal_BINARY_POWER },
	{ "BINARY_RSHIFT", anal_BINARY_RSHIFT },
	{ "BINARY_SUBSCR", anal_BINARY_SUBSCR },
	{ "BINARY_SUBTRACT", anal_BINARY_SUBTRACT },
	{ "BINARY_TRUE_DIVIDE", anal_BINARY_TRUE_DIVIDE },
	{ "BINARY_XOR", anal_BINARY_XOR },
	{ "BREAK_LOOP", anal_BREAK_LOOP },
	{ "BUILD_CLASS", anal_BUILD_CLASS },
	{ "BUILD_CONST_KEY_MAP", anal_BUILD_CONST_KEY_MAP },
	{ "BUILD_FUNCTION", anal_BUILD_FUNCTION },
	{ "BUILD_LIST", anal_BUILD_LIST },
	{ "BUILD_LIST_UNPACK", anal_BUILD_LIST_UNPACK },
	{ "BUILD_MAP", anal_BUILD_MAP },
	{ "BUILD_MAP_UNPACK", anal_BUILD_MAP_UNPACK },
	{ "BUILD_MAP_UNPACK_WITH_CALL", anal_BUILD_MAP_UNPACK_WITH_CALL },
	{ "BUILD_SET", anal_BUILD_SET },
	{ "BUILD_SET_UNPACK", anal_BUILD_SET_UNPACK },
	{ "BUILD_SLICE", anal_BUILD_SLICE },
	{ "BUILD_STRING", anal_BUILD_STRING },
	{ "BUILD_TUPLE", anal_BUILD_TUPLE },
	{ "BUILD_TUPLE_UNPACK", anal_BUILD_TUPLE_UNPACK },
	{ "BUILD_TUPLE_UNPACK_WITH_CALL", anal_BUILD_TUPLE_UNPACK_WITH_CALL },
	{ "CALL_FUNCTION", anal_CALL_FUNCTION },
	{ "CALL_FUNCTION_EX", anal_CALL_FUNCTION_EX },
	{ "CALL_FUNCTION_KW", anal_CALL_FUNCTION_KW },
	{ "CALL_FUNCTION_VAR", anal_CALL_FUNCTION_VAR },
	{ "CALL_FUNCTION_VAR_KW", anal_CALL_FUNCTION_VAR_KW },
	{ "CALL_METHOD", anal_CALL_METHOD },
	{ "DELETE_ATTR", anal_DELETE_ATTR },
	{ "DELETE_DEREF", anal_DELETE_DEREF },
	{ "DELETE_FAST", anal_DELETE_FAST },
	{ "DELETE_GLOBAL", anal_DELETE_GLOBAL },
	{ "DELETE_NAME", anal_DELETE_NAME },
	{ "DELETE_SLICE_0", anal_DELETE_SLICE_0 },
	{ "DELETE_SLICE_1", anal_DELETE_SLICE_1 },
	{ "DELETE_SLICE_2", anal_DELETE_SLICE_2 },
	{ "DELETE_SLICE_3", anal_DELETE_SLICE_3 },
	{ "DELETE_SUBSCR", anal_DELETE_SUBSCR },
	{ "DUP_TOP", anal_DUP_TOP },
	{ "DUP_TOPX", anal_DUP_TOPX },
	{ "DUP_TOP_TWO", anal_DUP_TOP_TWO },
	{ "END_ASYNC_FOR", anal_END_ASYNC_FOR },
	{ "END_FINALLY", anal_END_FINALLY },
	{ "EXEC_STMT", anal_EXEC_STMT },
	{ "EXTENDED_ARG", anal_EXTENDED_ARG },
	{ "FORMAT_VALUE", anal_FORMAT_VALUE },
	{ "FOR_LOOP", anal_FOR_LOOP },
	{ "GET_AITER", anal_GET_AITER },
	{ "GET_ANEXT", anal_GET_ANEXT },
	{ "GET_AWAITABLE", anal_GET_AWAITABLE },
	{ "GET_ITER", anal_GET_ITER },
	{ "GET_YIELD_FROM_ITER", anal_GET_YIELD_FROM_ITER },
	{ "IMPORT_FROM", anal_IMPORT_FROM },
	{ "IMPORT_NAME", anal_IMPORT_NAME },
	{ "IMPORT_STAR", anal_IMPORT_STAR },
	{ "INPLACE_ADD", anal_INPLACE_ADD },
	{ "INPLACE_AND", anal_INPLACE_AND },
	{ "INPLACE_DIVIDE", anal_INPLACE_DIVIDE },
	{ "INPLACE_FLOOR_DIVIDE", anal_INPLACE_FLOOR_DIVIDE },
	{ "INPLACE_LSHIFT", anal_INPLACE_LSHIFT },
	{ "INPLACE_MATRIX_MULTIPLY", anal_INPLACE_MATRIX_MULTIPLY },
	{ "INPLACE_MODULO", anal_INPLACE_MODULO },
	{ "INPLACE_MULTIPLY", anal_INPLACE_MULTIPLY },
	{ "INPLACE_OR", anal_INPLACE_OR },
	{ "INPLACE_POWER", anal_INPLACE_POWER },
	{ "INPLACE_RSHIFT", anal_INPLACE_RSHIFT },
	{ "INPLACE_SUBTRACT", anal_INPLACE_SUBTRACT },
	{ "INPLACE_TRUE_DIVIDE", anal_INPLACE_TRUE_DIVIDE },
	{ "INPLACE_XOR", anal_INPLACE_XOR },
	{ "LIST_APPEND", anal_LIST_APPEND },
	{ "LOAD_ASSERTION_ERROR", anal_LOAD_ASSERTION_ERROR },
	{ "LOAD_ATTR", anal_LOAD_ATTR },
	{ "LOAD_BUILD_CLASS", anal_LOAD_BUILD_CLASS },
	{ "LOAD_CLASSDEREF", anal_LOAD_CLASSDEREF },
	{ "LOAD_CLOSURE", anal_LOAD_CLOSURE },
	{ "LOAD_CONST", anal_LOAD_CONST },
	{ "LOAD_DEREF", anal_LOAD_DEREF },
	{ "LOAD_FAST", anal_LOAD_FAST },
	{ "LOAD_GLOBAL", anal_LOAD_GLOBAL },
	{ "LOAD_GLOBALS", anal_LOAD_GLOBALS },
	{ "LOAD_LOCAL", anal_LOAD_LOCAL },
	{ "LOAD_LOCALS", anal_LOAD_LOCALS },
	{ "LOAD_METHOD", anal_LOAD_METHOD },
	{ "LOAD_NAME", anal_LOAD_NAME },
	{ "MAKE_CLOSURE", anal_MAKE_CLOSURE },
	{ "MAKE_FUNCTION", anal_MAKE_FUNCTION },
	{ "MAP_ADD", anal_MAP_ADD },
	{ "NOP", anal_NOP },
	{ "POP_BLOCK", anal_POP_BLOCK },
	{ "POP_EXCEPT", anal_POP_EXCEPT },
	{ "POP_FINALLY", anal_POP_FINALLY },
	{ "POP_TOP", anal_POP_TOP },
	{ "PRINT_EXPR", anal_PRINT_EXPR },
	{ "PRINT_ITEM", anal_PRINT_ITEM },
	{ "PRINT_ITEM_TO", anal_PRINT_ITEM_TO },
	{ "PRINT_NEWLINE", anal_PRINT_NEWLINE },
	{ "PRINT_NEWLINE_TO", anal_PRINT_NEWLINE_TO },
	{ "RAISE_EXCEPTION", anal_RAISE_EXCEPTION },
	{ "RAISE_VARARGS", anal_RAISE_VARARGS },
	{ "RERAISE", anal_RERAISE },
	{ "RESERVE_FAST", anal_RESERVE_FAST },
	{ "RETURN_VALUE", anal_RETURN_VALUE },
	{ "ROT_FOUR", anal_ROT_FOUR },
	{ "ROT_THREE", anal_ROT_THREE },
	{ "ROT_TWO", anal_ROT_TWO },
	{ "SETUP_ANNOTATIONS", anal_SETUP_ANNOTATIONS },
	{ "SET_ADD", anal_SET_ADD },
	{ "SET_FUNC_ARGS", anal_SET_FUNC_ARGS },
	{ "SET_LINENO", anal_SET_LINENO },
	{ "SLICE_0", anal_SLICE_0 },
	{ "SLICE_1", anal_SLICE_1 },
	{ "SLICE_2", anal_SLICE_2 },
	{ "SLICE_3", anal_SLICE_3 },
	{ "STOP_CODE", anal_STOP_CODE },
	{ "STORE_ANNOTATION", anal_STORE_ANNOTATION },
	{ "STORE_ATTR", anal_STORE_ATTR },
	{ "STORE_DEREF", anal_STORE_DEREF },
	{ "STORE_FAST", anal_STORE_FAST },
	{ "STORE_GLOBAL", anal_STORE_GLOBAL },
	{ "STORE_LOCALS", anal_STORE_LOCALS },
	{ "STORE_MAP", anal_STORE_MAP },
	{ "STORE_NAME", anal_STORE_NAME },
	{ "STORE_SLICE_0", anal_STORE_SLICE_0 },
	{ "STORE_SLICE_1", anal_STORE_SLICE_1 },
	{ "STORE_SLICE_2", anal_STORE_SLICE_2 },
	{ "STORE_SLICE_3", anal_STORE_SLICE_3 },
	{ "STORE_SUBSCR", anal_STORE_SUBSCR },
	{ "UNARY_CALL", anal_UNARY_CALL },
	{ "UNARY_CONVERT", anal_UNARY_CONVERT },
	{ "UNARY_INVERT", anal_UNARY_INVERT },
	{ "UNARY_NEGATIVE", anal_UNARY_NEGATIVE },
	{ "UNARY_NOT", anal_UNARY_NOT },
	{ "UNARY_POSITIVE", anal_UNARY_POSITIVE },
	{ "UNPACK_ARG", anal_UNPACK_ARG },
	{ "UNPACK_EX", anal_UNPACK_EX },
	{ "UNPACK_LIST", anal_UNPACK_LIST },
	{ "UNPACK_SEQUENCE", anal_UNPACK_SEQUENCE },
	{ "UNPACK_TUPLE", anal_UNPACK_TUPLE },
	{ "UNPACK_VARARG", anal_UNPACK_VARARG },
	{ "WITH_CLEANUP", anal_WITH_CLEANUP },
	{ "WITH_CLEANUP_FINISH", anal_WITH_CLEANUP_FINISH },
	{ "WITH_CLEANUP_START", anal_WITH_CLEANUP_START },
	{ "WITH_EXCEPT_START", anal_WITH_EXCEPT_START },
	{ "YIELD_FROM", anal_YIELD_FROM },
	{ "YIELD_VALUE", anal_YIELD_VALUE },
	// Fix jump info
	{ "FOR_ITER", anal_FOR_ITER },
	{ "SETUP_LOOP", anal_SETUP_LOOP },
	{ "SETUP_EXCEPT", anal_SETUP_EXCEPT },
	{ "SETUP_FINALLY", anal_SETUP_FINALLY },
	{ "SETUP_WITH", anal_SETUP_WITH },
	{ "SETUP_ASYNC_WITH", anal_SETUP_ASYNC_WITH },
};

void anal_pyc_op(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg) {
	size_t i;
	for (i = 0; i < (sizeof (op_anal) / sizeof (op_anal_func)); i++) {
		if (!strcmp (op_anal[i].op_name, op_obj->op_name)) {
			op_anal[i].func (op, op_obj, oparg);
			break;
		}
	}
}
