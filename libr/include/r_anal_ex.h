/* radare - Apache 2.0 - Copyright 2013 - Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */
#include <r_anal.h>

#ifndef R2_ANAL_EX_H
#define R2_ANAL_EX_H
#undef R_API
#define R_API

enum {
	R_ANAL_EX_FMT_EXEC,
	R_ANAL_EX_FMT_DATA,
	R_ANAL_EX_FMT_MIXED,
};

typedef struct r_anal_ex_op_to_str_t {
	const char *str;
	ut32 value;
} RAnalExOpToStr;

enum {
	R_ANAL_EX_ILL_OP  =-1,   /* illegal instruction // trap */
	R_ANAL_EX_NULL_OP = 0,
	R_ANAL_EX_NOP = 1, /* does nothing */
	R_ANAL_EX_STORE_OP  = 1 << 20,  // Load or Store memory operation
	R_ANAL_EX_LOAD_OP   = 1 << 21,  // Load or Store memory operation
	R_ANAL_EX_REG_OP	= 1 << 22,  // register operation
	R_ANAL_EX_OBJ_OP	= 1 << 23,  // operates on an object
	R_ANAL_EX_STACK_OP  = 1 << 25,  // stack based operation
	R_ANAL_EX_BIN_OP	= 1 << 26,  // binary operation
	R_ANAL_EX_CODE_OP   = 1 << 27,  // operates on code
	R_ANAL_EX_DATA_OP   = 1 << 28,  // operates on data
	R_ANAL_EX_UNK_OP  = 1 << 29,  /* unknown opcode type */
	R_ANAL_EX_REP_OP  = 1 << 30,  /* repeats next instruction N times */
	R_ANAL_EX_COND_OP = 1 << 31, 
};

enum {
	R_ANAL_EX_TYPE_REF_NULL  = 0,
	R_ANAL_EX_TYPE_REF_UNK   = 1 << 1, 
	R_ANAL_EX_TYPE_REF	   = 1 << 2, 
	R_ANAL_EX_TYPE_SIGNED	= 1 << 3,
	R_ANAL_EX_TYPE_PRIM	  = 1 << 4, 
	R_ANAL_EX_TYPE_CONST	 = 1 << 5,
	R_ANAL_EX_TYPE_STATIC	= 1 << 6,
	R_ANAL_EX_TYPE_VOLATILE  = 1 << 7,
	R_ANAL_EX_TYPE_PUBLIC	= 1 << 8,

	R_ANAL_EX_TYPE_BOOL   = 1 << 10,
	R_ANAL_EX_TYPE_BYTE   = 1 << 11,
	R_ANAL_EX_TYPE_SHORT  = 1 << 12,
	R_ANAL_EX_TYPE_INT32  = 1 << 13,
	R_ANAL_EX_TYPE_INTEGER = 1 << 13,
	R_ANAL_EX_TYPE_INT64  = 1 << 14, 
	R_ANAL_EX_TYPE_LONG   = 1 << 14, 
	R_ANAL_EX_TYPE_FLOAT  = 1 << 15, 
	R_ANAL_EX_TYPE_DOUBLE = 1 << 16, 
	R_ANAL_EX_TYPE_STRING = 1 << 17, 
	R_ANAL_EX_TYPE_CHAR   = 1 << 18,
	R_ANAL_EX_TYPE_VOID   = 1 << 19,
};

// code ops
enum {
	R_ANAL_EX_CODEOP_JMP	= 1 << 1  | R_ANAL_EX_CODE_OP,/* mandatory jump */
	R_ANAL_EX_CODEOP_CALL   = 1 << 2  | R_ANAL_EX_CODE_OP,/* call to subroutine (branch+link) */
	R_ANAL_EX_CODEOP_RET	= 1 << 3  | R_ANAL_EX_CODE_OP,/* returns from subrutine */
	R_ANAL_EX_CODEOP_TRAP   = 1 << 4  | R_ANAL_EX_CODE_OP,/* it's a trap! */
	R_ANAL_EX_CODEOP_SWI	= 1 << 5  | R_ANAL_EX_CODE_OP,/* syscall  software interrupt */
	R_ANAL_EX_CODEOP_IO	 = 1 << 6  | R_ANAL_EX_CODE_OP,
	R_ANAL_EX_CODEOP_LEAVE  = 1 << 7  | R_ANAL_EX_CODE_OP,
	R_ANAL_EX_CODEOP_SWITCH = 1 << 8  | R_ANAL_EX_CODE_OP,
	R_ANAL_EX_CODEOP_CJMP   = R_ANAL_EX_COND_OP | R_ANAL_EX_CODE_OP | R_ANAL_EX_CODEOP_JMP,
	R_ANAL_EX_CODEOP_EOB	= R_ANAL_EX_CODEOP_JMP | R_ANAL_EX_CODEOP_RET | R_ANAL_EX_CODEOP_LEAVE | R_ANAL_EX_CODEOP_SWITCH,
};

enum {
	// call return types
	R_ANAL_EX_RET_TYPE_REF_NULL = 1 << 10,
	R_ANAL_EX_RET_TYPE_REF	  = 1 << 11 ,
	R_ANAL_EX_RET_TYPE_PRIM	 = 1 << 12 ,
	R_ANAL_EX_RET_TYPE_CONST	= 1 << 13,
	R_ANAL_EX_RET_TYPE_STATIC   = 1 << 14,
};

// jmp conditionals
enum {
	// TODO these should be mapped to some sort of
	// flags register
	R_ANAL_EX_COND_EQ  = 1 << 11,
	R_ANAL_EX_COND_NE  = 1 << 12,
	R_ANAL_EX_COND_GE  = 1 << 13,
	R_ANAL_EX_COND_GT  = 1 << 14,
	R_ANAL_EX_COND_LE  = 1 << 15,
	R_ANAL_EX_COND_LT  = 1 << 16,
	R_ANAL_EX_COND_AL  = 1 << 17,
	R_ANAL_EX_COND_NV  = 1 << 18,
	R_ANAL_EX_COND_NULL  = 1 << 19,
};

// bin ops
enum {
	R_ANAL_EX_BINOP_NEG = 0 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_XCHG = 1 << 1 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_CMP  = 1 << 2  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_ADD  = 1 << 3  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_SUB  = 1 << 4  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_MUL  = 1 << 6  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_DIV  = 1 << 7  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_SHR  = 1 << 8  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_SHL  = 1 << 9  | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_SAL  = 1 << 10 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_SAR  = 1 << 11 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_OR   = 1 << 12 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_AND  = 1 << 14 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_XOR  = 1 << 15 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_NOT  = 1 << 16 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_MOD  = 1 << 17 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_ROR  = 1 << 18 | R_ANAL_EX_BIN_OP,
	R_ANAL_EX_BINOP_ROL  = 1 << 19 | R_ANAL_EX_BIN_OP,
};

// Object ops
enum {
	R_ANAL_EX_OBJOP_CAST  = 1 << 0 | R_ANAL_EX_OBJ_OP,
	R_ANAL_EX_OBJOP_CHECK = 1 << 1 | R_ANAL_EX_OBJ_OP,
	R_ANAL_EX_OBJOP_NEW   = 1 << 2 | R_ANAL_EX_OBJ_OP,
	R_ANAL_EX_OBJOP_DEL   = 1 << 3 | R_ANAL_EX_OBJ_OP,
	R_ANAL_EX_OBJOP_SIZE   = 1 << 4 | R_ANAL_EX_OBJ_OP,
};


// Memory or Data Operations
// Locations of item loaded (base of indirect)
enum {
	R_ANAL_EX_LDST_FROM_REF   =  1 << 1,
	R_ANAL_EX_LDST_FROM_MEM   =  1 << 1,

	R_ANAL_EX_LDST_FROM_REG   =  1 << 2,
	R_ANAL_EX_LDST_FROM_STACK =  1 << 3,
	R_ANAL_EX_LDST_FROM_CONST =  1 << 4,
	R_ANAL_EX_LDST_FROM_VAR   =  1 << 5,

	// If indirect load, where are we getting the indirection,
	R_ANAL_EX_LDST_INDIRECT_REF  = 1 << 6,
	R_ANAL_EX_LDST_INDIRECT_MEM  = 1 << 6,

	R_ANAL_EX_LDST_INDIRECT_REG   =  1 << 7,
	R_ANAL_EX_LDST_INDIRECT_STACK =  1 << 8,
	R_ANAL_EX_LDST_INDIRECT_IDX   =  1 << 9,
	R_ANAL_EX_LDST_INDIRECT_VAR   =  1 << 10,

	// Location to put the item,
	R_ANAL_EX_LDST_TO_REF  = 1 << 11,
	R_ANAL_EX_LDST_TO_MEM  = 1 << 11,

	R_ANAL_EX_LDST_TO_REG = 1 << 12,
	R_ANAL_EX_LDST_TO_STACK =  1 << 13,
	R_ANAL_EX_LDST_TO_VAR =    1 << 14,

	// Stack, Memory, Register, Bss, Data ,
	R_ANAL_EX_LDST_OP_PUSH  = 1 << 15  ,
	R_ANAL_EX_LDST_OP_POP   = 1 << 16,
	R_ANAL_EX_LDST_OP_MOV   = 1 << 17 ,
	R_ANAL_EX_LDST_OP_EFF_ADDR   = 1 << 18,
};

enum {
	R_ANAL_EX_CODEOP_UCALL = R_ANAL_EX_UNK_OP | R_ANAL_EX_CODEOP_CALL,
	R_ANAL_EX_CODEOP_UJMP  = R_ANAL_EX_UNK_OP | R_ANAL_EX_CODEOP_JMP,
	R_ANAL_EX_LDST_OP_UPUSH = R_ANAL_EX_UNK_OP | R_ANAL_EX_LDST_OP_PUSH,
	R_ANAL_EX_LDST_OP_UPOP  = R_ANAL_EX_UNK_OP | R_ANAL_EX_LDST_OP_POP,
};

enum {

	R_ANAL_EX_LDST_LOAD_FROM_CONST_REF_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		R_ANAL_EX_LOAD_OP |\
		R_ANAL_EX_LDST_FROM_REF |\
		R_ANAL_EX_LDST_FROM_CONST |\
		R_ANAL_EX_LDST_TO_STACK |\
		R_ANAL_EX_TYPE_REF,
		 


	R_ANAL_EX_LDST_LOAD_FROM_CONST_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		R_ANAL_EX_LOAD_OP |\
		R_ANAL_EX_LDST_FROM_CONST |\
		R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_CONST_INDIRECT_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		R_ANAL_EX_LOAD_OP |\
		R_ANAL_EX_LDST_FROM_CONST |\
		R_ANAL_EX_LDST_INDIRECT_IDX |\
		R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_VAR |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_VAR |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_VAR_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_VAR |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_VAR_TO_STACK_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_VAR |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_REF |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_REF |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_STACK, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_VAR, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_INDIRECT_IDX |\
		 R_ANAL_EX_LDST_TO_VAR, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_TO_VAR = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_TO_VAR, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_TO_VAR_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_TO_VAR, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_TO_REF, 

	R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_REF_REF = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_STORE_OP |\
		 R_ANAL_EX_LDST_FROM_STACK |\
		 R_ANAL_EX_LDST_TO_REF, 

	R_ANAL_EX_LDST_LOAD_FROM_REF_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		 R_ANAL_EX_LOAD_OP |\
		 R_ANAL_EX_LDST_FROM_REF |\
		 R_ANAL_EX_LDST_TO_STACK |\
		 R_ANAL_EX_TYPE_PRIM,

	R_ANAL_EX_LDST_LOAD_FROM_PRIM_VAR_TO_STACK = R_ANAL_EX_LDST_OP_PUSH |\
		   R_ANAL_EX_LOAD_OP |\
		   R_ANAL_EX_LDST_FROM_VAR |\
		   R_ANAL_EX_TYPE_PRIM,

	R_ANAL_EX_LDST_LOAD_GET_STATIC = R_ANAL_EX_LDST_OP_PUSH |\
		R_ANAL_EX_LOAD_OP |\
		R_ANAL_EX_LDST_FROM_REF |\
		R_ANAL_EX_LDST_TO_STACK |\
		R_ANAL_EX_TYPE_REF,

	R_ANAL_EX_LDST_STORE_PUT_STATIC = R_ANAL_EX_LDST_OP_POP |\
		R_ANAL_EX_STORE_OP |\
		R_ANAL_EX_LDST_FROM_STACK |\
		R_ANAL_EX_LDST_TO_REF |\
		R_ANAL_EX_TYPE_REF,

	R_ANAL_EX_LDST_LOAD_GET_FIELD = R_ANAL_EX_LDST_OP_PUSH |\
		R_ANAL_EX_LOAD_OP |\
		R_ANAL_EX_LDST_FROM_REF |\
		R_ANAL_EX_LDST_TO_STACK |\
		R_ANAL_EX_TYPE_REF,

	R_ANAL_EX_LDST_STORE_PUT_FIELD = R_ANAL_EX_LDST_OP_POP |\
		R_ANAL_EX_STORE_OP |\
		R_ANAL_EX_LDST_FROM_STACK |\
		R_ANAL_EX_LDST_TO_REF |\
		R_ANAL_EX_TYPE_REF,
};

// BB and OP 
R_API ut64 r_anal_ex_map_anal_ex_to_anal_op_type(ut64 ranal2_op_type);
R_API void r_anal_ex_op_to_bb(RAnal *anal, RAnalState *state, RAnalBlock *bb, RAnalOp *op);
R_API int r_anal_ex_is_op_type_eop(ut64 x);

R_API ut64 r_anal_ex_map_anal_ex_to_anal_bb_type (ut64 ranal2_op_type);

/* by default performs recursive descent, but is anal->analysis_algorithm
 * is present, then that will be the algorithm used for analyzing the code 
 * or data
 */
R_API RList * r_anal_ex_analyze( RAnal *anal, RAnalState *state, ut64 addr);
R_API RList * r_anal_ex_analysis_driver( RAnal *anal, RAnalState *state, ut64 addr);
R_API RList * r_anal_ex_perform_analysis( RAnal *anal, RAnalState *state, ut64 addr);

// BB and OP handling
R_API void r_anal_ex_update_bb_cfg_head_tail( RAnalBlock *start, RAnalBlock * head, RAnalBlock * tail );
R_API RAnalOp * r_anal_ex_get_op(RAnal *anal, RAnalState *state, ut64 addr);
R_API RAnalBlock * r_anal_ex_get_bb(RAnal *anal, RAnalState *state, ut64 addr);
R_API void r_anal_ex_clone_op_switch_to_bb (RAnalBlock *bb, RAnalOp *op);

// used to perform comparisons on BB to determine if BB are in same body
R_API int r_anal_ex_bb_head_comparator(RAnalBlock *a, RAnalBlock *b);
// compare two BB to see if they are equal
R_API int r_anal_ex_bb_address_comparator(RAnalBlock *a, RAnalBlock *b);


// Type definitions to strings
#define R_ANAL_EX_TYPE_REF_NULL_STR "null"
#define R_ANAL_EX_TYPE_UNK_REF_STR "unk_ref"
#define R_ANAL_EX_TYPE_REF_STR "ref"
#define R_ANAL_EX_TYPE_SIGNED_STR "signed"
#define R_ANAL_EX_TYPE_PRIM_STR "prim"
#define R_ANAL_EX_TYPE_CONST_STR "const"
#define R_ANAL_EX_TYPE_STATIC_STR "static"
#define R_ANAL_EX_TYPE_VOLATILE_STR "volatile"
#define R_ANAL_EX_TYPE_PUBLIC_STR "public"
#define R_ANAL_EX_TYPE_BOOL_STR "bool"
#define R_ANAL_EX_TYPE_BYTE_STR "byte"
#define R_ANAL_EX_TYPE_SHORT_STR "short"
#define R_ANAL_EX_TYPE_INT32_STR "int32"
#define R_ANAL_EX_TYPE_INT64_STR "int64"
#define R_ANAL_EX_TYPE_FLOAT_STR "float"
#define R_ANAL_EX_TYPE_DOUBLE_STR "double"

// Conditional Strings
#define R_ANAL_EX_COND_EQ_STR "=="
#define R_ANAL_EX_COND_NE_STR "!="
#define R_ANAL_EX_COND_GE_STR ">="
#define R_ANAL_EX_COND_GT_STR ">"
#define R_ANAL_EX_COND_LE_STR "<="
#define R_ANAL_EX_COND_LT_STR "<"
#define R_ANAL_EX_COND_AL_STR "==="
#define R_ANAL_EX_COND_NV_STR "is_zero"
#define R_ANAL_EX_COND_NULL_STR "is_null"

// Operation types
#define R_ANAL_EX_ILL_OP_STR    "op_illegal"
#define R_ANAL_EX_NULL_OP_STR   "op_null"
#define R_ANAL_EX_NOP_OP_STR    "op_nop"
#define R_ANAL_EX_STORE_OP_STR  "op_store"
#define R_ANAL_EX_LOAD_OP_STR   "op_"
#define R_ANAL_EX_REG_OP_STR    "op_reg"
#define R_ANAL_EX_OBJ_OP_STR    "op_obj"
#define R_ANAL_EX_STACK_OP_STR  "op_stack"
#define R_ANAL_EX_BIN_OP_STR    "op_bin"
#define R_ANAL_EX_CODE_OP_STR   "op_code"
#define R_ANAL_EX_DATA_OP_STR   "op_data"
#define R_ANAL_EX_UNK_OP_STR  "op_unk"
#define R_ANAL_EX_REP_OP_STR  "op_rep"
#define R_ANAL_EX_COND_OP_STR "op_cond"

// Code operation Strings
#define R_ANAL_EX_CODEOP_JMP_STR "jmp"
#define R_ANAL_EX_CODEOP_CALL_STR "call"
#define R_ANAL_EX_CODEOP_RET_STR "ret"
#define R_ANAL_EX_CODEOP_TRAP_STR "trap"
#define R_ANAL_EX_CODEOP_SWI_STR "swi"
#define R_ANAL_EX_CODEOP_IO_STR "io"
#define R_ANAL_EX_CODEOP_LEAVE_STR "leave"
#define R_ANAL_EX_CODEOP_SWITCH_STR "switch"
#define R_ANAL_EX_CODEOP_CJMP_STR_STR "cjmp"
#define R_ANAL_EX_CODEOP_EOB_STR_STR "eob"

// Return Type Strings
#define R_ANAL_EX_RET_TYPE_REF_NULL_STR "ref_null"
#define R_ANAL_EX_RET_TYPE_REF_STR "ref"
#define R_ANAL_EX_RET_TYPE_PRIM_STR "prim"
#define R_ANAL_EX_RET_TYPE_CONST_STR "const"
#define R_ANAL_EX_RET_TYPE_STATIC_STR "static"

// Binary operation Strings
#define R_ANAL_EX_BINOP_XCHG_STR "xchg"
#define R_ANAL_EX_BINOP_CMP_STR  "cmp"
#define R_ANAL_EX_BINOP_ADD_STR  "add"
#define R_ANAL_EX_BINOP_SUB_STR  "sub"
#define R_ANAL_EX_BINOP_MUL_STR  "mul"
#define R_ANAL_EX_BINOP_DIV_STR  "div"
#define R_ANAL_EX_BINOP_SHR_STR  "shr"
#define R_ANAL_EX_BINOP_SHL_STR  "shl"
#define R_ANAL_EX_BINOP_SAL_STR  "sal"
#define R_ANAL_EX_BINOP_SAR_STR  "sar"
#define R_ANAL_EX_BINOP_OR_STR   "or"
#define R_ANAL_EX_BINOP_AND_STR  "and"
#define R_ANAL_EX_BINOP_XOR_STR  "xor"
#define R_ANAL_EX_BINOP_NOT_STR  "not"
#define R_ANAL_EX_BINOP_MOD_STR  "mod"
#define R_ANAL_EX_BINOP_ROR_STR  "ror"
#define R_ANAL_EX_BINOP_ROL_STR  "rol"

// Object operations strings
#define R_ANAL_EX_OBJOP_CAST_STR "cast"
#define R_ANAL_EX_OBJOP_CHECK_STR "typecheck"
#define R_ANAL_EX_OBJOP_NEW_STR "new"
#define R_ANAL_EX_OBJOP_DEL_STR "del"
#define R_ANAL_EX_OBJOP_SIZE_STR "size"

// Load and Store Operations Info Strings
#define R_ANAL_EX_LDST_FROM_REF_STR "from_ref"
#define R_ANAL_EX_LDST_FROM_MEM_STR "from mem"
#define R_ANAL_EX_LDST_FROM_REG_STR "from_reg"
#define R_ANAL_EX_LDST_FROM_STACK_STR "from_stack"
#define R_ANAL_EX_LDST_FROM_CONST_STR "from_const"
#define R_ANAL_EX_LDST_FROM_VAR_STR "from_var"
#define R_ANAL_EX_LDST_INDIRECT_REF_STR "indirect_ref"
#define R_ANAL_EX_LDST_INDIRECT_MEM_STR "indirect mem"
#define R_ANAL_EX_LDST_INDIRECT_REG_STR "indirect_reg"
#define R_ANAL_EX_LDST_INDIRECT_STACK_STR "indirect_stack"
#define R_ANAL_EX_LDST_INDIRECT_IDX_STR "indirect_idx"
#define R_ANAL_EX_LDST_INDIRECT_VAR_STR "indirect_var"
#define R_ANAL_EX_LDST_TO_REF_STR "to_ref"
#define R_ANAL_EX_LDST_TO_MEM_STR "to mem"
#define R_ANAL_EX_LDST_TO_REG_STR "to_reg"
#define R_ANAL_EX_LDST_TO_STACK_STR "to_stack"
#define R_ANAL_EX_LDST_TO_VAR_STR "to_var"

#define R_ANAL_EX_LDST_OP_PUSH_STR "push"
#define R_ANAL_EX_LDST_OP_POP_STR "pop"
#define R_ANAL_EX_LDST_OP_TYPE_MOV_STR "mov"
#define R_ANAL_EX_LDST_OP_TYPE_EFF_ADDR_STR "eff_addr"

// Compound Operation Strings
#define R_ANAL_EX_LDST_LOAD_FROM_CONST_REF_TO_STACK_STR "load from_const ref to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_CONST_TO_STACK_STR "load from_const to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_CONST_INDIRECT_TO_STACK_STR "load from_const indirect to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK_STR "load from_var indirect_idx to stack"
#define R_ANAL_EX_LDST_LOAD_FROM_VAR_INDIRECT_TO_STACK_REF_STR "load from_var indirect_idx to_stack ref"
#define R_ANAL_EX_LDST_LOAD_FROM_VAR_TO_STACK_STR "load from_var to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_VAR_TO_STACK_REF_STR "load from_var to_stack ref"
#define R_ANAL_EX_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK_STR "load from_ref indirect_idx to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_REF_INDIRECT_TO_STACK_REF_STR "load from_ref indirect_idx to_stack ref"
#define R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR_STR "store from_stack indirect_idx to_var"
#define R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_VAR_REF_STR "store from_stack indirect_idx to_var ref"
#define R_ANAL_EX_LDST_STORE_FROM_STACK_TO_VAR_STR "store from_stack to_var"
#define R_ANAL_EX_LDST_STORE_FROM_STACK_TO_VAR_REF_STR "store from_stack to_var ref"
#define R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_REF_STR "store from_stack indirect_idx to_ref"}
#define R_ANAL_EX_LDST_STORE_FROM_STACK_INDIRECT_TO_REF_REF_STR "store from_stack indirect_idx to_ref ref"}
#define R_ANAL_EX_LDST_LOAD_FROM_REF_TO_STACK_STR "load from_ref to_stack"
#define R_ANAL_EX_LDST_LOAD_FROM_PRIM_VAR_TO_STACK_STR "load from_var to_stack"
#define R_ANAL_EX_LDST_LOAD_GET_STATIC_STR "load from_ref to_stack ref"
#define R_ANAL_EX_LDST_STORE_PUT_STATIC_STR "store from_stack to_ref"
#define R_ANAL_EX_LDST_LOAD_GET_FIELD_STR "load from_ref to_stack ref"
#define R_ANAL_EX_LDST_STORE_PUT_FIELD_STR "load from_ref to_stack ref"

#endif
