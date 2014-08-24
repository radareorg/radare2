/* radare - Apache 2.0 - Copyright 2013 - Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_anal.h>
#include <r_anal_ex.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include "../config.h"

#ifdef IFDBG
#undef IFDBG
#endif

#define DO_THE_DBG 0
#define IFDBG  if(DO_THE_DBG)
#define IFINT  if(0)


static void r_anal_ex_perform_pre_anal(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_ex_perform_pre_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_ex_perform_pre_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);
//static void r_anal_ex_perform_pre_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr);

static void r_anal_ex_perform_post_anal(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_ex_perform_post_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_ex_perform_post_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);
//static void r_anal_ex_perform_post_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr);

static void r_anal_ex_perform_revisit_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);

ut64 extract_code_op(ut64 ranal2_op_type);
ut64 extract_load_store_op(ut64 ranal2_op_type);
ut64 extract_unknown_op(ut64 ranal2_op_type);
ut64 extract_bin_op(ut64 ranal2_op_type);


static void r_anal_ex_perform_pre_anal(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal) {
		anal->cur->pre_anal (anal, state, addr);
	}
}

static void r_anal_ex_perform_pre_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_op_cb) {
		anal->cur->pre_anal_op_cb (anal, state, addr);
	}
}

static void r_anal_ex_perform_pre_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_bb_cb) {
		anal->cur->pre_anal_bb_cb (anal, state, addr);
	}
}

/*static void r_anal_ex_perform_pre_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_fn_cb) {
		anal->cur->pre_anal_fn_cb (anal, state, addr);
	}
}*/

static void r_anal_ex_perform_post_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_op_cb) {
		anal->cur->post_anal_op_cb (anal, state, addr);
	}
}

static void r_anal_ex_perform_post_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_bb_cb) {
		anal->cur->post_anal_bb_cb (anal, state, addr);
	}
}

/*static void r_anal_ex_perform_post_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_fn_cb) {
		anal->cur->post_anal_fn_cb (anal, state, addr);
	}
}*/

static void r_anal_ex_perform_post_anal(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal) {
		anal->cur->post_anal (anal, state, addr);
	}
}

static void r_anal_ex_perform_revisit_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->revisit_bb_anal) {
		anal->cur->revisit_bb_anal (anal, state, addr);
	}
}

R_API int r_anal_ex_bb_address_comparator(RAnalBlock *a, RAnalBlock *b){
	if (a->addr == b->addr)
		return 0;
	else if (a->addr < b->addr)
		return -1;
	// a->addr > b->addr
	return 1;
}

R_API int r_anal_ex_bb_head_comparator(RAnalBlock *a, RAnalBlock *b){
	if (a->head == b->head)
		return 0;
	else if (a->head < b->head )
		return -1;
	// a->head > b->head
	return 1;
}

R_API void r_anal_ex_clone_op_switch_to_bb (RAnalBlock *bb, RAnalOp *op) {
	RListIter *iter;
	RAnalCaseOp *caseop = NULL;

	if ( op->switch_op ) {

		bb->switch_op = r_anal_switch_op_new (op->switch_op->addr,
											op->switch_op->min_val,
											op->switch_op->max_val);

		r_list_foreach (op->switch_op->cases, iter, caseop) {
			r_anal_switch_op_add_case (bb->switch_op, caseop->addr,
													caseop->value, caseop->jump);
		}
	}
}

R_API RAnalOp * r_anal_ex_get_op(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalOp *current_op = state->current_op;
	const ut8 * data;
	// current_op set in a prior stage
	if (current_op) return current_op;
	IFDBG eprintf("[==] r_anal_ex_get_op: Parsing op @ 0x%04"PFMT64x"\n", addr);

	if (anal->cur == NULL ||
		(anal->cur->op_from_buffer == NULL && anal->cur->op == NULL) ) {
		return NULL;
	}


	if (!r_anal_state_addr_is_valid(state, addr) ||
		(anal->cur && (anal->cur->op == NULL && anal->cur->op_from_buffer == NULL))) {
		state->done = 1;
		return NULL;
	}
	data = r_anal_state_get_buf_by_addr(state, addr);

	if (anal->cur->op_from_buffer) {
		current_op = anal->cur->op_from_buffer (anal, addr, data,  r_anal_state_get_len( state, addr) );
	} else {
		current_op = r_anal_op_new();
		anal->cur->op (anal, current_op, addr, data,  r_anal_state_get_len( state, addr) );
	}

	state->current_op = current_op;
	return current_op;

}

R_API RAnalBlock * r_anal_ex_get_bb(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalBlock *current_bb = state->current_bb;
	RAnalOp *op = state->current_op;
	static ut64 test = 0;

	// current_bb set before in a pre-analysis stage.
	if (current_bb) return current_bb;
	IFDBG eprintf("[==] r_anal_ex_get_bb: Parsing op @ 0x%04"PFMT64x"\n", addr);

	if (r_anal_state_addr_is_valid(state, addr) && op == NULL)
		op = r_anal_ex_get_op(anal, state, addr);

	if (op == NULL || !r_anal_state_addr_is_valid(state, addr)) return NULL;

	current_bb = r_anal_bb_new ();
	r_anal_ex_op_to_bb(anal, state, current_bb, op);

	if (r_anal_op_is_eob (op))
		current_bb->type |= R_ANAL_BB_TYPE_LAST;

	if (current_bb->op_bytes == NULL) {
		current_bb->op_sz = state->current_op->size;
		current_bb->op_bytes = malloc(current_bb->op_sz);
		if (current_bb->op_bytes) {
			memcpy(current_bb->op_bytes, r_anal_state_get_buf_by_addr(state, addr), current_bb->op_sz);
		}
	}
	state->current_bb = current_bb;
	// this can be overridden in a post_bb_anal_cb
	state->next_addr = addr + current_bb->op_sz;
	current_bb->op_sz = state->current_op->size;
	test += current_bb->op_sz;
	IFDBG eprintf("[==] r_anal_ex_get_bb: op size @ 0x%04x seen 0x%04"PFMT64x"\n", state->current_op->size, test);

	return current_bb;
}

R_API void r_anal_ex_update_bb_cfg_head_tail( RAnalBlock *start, RAnalBlock * head, RAnalBlock * tail ) {
	RAnalBlock *bb = start;

	if (bb) {
		bb->head = head;
		bb->tail = tail;
	}

	if (bb && bb->next){
		bb->head = head;
		bb->tail = tail;
		do {
			bb->next->prev = bb;
			bb = bb->next;
			bb->head = head;
			bb->tail = tail;
		}while (bb->next != NULL && !(bb->type & R_ANAL_BB_TYPE_TAIL));
	}
}

R_API RList * r_anal_ex_perform_analysis( RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->analysis_algorithm)
		return anal->cur->analysis_algorithm (anal, state, addr);

	return r_anal_ex_analysis_driver (anal, state, addr);
}

R_API RList * r_anal_ex_analysis_driver( RAnal *anal, RAnalState *state, ut64 addr ) {
	ut64 bytes_consumed = 0,
		 len = r_anal_state_get_len (state, addr);

	RAnalBlock *pcurrent_bb = state->current_bb,
			   *pcurrent_head = state->current_bb_head,
				*past_bb = NULL;
	RAnalOp * pcurrent_op = state->current_op;

	ut64 backup_addr = state->current_addr;
	state->current_addr = addr;

	RList *bb_list = r_anal_bb_list_new ();

	if (state->done)
		return bb_list;

	state->current_bb_head = NULL;
	state->current_bb = NULL;
	state->current_op = NULL;


	r_anal_ex_perform_pre_anal (anal, state, state->current_addr);

	while (!state->done && bytes_consumed < len) {


		state->current_bb = r_anal_state_search_bb (state, state->current_addr);
		// check state for bb

		if (state->current_bb) {
			// TODO something special should happen here.

			r_anal_ex_perform_revisit_bb_cb (anal, state, state->current_addr);
			bytes_consumed += state->current_bb->op_sz;
			if ( state->done) break;
			continue;
		}

		r_anal_ex_perform_pre_anal_op_cb (anal, state, state->current_addr);
		if (state->done) break;

	   	r_anal_ex_get_op (anal, state, state->current_addr);
		r_anal_ex_perform_post_anal_op_cb (anal, state, state->current_addr);
		if (state->done) break;


		r_anal_ex_perform_pre_anal_bb_cb (anal, state, state->current_addr);
		if (state->done) break;


		r_anal_ex_get_bb (anal, state, state->current_addr);


		if ( state->current_bb_head == NULL ) {
			state->current_bb_head = state->current_bb;
			state->current_bb_head->type |= R_ANAL_BB_TYPE_HEAD;
		}

		if (past_bb) {
			past_bb->next = state->current_bb;
			state->current_bb->prev = past_bb;
		}

		past_bb = state->current_bb;

		r_anal_state_insert_bb (state, state->current_bb);
		r_list_append (bb_list, state->current_bb);


		r_anal_ex_perform_post_anal_bb_cb (anal, state, state->current_addr);
		if (state->done) {
			break;
		}

		bytes_consumed += state->current_bb->op_sz;
		state->current_addr = state->next_addr;
		r_anal_op_free (state->current_op);

		state->current_op = NULL;
		state->current_bb = NULL;
		IFDBG eprintf ("[=*=] Bytes consumed overall: %"PFMT64d" locally: %"PFMT64d" of %"PFMT64d"\n", state->bytes_consumed, bytes_consumed, len);
	}


	r_anal_op_free (state->current_op);
	r_anal_ex_perform_post_anal (anal, state, addr);
	state->current_op = pcurrent_op;
	state->current_bb = pcurrent_bb;
	state->current_bb_head = pcurrent_head;
	state->current_addr = backup_addr;
	return bb_list;
}

R_API void r_anal_ex_op_to_bb(RAnal *anal, RAnalState *state, RAnalBlock *bb, RAnalOp *op) {
	//ut64 cnd_jmp = (R_ANAL_EX_COND_OP | R_ANAL_EX_CODEOP_JMP);
	bb->addr = op->addr;
	bb->size = op->size;
	bb->type2 = op->type2;
	bb->type = r_anal_ex_map_anal_ex_to_anal_bb_type ( op->type2 );
	bb->fail = op->fail;
	bb->jump = op->jump;

	bb->conditional = R_ANAL_EX_COND_OP & op->type2 ? R_ANAL_OP_TYPE_COND : 0;
	if (r_anal_op_is_eob (op))
		bb->type |= R_ANAL_BB_TYPE_LAST;
	r_anal_ex_clone_op_switch_to_bb (bb, op);
}

R_API ut64 r_anal_ex_map_anal_ex_to_anal_bb_type (ut64 ranal2_op_type) {
	ut64 bb_type = 0;
	ut64 conditional = (R_ANAL_EX_COND_OP & ranal2_op_type)?
		R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL_EX_CODE_OP | 0x1FF);

	if (conditional)
		bb_type |= R_ANAL_BB_TYPE_COND;
	if (ranal2_op_type & R_ANAL_EX_LOAD_OP)
		bb_type |= R_ANAL_BB_TYPE_LD;
	if (ranal2_op_type & R_ANAL_EX_BIN_OP)
		bb_type |= R_ANAL_BB_TYPE_BINOP;
	if (ranal2_op_type & R_ANAL_EX_LOAD_OP)
		bb_type |= R_ANAL_BB_TYPE_LD;
	if (ranal2_op_type & R_ANAL_EX_STORE_OP)
		bb_type |= R_ANAL_BB_TYPE_ST;
	/* mark bb with a comparison */
	if (ranal2_op_type & R_ANAL_EX_BINOP_CMP)
		bb_type |= R_ANAL_BB_TYPE_CMP;

	/* change in control flow here */
	if (code_op_val & R_ANAL_EX_CODEOP_JMP) {
		bb_type |= R_ANAL_BB_TYPE_JMP;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if (code_op_val & R_ANAL_EX_CODEOP_CALL) {
		bb_type |= R_ANAL_BB_TYPE_CALL;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if ( code_op_val & R_ANAL_EX_CODEOP_SWITCH) {
		bb_type |= R_ANAL_BB_TYPE_SWITCH;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if (code_op_val & R_ANAL_EX_CODEOP_LEAVE ||
				code_op_val & R_ANAL_EX_CODEOP_RET ) {
		bb_type |= R_ANAL_BB_TYPE_RET;
		bb_type |= R_ANAL_BB_TYPE_LAST;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	}

	if ( ranal2_op_type  & R_ANAL_EX_UNK_OP && code_op_val & R_ANAL_EX_CODEOP_JMP)
		bb_type |= R_ANAL_BB_TYPE_FOOT;

	if ( conditional && code_op_val & R_ANAL_EX_CODEOP_JMP)
		bb_type |= R_ANAL_BB_TYPE_BODY;

	return bb_type;
}

R_API int r_anal_ex_is_op_type_eop(ut64 x) {
	ut8 result = (x & R_ANAL_EX_CODE_OP) ? 1 : 0;
	return result &&
			( (x & R_ANAL_EX_CODEOP_LEAVE) == R_ANAL_EX_CODEOP_LEAVE ||
			 (x & R_ANAL_EX_CODEOP_RET) == R_ANAL_EX_CODEOP_RET ||
			 (x & R_ANAL_EX_CODEOP_JMP) == R_ANAL_EX_CODEOP_JMP ||
			 (x & R_ANAL_EX_CODEOP_SWITCH) == R_ANAL_EX_CODEOP_SWITCH);
}

ut64 extract_code_op(ut64 ranal2_op_type) {
	ut64 conditional = R_ANAL_EX_COND_OP & ranal2_op_type ? R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL_EX_CODE_OP | 0x1FF);
	switch (code_op_val) {
		case R_ANAL_EX_CODEOP_CALL : return conditional | R_ANAL_OP_TYPE_CALL;
		case R_ANAL_EX_CODEOP_JMP  : return conditional | R_ANAL_OP_TYPE_JMP;
		case R_ANAL_EX_CODEOP_RET  : return conditional | R_ANAL_OP_TYPE_RET;
		case R_ANAL_EX_CODEOP_LEAVE: return R_ANAL_OP_TYPE_LEAVE;
		case R_ANAL_EX_CODEOP_SWI  : return R_ANAL_OP_TYPE_SWI;
		case R_ANAL_EX_CODEOP_TRAP : return R_ANAL_OP_TYPE_TRAP;
		case R_ANAL_EX_CODEOP_SWITCH: return R_ANAL_OP_TYPE_SWITCH;
	}
	return R_ANAL_OP_TYPE_UNK;
}


ut64 extract_load_store_op(ut64 ranal2_op_type) {
	if ( (ranal2_op_type & R_ANAL_EX_LDST_OP_PUSH) == R_ANAL_EX_LDST_OP_PUSH)
		return R_ANAL_OP_TYPE_PUSH;
	if ( (ranal2_op_type & R_ANAL_EX_LDST_OP_POP) == R_ANAL_EX_LDST_OP_POP )
		return R_ANAL_OP_TYPE_POP;
	if ( (ranal2_op_type & R_ANAL_EX_LDST_OP_MOV) == R_ANAL_EX_LDST_OP_MOV)
		return R_ANAL_OP_TYPE_MOV;
	if ( (ranal2_op_type & R_ANAL_EX_LDST_OP_EFF_ADDR) == R_ANAL_EX_LDST_OP_EFF_ADDR)
		return R_ANAL_OP_TYPE_LEA;
	return R_ANAL_OP_TYPE_UNK;
}


ut64 extract_unknown_op(ut64 ranal2_op_type) {

	if ( (ranal2_op_type & R_ANAL_EX_CODEOP_JMP) == R_ANAL_EX_CODEOP_JMP )  return R_ANAL_OP_TYPE_UJMP;
	if ( (ranal2_op_type & R_ANAL_EX_CODEOP_CALL) == R_ANAL_EX_CODEOP_CALL) return R_ANAL_OP_TYPE_UCALL;
	if ( (ranal2_op_type & R_ANAL_EX_LDST_OP_PUSH) == R_ANAL_EX_LDST_OP_PUSH) return R_ANAL_OP_TYPE_UPUSH;
	return R_ANAL_OP_TYPE_UNK;
}

ut64 extract_bin_op(ut64 ranal2_op_type) {

	ut64 bin_op_val = ranal2_op_type & (R_ANAL_EX_BIN_OP | 0x80000);
	switch (bin_op_val) {
		case R_ANAL_EX_BINOP_XCHG:return R_ANAL_OP_TYPE_XCHG;
		case R_ANAL_EX_BINOP_CMP: return R_ANAL_OP_TYPE_CMP;
		case R_ANAL_EX_BINOP_ADD: return R_ANAL_OP_TYPE_ADD;
		case R_ANAL_EX_BINOP_SUB: return R_ANAL_OP_TYPE_SUB;
		case R_ANAL_EX_BINOP_MUL: return R_ANAL_OP_TYPE_MUL;
		case R_ANAL_EX_BINOP_DIV: return R_ANAL_OP_TYPE_DIV;
		case R_ANAL_EX_BINOP_SHR: return R_ANAL_OP_TYPE_SHR;
		case R_ANAL_EX_BINOP_SHL: return R_ANAL_OP_TYPE_SHL;
		case R_ANAL_EX_BINOP_SAL: return R_ANAL_OP_TYPE_SAL;
		case R_ANAL_EX_BINOP_SAR: return R_ANAL_OP_TYPE_SAR;
		case R_ANAL_EX_BINOP_OR : return R_ANAL_OP_TYPE_OR;
		case R_ANAL_EX_BINOP_AND: return R_ANAL_OP_TYPE_AND;
		case R_ANAL_EX_BINOP_XOR: return R_ANAL_OP_TYPE_XOR;
		case R_ANAL_EX_BINOP_NOT: return R_ANAL_OP_TYPE_NOT;
		case R_ANAL_EX_BINOP_MOD: return R_ANAL_OP_TYPE_MOD;
		case R_ANAL_EX_BINOP_ROR: return R_ANAL_OP_TYPE_ROR;
		case R_ANAL_EX_BINOP_ROL: return R_ANAL_OP_TYPE_ROL;
		default: break;
	}
	return R_ANAL_OP_TYPE_UNK;
}


R_API ut64 r_anal_ex_map_anal_ex_to_anal_op_type (ut64 ranal2_op_type) {

	switch (ranal2_op_type) {
		case R_ANAL_EX_NULL_OP: return R_ANAL_OP_TYPE_NULL;
		case R_ANAL_EX_NOP: return R_ANAL_OP_TYPE_NOP;
		case R_ANAL_EX_ILL_OP: return R_ANAL_OP_TYPE_ILL;
		default: break;
	}

	if ( ranal2_op_type & R_ANAL_EX_UNK_OP)
		return extract_unknown_op(ranal2_op_type);

	if ( ranal2_op_type & R_ANAL_EX_CODE_OP)
		return extract_code_op(ranal2_op_type);

	if ( ranal2_op_type & R_ANAL_EX_REP_OP)
		return R_ANAL_OP_TYPE_REP | r_anal_ex_map_anal_ex_to_anal_op_type ( ranal2_op_type & ~R_ANAL_EX_REP_OP );

	if ( ranal2_op_type & (R_ANAL_EX_LOAD_OP | R_ANAL_EX_STORE_OP ))
		return extract_load_store_op(ranal2_op_type);

	if ( ranal2_op_type & R_ANAL_EX_BIN_OP)
		return extract_bin_op(ranal2_op_type);

	return R_ANAL_OP_TYPE_UNK;
}

