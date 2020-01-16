/* radare - Apache 2.0 - Copyright 2013 - Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_anal.h>
#include <r_anal_ex.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include <config.h>

#ifdef IFDBG
#undef IFDBG
#endif

#define DO_THE_DBG 0
#define IFDBG  if(DO_THE_DBG)
#define IFINT  if(0)


static void r_anal_java_perform_pre_anal(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_java_perform_pre_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_java_perform_pre_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);
//static void r_anal_java_perform_pre_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr);

static void r_anal_java_perform_post_anal(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_java_perform_post_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr);
static void r_anal_java_perform_post_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);
//static void r_anal_java_perform_post_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr);

static void r_anal_java_perform_revisit_bb_cb(RAnal *anal, RAnalState *state, ut64 addr);

ut64 extract_load_store_op(ut64 ranal2_op_type);
ut64 extract_unknown_op(ut64 ranal2_op_type);

static void r_anal_java_perform_pre_anal(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->cur && anal->cur->pre_anal) {
		anal->cur->pre_anal (anal, state, addr);
	}
}

static void r_anal_java_perform_pre_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->cur && anal->cur->pre_anal_op_cb) {
		anal->cur->pre_anal_op_cb (anal, state, addr);
	}
}

static void r_anal_java_perform_pre_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->cur && anal->cur->pre_anal_bb_cb) {
		anal->cur->pre_anal_bb_cb (anal, state, addr);
	}
}

/*static void r_anal_java_perform_pre_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_fn_cb) {
		anal->cur->pre_anal_fn_cb (anal, state, addr);
	}
}*/

static void r_anal_java_perform_post_anal_op_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->use_ex && anal->cur && anal->cur->post_anal_op_cb) {
		anal->cur->post_anal_op_cb (anal, state, addr);
	}
}

static void r_anal_java_perform_post_anal_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->use_ex && anal->cur && anal->cur->post_anal_bb_cb) {
		anal->cur->post_anal_bb_cb (anal, state, addr);
	}
}

/*static void r_anal_java_perform_post_anal_fn_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_fn_cb) {
		anal->cur->post_anal_fn_cb (anal, state, addr);
	}
}*/

static void r_anal_java_perform_post_anal(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->cur && anal->cur->post_anal) {
		anal->cur->post_anal (anal, state, addr);
	}
}

static void r_anal_java_perform_revisit_bb_cb(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->use_ex && anal->cur && anal->cur->revisit_bb_anal) {
		anal->cur->revisit_bb_anal (anal, state, addr);
	}
}

R_API void r_anal_java_clone_op_switch_to_bb (RAnalBlock *bb, RAnalOp *op) {
	RListIter *iter;
	RAnalCaseOp *caseop = NULL;

	if (bb && op && op->switch_op) {
		bb->switch_op = r_anal_switch_op_new (op->switch_op->addr,
				op->switch_op->min_val,
				op->switch_op->max_val);
		r_list_foreach (op->switch_op->cases, iter, caseop) {
			r_anal_switch_op_add_case (bb->switch_op, caseop->addr,
					caseop->value, caseop->jump);
		}
	}
}

R_API RAnalOp * r_anal_java_get_op(RAnal *anal, RAnalState *state, ut64 addr, RAnalOpMask mask) {
	RAnalOp *current_op = state->current_op;
	const ut8 * data;
	// current_op set in a prior stage
	if (current_op) {
		return current_op;
	}
	if (!anal || !anal->cur || (!anal->cur->op_from_buffer && !anal->cur->op)) {
		return NULL;
	}
	if (!r_anal_state_addr_is_valid(state, addr) ||
		(anal->cur && (!anal->cur->op && !anal->cur->op_from_buffer))) {
		state->done = 1;
		return NULL;
	}
	data = r_anal_state_get_buf_by_addr(state, addr);
	if (anal->cur->op_from_buffer) {
		current_op = anal->cur->op_from_buffer (anal, addr, data,  r_anal_state_get_len (state, addr));
	} else {
		current_op = r_anal_op_new();
		anal->cur->op (anal, current_op, addr, data,  r_anal_state_get_len (state, addr), mask);
	}
	state->current_op = current_op;
	return current_op;
}

R_API RAnalBlock * r_anal_java_get_bb(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalBlock *current_bb = state->current_bb;
	RAnalOp *op = state->current_op;
	// current_bb set before in a pre-analysis stage.
	if (current_bb) {
		return current_bb;
	}
	if (r_anal_state_addr_is_valid (state, addr) && !op) {
		op = r_anal_java_get_op (anal, state, addr, R_ANAL_OP_MASK_ALL);
	}
	if (!op || !r_anal_state_addr_is_valid (state, addr)) {
		return NULL;
	}
	current_bb = r_anal_java_op_to_bb (anal, state, op);
	if (!current_bb) {
		return NULL;
	}
	if (!current_bb->op_bytes) {
		current_bb->op_sz = state->current_op->size;
		current_bb->op_bytes = malloc (current_bb->op_sz);
		if (current_bb->op_bytes) {
			int buf_len = r_anal_state_get_len (state, addr);
			if (current_bb->op_sz > buf_len) {
				r_anal_block_unref (current_bb);
				return NULL;
			}
			memcpy (current_bb->op_bytes,
				r_anal_state_get_buf_by_addr (state, addr),
				current_bb->op_sz);
		}
	}
	state->current_bb = current_bb;
	// this can be overridden in a post_bb_anal_cb
	state->next_addr = addr + current_bb->op_sz;
	current_bb->op_sz = state->current_op->size;
	return current_bb;
}

R_API RList* r_anal_java_perform_analysis(RAnal *anal, RAnalState *state, ut64 addr) {
	if (anal && anal->cur && anal->cur->analysis_algorithm) {
		return anal->cur->analysis_algorithm (anal, state, addr);
	}
	return r_anal_java_analysis_driver (anal, state, addr);
}

R_API RList* r_anal_java_analysis_driver(RAnal *anal, RAnalState *state, ut64 addr ) {
	ut64 consumed_iter = 0;
	ut64 bytes_consumed = 0, len = r_anal_state_get_len (state, addr);
	RAnalBlock *past_bb = NULL;
	RAnalOp *pcurrent_op = state->current_op;
	ut64 backup_addr = state->current_addr;
	state->current_addr = addr;
	RList *bb_list = r_list_newf ((RListFree)r_anal_block_unref);

	if (state->done) {
		return bb_list;
	}

	RAnalBlock *prev_current_bb = state->current_bb;
	state->current_bb = NULL;
	state->current_op = NULL;

	r_anal_java_perform_pre_anal (anal, state, state->current_addr);
	while (!state->done && bytes_consumed < len) {
		state->current_bb = r_anal_state_search_bb (state, state->current_addr);
		// check state for bb
		if (state->current_bb) {
			// TODO something special should happen here.
			r_anal_block_ref (state->current_bb);
			r_anal_java_perform_revisit_bb_cb (anal, state, state->current_addr);
			consumed_iter += state->current_bb->op_sz;
			bytes_consumed += state->current_bb->op_sz;
			if (state->current_bb) {
				r_anal_block_unref (state->current_bb);
				state->current_bb = NULL;
			}
			if (state->done) {
				break;
			}
			continue;
		}
		r_anal_java_perform_pre_anal_op_cb (anal, state, state->current_addr);
		if (state->done) {
			break;
		}
	   	r_anal_java_get_op (anal, state, state->current_addr, R_ANAL_OP_MASK_ALL);
		r_anal_java_perform_post_anal_op_cb (anal, state, state->current_addr);
		if (state->done) {
			break;
		}
		r_anal_java_perform_pre_anal_bb_cb (anal, state, state->current_addr);
		if (state->done) {
			break;
		}
		if (!r_anal_java_get_bb (anal, state, state->current_addr)) {
			break;
		}
		if (past_bb) {
			state->current_bb->prev = past_bb;
		}
		past_bb = state->current_bb;
		//state->current_bb is shared in two list and one ht!!! 
		//source of UAF this should be rewritten to avoid such errors 
		r_anal_state_insert_bb (state, state->current_bb);

		r_anal_block_ref (state->current_bb);
		r_list_append (bb_list, state->current_bb);

		r_anal_java_perform_post_anal_bb_cb (anal, state, state->current_addr);
		if (state->done) {
			break;
		}
		if (state->current_bb) {
			bytes_consumed += state->current_bb->op_sz;
			consumed_iter += state->current_bb->op_sz;
			r_anal_block_unref (state->current_bb);
			state->current_bb = NULL;
		}
		state->current_addr = state->next_addr;
		r_anal_op_free (state->current_op);
		state->current_op = NULL;
		if (!consumed_iter) {
			eprintf ("No bytes consumed, bailing!\n");
			break;
		}
		consumed_iter = 0;
	}

	if (state->current_bb) {
		r_anal_block_unref (state->current_bb);
	}
	r_anal_op_free (state->current_op);
	r_anal_java_perform_post_anal (anal, state, addr);
	state->current_op = pcurrent_op;
	state->current_bb = prev_current_bb;
	state->current_addr = backup_addr;
	return bb_list;
}

R_API RAnalBlock *r_anal_java_op_to_bb(RAnal *anal, RAnalState *state, RAnalOp *op) {
	RAnalBlock *block = r_anal_create_block (anal, op->addr, op->size);
	if (!block) {
		return NULL;
	}
	block->type2 = op->type2;
	block->type = r_anal_java_map_anal_ex_to_anal_bb_type ( op->type2 );
	block->fail = op->fail;
	block->jump = op->jump;
	block->conditional = R_ANAL_JAVA_COND_OP & op->type2 ? R_ANAL_OP_TYPE_COND : 0;
	r_anal_java_clone_op_switch_to_bb (block, op);
	return block;
}

R_API ut64 r_anal_java_map_anal_ex_to_anal_bb_type (ut64 ranal2_op_type) {
	ut64 bb_type = 0;
	ut64 conditional = (R_ANAL_JAVA_COND_OP & ranal2_op_type)?
		R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL_JAVA_CODE_OP | 0x1FF);

	if (conditional) {
		bb_type |= R_ANAL_BB_TYPE_COND;
	}
	if (ranal2_op_type & R_ANAL_JAVA_LOAD_OP) {
		bb_type |= R_ANAL_BB_TYPE_LD;
	}
	if (ranal2_op_type & R_ANAL_JAVA_BIN_OP) {
		bb_type |= R_ANAL_BB_TYPE_BINOP;
	}
	if (ranal2_op_type & R_ANAL_JAVA_LOAD_OP) {
		bb_type |= R_ANAL_BB_TYPE_LD;
	}
	if (ranal2_op_type & R_ANAL_JAVA_STORE_OP) {
		bb_type |= R_ANAL_BB_TYPE_ST;
	}
	/* mark bb with a comparison */
	if (ranal2_op_type & R_ANAL_JAVA_BINOP_CMP) {
		bb_type |= R_ANAL_BB_TYPE_CMP;
	}

	/* change in control flow here */
	if (code_op_val & R_ANAL_JAVA_CODEOP_JMP) {
		bb_type |= R_ANAL_BB_TYPE_JMP;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if (code_op_val & R_ANAL_JAVA_CODEOP_CALL) {
		bb_type |= R_ANAL_BB_TYPE_CALL;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if ( code_op_val & R_ANAL_JAVA_CODEOP_SWITCH) {
		bb_type |= R_ANAL_BB_TYPE_SWITCH;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	} else if (code_op_val & R_ANAL_JAVA_CODEOP_LEAVE ||
				code_op_val & R_ANAL_JAVA_CODEOP_RET ) {
		bb_type |= R_ANAL_BB_TYPE_RET;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	}

	return bb_type;
}


