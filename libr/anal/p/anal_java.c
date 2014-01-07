/* radare - Apache 2.0 - Copyright 2010-2013 - pancake and 
 Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_anal_ex.h>

#include "../../../shlr/java/code.h"
#include "../../../shlr/java/class.h"

#define IFDBG  if(0)
#define IFINT  if(0)


typedef struct r_anal_ex_java_lin_sweep {
	RList *cfg_node_addrs;
}RAnalJavaLinearSweep;

static int analyze_from_code_buffer ( RAnal *anal, RAnalFunction *fcn, ut64 addr, const ut8 *code_buf, ut64 code_length);
static int analyze_from_code_attr (RAnal *anal, RAnalFunction *fcn, const RBinJavaField *method);
static int analyze_method(RAnal *anal, RAnalFunction *fcn, RAnalState *state);

static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len);
//static int java_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype);
//static int java_fn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype);

static void java_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr);
static int handle_bb_cf_recursive_descent (RAnal *anal, RAnalState *state);

static void java_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr);
static int handle_bb_cf_linear_sweep (RAnal *anal, RAnalState *state);
static int java_post_anal_linear_sweep(RAnal *anal, RAnalState *state);



static int java_analyze_fns( RAnal *anal, ut64 start, ut64 end, int reftype, int depth);

static RAnalOp * java_op_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);
static RAnalBlock * java_bb_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);
static RAnalFunction * java_fn_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);

static int check_addr_in_code (RBinJavaField *method, ut64 addr);
static int check_addr_less_end (RBinJavaField *method, ut64 addr);
static int check_addr_less_start (RBinJavaField *method, ut64 addr);

static int java_revisit_bb_anal_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr);

static int check_addr_less_end (RBinJavaField *method, ut64 addr) {
	ut64 end = r_bin_java_get_method_code_size (method);
	if (addr < end)
		return R_TRUE;
	return R_FALSE;
}

static int check_addr_in_code (RBinJavaField *method, ut64 addr) {
	return !check_addr_less_start (method, addr) && \
		check_addr_less_end ( method, addr);
}

static int check_addr_less_start (RBinJavaField *method, ut64 addr) {
	ut64 start = r_bin_java_get_method_code_offset (method);
	if (addr < start)
		return R_TRUE;
	return R_FALSE;
}


static int java_revisit_bb_anal_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr) {
    RAnalBlock *current_head = state && state->current_bb_head ? state->current_bb_head : NULL;
	if (current_head && state->current_bb && 
		state->current_bb->type & R_ANAL_BB_TYPE_TAIL) {
		r_anal_ex_update_bb_cfg_head_tail (current_head, current_head, state->current_bb);
		// XXX should i do this instead -> r_anal_ex_perform_post_anal_bb_cb (anal, state, addr+offset);
        state->done = 1;
	}
	return R_ANAL_RET_END;
}

static void java_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalBlock *bb = state->current_bb;
	RAnalBlock *current_head = state->current_bb_head;
	if (current_head && state->current_bb->type & R_ANAL_BB_TYPE_TAIL) {
		r_anal_ex_update_bb_cfg_head_tail (current_head, current_head, state->current_bb);
	} 

	// basic filter for handling the different type of operations
	// depending on flags some may be called more than once
	// if (bb->type2 & R_ANAL_EX_ILL_OP)   handle_bb_ill_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_COND_OP)  handle_bb_cond_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_UNK_OP)   handle_bb_unknown_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_NULL_OP)  handle_bb_null_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_NOP_OP)   handle_bb_nop_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_REP_OP)   handle_bb_rep_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_STORE_OP) handle_bb_store_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_LOAD_OP)  handle_bb_load_op (anal, state
	// if (bb->type2 & R_ANAL_EX_REG_OP)   handle_bb_reg_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_OBJ_OP)   handle_bb_obj_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_STACK_OP) handle_bb_stack_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_BIN_OP)   handle_bb_bin_op (anal, state);
	if (bb->type2 & R_ANAL_EX_CODE_OP)  handle_bb_cf_recursive_descent (anal, state);
	// if (bb->type2 & R_ANAL_EX_DATA_OP)  handle_bb_data_op (anal, state);
}

static void java_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalBlock *bb = state->current_bb;
	if (state->current_bb_head && state->current_bb->type & R_ANAL_BB_TYPE_TAIL) {
		//r_anal_ex_update_bb_cfg_head_tail (state->current_bb_head, state->current_bb_head, state->current_bb);
	} 

	// basic filter for handling the different type of operations
	// depending on flags some may be called more than once
	// if (bb->type2 & R_ANAL_EX_ILL_OP)   handle_bb_ill_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_COND_OP)  handle_bb_cond_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_UNK_OP)   handle_bb_unknown_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_NULL_OP)  handle_bb_null_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_NOP_OP)   handle_bb_nop_op (anal, state); 
	// if (bb->type2 & R_ANAL_EX_REP_OP)   handle_bb_rep_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_STORE_OP) handle_bb_store_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_LOAD_OP)  handle_bb_load_op (anal, state
	// if (bb->type2 & R_ANAL_EX_REG_OP)   handle_bb_reg_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_OBJ_OP)   handle_bb_obj_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_STACK_OP) handle_bb_stack_op (anal, state);
	// if (bb->type2 & R_ANAL_EX_BIN_OP)   handle_bb_bin_op (anal, state);
	if (bb->type2 & R_ANAL_EX_CODE_OP)  handle_bb_cf_linear_sweep (anal, state);
	// if (bb->type2 & R_ANAL_EX_DATA_OP)  handle_bb_data_op (anal, state);
}

static int handle_bb_cf_recursive_descent (RAnal *anal, RAnalState *state) {

	ut32 ranal_control_type = -1;
	RAnalFunction *fcn = state->current_fcn;
	RAnalBlock *bb = state->current_bb;
	RAnalOp *op = state->current_op;

	ut64 addr = 0;
	int result = 0;
	if (bb == NULL) {
		eprintf("Error: unable to handle basic block @ 0x%08"PFMT64x"\n", addr);
		return R_ANAL_RET_ERROR;
	} else if (state->max_depth <= state->current_depth) {
		return R_ANAL_RET_ERROR;
	}

	state->current_depth++;
	addr = bb->addr;
	IFDBG eprintf("Handling a control flow change @ 0x%04"PFMT64x".\n", addr);
	ut32 control_type = r_anal_ex_map_anal_ex_to_anal_op_type (bb->type2);

	// XXX - transition to type2 control flow condtions
	switch (control_type) {
		case R_ANAL_OP_TYPE_CALL:
			IFDBG eprintf(" - Handling a call @ 0x%04"PFMT64x".\n", addr);
			r_anal_fcn_xref_add (anal, state->current_fcn, bb->addr, bb->jump, 
				control_type == R_ANAL_OP_TYPE_CALL? R_ANAL_REF_TYPE_CALL : R_ANAL_REF_TYPE_CODE);
			result = R_ANAL_RET_ERROR;
			break;
		case R_ANAL_OP_TYPE_JMP:
			{
				RList * jmp_list;
				IFDBG eprintf(" - Handling a jmp @ 0x%04"PFMT64x" to 0x%04"PFMT64x".\n", addr, bb->jump);
				
				// visited some other time				
				if (r_anal_state_search_bb (state, bb->jump) == NULL) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->jump );	
					if (jmp_list)
						bb->jumpbb = (RAnalBlock *) r_list_get_n(jmp_list, 0);
				} else {
					bb->jumpbb = r_anal_state_search_bb (state, bb->jump);
				}

				if (state->done == 1) {
					IFDBG eprintf(" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
				}
				result = R_ANAL_RET_END;

			}
			break;
		case R_ANAL_OP_TYPE_CJMP:
			{
				RList *jmp_list;
				ut8 encountered_stop = 0;
				IFDBG eprintf(" - Handling an cjmp @ 0x%04"PFMT64x" jmp to 0x%04"PFMT64x" and fail to 0x%04"PFMT64x".\n", addr, bb->jump, bb->fail);
				IFDBG eprintf(" - Handling jmp to 0x%04"PFMT64x".\n", bb->jump);
				// visited some other time				
				if (r_anal_state_search_bb (state, bb->jump) == NULL) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->jump );	
					if (jmp_list)
						bb->jumpbb = (RAnalBlock *) r_list_get_n(jmp_list, 0);
				} else {
					bb->jumpbb = r_anal_state_search_bb (state, bb->jump);
				}

				if (state->done == 1) {
					IFDBG eprintf(" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
					state->done = 0;
					encountered_stop = 1;
				}
				
				if (r_anal_state_search_bb (state, bb->fail) == NULL) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->fail );	
					if (jmp_list)
						bb->jumpbb = (RAnalBlock *) r_list_get_n(jmp_list, 0);
				} else {
					bb->jumpbb = r_anal_state_search_bb (state, bb->jump);
				}

				IFDBG eprintf(" - Handling an cjmp @ 0x%04"PFMT64x" jmp to 0x%04"PFMT64x" and fail to 0x%04"PFMT64x".\n", addr, bb->jump, bb->fail);
				IFDBG eprintf(" - Handling fail to 0x%04"PFMT64x".\n", bb->fail);
				// r_anal_state_merge_bb_list (state, fail_list);
				if (state->done == 1) {
					IFDBG eprintf(" Looks like this fail (bb @ 0x%04"PFMT64x") found a return.\n", addr);
				}

				result = R_ANAL_RET_END;
				if (encountered_stop) state->done = 1;
			}
			break;
		
		case R_ANAL_OP_TYPE_SWITCH:
		{	
			IFDBG eprintf(" - Handling an switch @ 0x%04"PFMT64x".\n", addr);
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				RList *jmp_list = NULL;
				ut8 encountered_stop = 0;
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					if (caseop) {
						if (r_anal_state_addr_is_valid(state, caseop->jump) ) {
							jmp_list = r_anal_ex_perform_analysis ( anal, state, caseop->jump );
							if (jmp_list)
								caseop->jumpbb = (RAnalBlock *) r_list_get_n(jmp_list, 0);
							if (state->done == 1) {
								IFDBG eprintf(" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
								state->done = 0;
								encountered_stop = 1;
							}
						}
					}
				}
				if (encountered_stop) state->done = 1;
			}

			result = R_ANAL_RET_END;
		}
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RET:
			IFDBG eprintf(" - Handling an ret @ 0x%04"PFMT64x".\n", addr);
			state->done = 1;
			result = R_ANAL_RET_END;
			break;
		default: break;
	}
	
	state->current_depth--;
	return result;
}

static int java_post_anal_linear_sweep(RAnal *anal, RAnalState *state) {
	RAnalJavaLinearSweep *nodes = state->user_state;
	RAnalCaseOp *caseop;
	RListIter *iter;
	RList *jmp_list = NULL;
	ut64 *naddr;

	state->done = 0;
	if (nodes == NULL || nodes->cfg_node_addrs == NULL) {
		state->done = 1;
		return R_ANAL_RET_ERROR;
	}

	while (r_list_length (nodes->cfg_node_addrs) > 0) {
		naddr = r_list_get_n (nodes->cfg_node_addrs, 0);
		r_list_del_n (nodes->cfg_node_addrs, 0);
		if (naddr && r_anal_state_search_bb(state, *naddr) == NULL) {
			ut64 list_length = 0;
			IFDBG eprintf(" - Visiting 0x%04"PFMT64x" for analysis.\n", *naddr);
			jmp_list = r_anal_ex_perform_analysis ( anal, state, *naddr );
			list_length = r_list_length (jmp_list);
			if ( list_length > 0) {
				IFDBG eprintf(" - Found %d more basic blocks missed on the initial pass.\n", *naddr);
			}			
		}

	}
	return R_ANAL_RET_END;
}


static int handle_bb_cf_linear_sweep (RAnal *anal, RAnalState *state) {
	ut64 * naddr;
	ut32 ranal_control_type = -1;
	RAnalFunction *fcn = state->current_fcn;
	RAnalBlock *bb = state->current_bb;
	RAnalOp *op = state->current_op;
	RAnalJavaLinearSweep *nodes = state->user_state;

	if (nodes == NULL || nodes->cfg_node_addrs == NULL) {
		state->done = 1;
		return R_ANAL_RET_ERROR;		
	}

	ut64 addr = 0;
	int result = 0;
	if (bb == NULL) {
		eprintf("Error: unable to handle basic block @ 0x%08"PFMT64x"\n", addr);
		return R_ANAL_RET_ERROR;
	} else if (state->max_depth <= state->current_depth) {
		return R_ANAL_RET_ERROR;
	}

	state->current_depth++;
	addr = bb->addr;
	IFDBG eprintf("Handling a control flow change @ 0x%04"PFMT64x".\n", addr);
	ut32 control_type = r_anal_ex_map_anal_ex_to_anal_op_type (bb->type2);

	// XXX - transition to type2 control flow condtions
	switch (control_type) {
		case R_ANAL_OP_TYPE_CALL:
			IFDBG eprintf(" - Handling a call @ 0x%04"PFMT64x"\n", addr);
			r_anal_fcn_xref_add (anal, state->current_fcn, bb->addr, bb->jump, 
				control_type == R_ANAL_OP_TYPE_CALL? R_ANAL_REF_TYPE_CALL : R_ANAL_REF_TYPE_CODE);
			result = R_ANAL_RET_ERROR;
			break;
		case R_ANAL_OP_TYPE_JMP:
			naddr = malloc(sizeof(ut64));
			*naddr = bb->jump;
			IFDBG eprintf(" - Handling a jmp @ 0x%04"PFMT64x", adding for future visit\n", addr);
			r_list_append(nodes->cfg_node_addrs, naddr);
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			naddr = malloc(sizeof(ut64));
			*naddr = bb->jump;
			IFDBG eprintf(" - Handling a bb->jump @ 0x%04"PFMT64x", adding 0x%04"PFMT64x" for future visit\n", addr, *naddr);
			r_list_append(nodes->cfg_node_addrs, naddr);
			naddr = malloc(sizeof(ut64));
			*naddr = bb->fail;
			IFDBG eprintf(" - Handling a bb->fail @ 0x%04"PFMT64x", adding 0x%04"PFMT64x" for future visit\n", addr, *naddr);
			r_list_append(nodes->cfg_node_addrs, naddr);
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_SWITCH:
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				RList *jmp_list = NULL;
				IFDBG eprintf(" - Handling a switch_op @ 0x%04"PFMT64x":\n", addr);
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					ut64 * naddr;
					if (caseop) {
						naddr = malloc(sizeof(ut64));
						*naddr = caseop->jump;
						IFDBG ("Adding 0x%04"PFMT64x" for future visit\n", *naddr);
						r_list_append(nodes->cfg_node_addrs, caseop->jump);
					}
				}
			}
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RET:
			IFDBG eprintf(" - Handling an ret @ 0x%04"PFMT64x".\n", addr);
			state->done = 1;
			result = R_ANAL_RET_END;
			break;
		default: break;
	}
	
	state->current_depth--;
	return result;
}


static int analyze_from_code_buffer ( RAnal *anal, RAnalFunction *fcn, ut64 addr, const ut8 *code_buf, ut64 code_length  ) {
	
	char gen_name[1025];

	RAnalState *state = NULL;
	int result = R_ANAL_RET_ERROR;
	RAnalJavaLinearSweep *nodes;

	free(fcn->name);
	free(fcn->dsc);
	snprintf(gen_name, 1024, "java.fcn.%08"PFMT64x"", addr);
	
	fcn->name = strdup (gen_name);
	fcn->dsc = strdup ("java.dsc.unknown");
	
	fcn->size = code_length;
	fcn->type = R_ANAL_FCN_TYPE_FCN;
	fcn->addr = addr;

	state = r_anal_state_new(addr, code_buf, code_length);
	nodes = R_NEW0(RAnalJavaLinearSweep);
	nodes->cfg_node_addrs = r_list_new();
	nodes->cfg_node_addrs->free = free;

	state->user_state = nodes;

	result = analyze_method(anal, fcn, state);
	fcn->size = state->bytes_consumed;
	result = state->anal_ret_val;
	
	r_list_free(nodes->cfg_node_addrs);
	free(nodes);
	r_anal_state_free(state);
	
	return result;
}

static int analyze_from_code_attr (RAnal *anal, RAnalFunction *fcn, const RBinJavaField *method) {
	RBinJavaAttrInfo* code_attr = method ? r_bin_java_get_method_code_attribute(method) : NULL;
	ut8 * code_buf = NULL;
	int result = R_FALSE;

	ut64 code_length = 0, 
		 addr = -1;


	if (code_attr == NULL) {
		char gen_name[1025];	
		snprintf(gen_name, 1024, "java.fcn.%08"PFMT64x"", addr);
		
		fcn->name = strdup (gen_name);
		fcn->dsc = strdup ("java.dsc.failed");
		
		fcn->size = code_length;
		fcn->type = R_ANAL_FCN_TYPE_FCN;
		fcn->addr = addr;

		return R_ANAL_RET_ERROR;
	}
	
	code_length = code_attr->info.code_attr.code_length;
	addr = code_attr->info.code_attr.code_offset;

	code_buf = malloc(code_length);
	
	anal->iob.read_at (anal->iob.io, addr, code_buf, code_length);
	result = analyze_from_code_buffer ( anal, fcn, addr, code_buf, code_length);
	
	free(code_buf);
	free(fcn->name);
	free(fcn->dsc);

	fcn->name = strdup (method->name);
	fcn->dsc = strdup (method->descriptor);
	
	return result;
}

static int analyze_method(RAnal *anal, RAnalFunction *fcn, RAnalState *state) {
	ut64 bytes_consumed = 0;
	RList *bbs = NULL;
	int result = R_ANAL_RET_ERROR;
	// deallocate niceties
	r_list_free(fcn->bbs);
	fcn->bbs = r_anal_bb_list_new();

	IFDBG eprintf("analyze_method: Parsing fcn %s @ 0x%08"PFMT64x", %d bytes\n", fcn->name, fcn->addr, fcn->size);
	
	state->current_fcn = fcn;
	// Not a resource leak.  Basic blocks should be stored in the state->fcn
	bbs = r_anal_ex_perform_analysis (anal, state, fcn->addr);
    bytes_consumed = state->bytes_consumed;
	IFDBG eprintf("analyze_method: Completed Parsing fcn %s @ 0x%08"PFMT64x", consumed %"PFMT64d" bytes\n", fcn->name, fcn->addr, bytes_consumed);
	
	return state->anal_ret_val;
}

static int java_analyze_fns_from_buffer( RAnal *anal, ut64 start, ut64 end, int reftype, int depth) { 

	int result = R_ANAL_RET_ERROR;
	ut64 addr = start;
	ut64 offset = 0;
	ut64 buf_len = end - start;
	ut8 analyze_all = 0,
	    *buffer = NULL;

	if (end == UT64_MAX) {
		//analyze_all = 1;
		buf_len = anal->iob.size (anal->iob.io);
		
		if (buf_len == UT64_MAX) buf_len = 1024;
		
		end = start + buf_len;
	}

	
	buffer = malloc(buf_len);
	if (buffer == NULL) return R_ANAL_RET_ERROR;
	
	
	anal->iob.read_at (anal->iob.io, addr, buffer, buf_len);

	while (offset < buf_len) {
		ut64 length = buf_len - offset;

		RAnalFunction *fcn = r_anal_fcn_new ();
		result = analyze_from_code_buffer ( anal, fcn, addr, buffer+offset, length );
		if (result == R_ANAL_RET_ERROR) {
			eprintf ("Failed to parse java fn: %s @ 0x%04"PFMT64x"\n", fcn->name, fcn->addr);
			// XXX - TO Stop or not to Stop ??
			break;
		}
		//r_listrange_add (anal->fcnstore, fcn);
		r_list_append (anal->fcns, fcn);
		offset += fcn->size;
		if (!analyze_all) break;
	}
	free (buffer);
	return result;
}


static int java_analyze_fns( RAnal *anal, ut64 start, ut64 end, int reftype, int depth) {
	//anal->iob.read_at (anal->iob.io, op.jump, bbuf, sizeof (bbuf));
	const RList *methods_list = r_bin_java_get_methods_list (NULL);
	RListIter *iter;
	RBinJavaField *method = NULL;
	ut8 analyze_all = 0;
	RAnalRef *ref = NULL;
	int result = R_ANAL_RET_ERROR;

	if (end == UT64_MAX) analyze_all = 1;
	
	if (methods_list == NULL) return java_analyze_fns_from_buffer(anal, start, end, reftype, depth);
	
	r_list_foreach ( methods_list, iter, method ) {
		if ( (method && analyze_all) || 
			(check_addr_less_start (method, end) || 
			check_addr_in_code (method, end)) ) {

			RAnalFunction *fcn = r_anal_fcn_new ();
			result = analyze_from_code_attr ( anal, fcn, method );
			if (result == R_ANAL_RET_ERROR) {
				eprintf ("Failed to parse java fn: %s @ 0x%04"PFMT64x"\n", fcn->name, fcn->addr);
				// XXX - TO Stop or not to Stop ??
			}
			//r_listrange_add (anal->fcnstore, fcn);
			r_list_append (anal->fcns, fcn);
		}
		
	}
	return result;
}

static int java_fn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	RBinJavaField *method = r_bin_java_get_method_code_attribute_with_addr(NULL,  addr);
	if (method) return analyze_from_code_attr (anal, fcn, method);
	return analyze_from_code_buffer (anal, fcn, addr, buf, len);
}

static int java_switch_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_byte = data[0];
	ut8 padding = (4 - (addr+1) % 4);
	ut32 pos = padding + (addr+1)  % 4;

	if (op_byte == 0xaa) {
		// handle a table switch condition
		int min_val = (ut32)(UINT (data, pos + 4)),
			max_val = (ut32)(UINT (data, pos + 8));

		ut32 default_loc = (ut32)(UINT (data, pos)),
			 cur_case = 0;
		
		op->switch_op = r_anal_switch_op_new (addr, min_val, default_loc);
		
		RAnalCaseOp *caseop = NULL;
		IFDBG {
			eprintf("Handling tableswitch op @ 0x%04"PFMT64x"\n", addr);
			eprintf("default_jump @ 0x%04x ", default_loc);
			eprintf("min_val: %d max_val: %d\n", min_val, max_val);
		}
		pos += 12;
		
		//caseop = r_anal_switch_op_add_case(op->switch_op, addr+default_loc, -1, addr+offset);
		for (cur_case = 0; cur_case <= max_val - min_val; pos+=4, cur_case++) {
			//ut32 value = (ut32)(UINT (data, pos));
			ut32 offset = (ut32)(R_BIN_JAVA_UINT (data, pos));
			IFDBG eprintf ("offset value: 0x%04x, interpretted addr case: %d offset: 0x%04x\n", offset, cur_case+min_val, addr+offset);
			caseop = r_anal_switch_op_add_case(op->switch_op, addr+pos, cur_case+min_val, addr+offset);
			caseop->bb_ref_to = addr+offset;
			caseop->bb_ref_from = addr; // TODO figure this one out
		}
	}
	op->size = pos;
	return op->size;
}
static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	unsigned int i;
	int sz = 1;
	
	/* get opcode size */
	//ut8 op_byte = data[0];
	ut8 op_byte = data[0];
	sz = java_ops[op_byte].size;
	if (op == NULL)	return sz;

	memset (op, '\0', sizeof (RAnalOp));
	
	IFDBG {
		//eprintf ("Extracting op from buffer (%d bytes) @ 0x%04x\n", len, addr);
		//eprintf ("Parsing op: (0x%02x) %s.\n", op_byte, java_ops[op_byte].name);
	}
	op->addr = addr;
	op->size= sz;
	op->type2 = java_ops[op_byte].op_type;
	op->type = r_anal_ex_map_anal_ex_to_anal_op_type (op->type2); 
	
	op->eob = r_anal_ex_is_op_type_eop(op->type2);
	IFDBG {
		char *ot_str = r_anal_optype_to_string(op->type);
		eprintf ("op_type2: %s @ 0x%04"PFMT64x" 0x%08"PFMT64x" op_type: (0x%02"PFMT64x") %s.\n", java_ops[op_byte].name, addr, op->type2, op->type,  ot_str);
		//eprintf ("op_eob: 0x%02x.\n", op->eob);	
		//eprintf ("op_byte @ 0: 0x%02x op_byte @ 0x%04x: 0x%02x.\n", data[0], addr, data[addr]);
	}

	if ( op->type == R_ANAL_OP_TYPE_CJMP ) {
		op->jump = addr + (int)(short)(USHORT (data, 1));
		op->fail = addr + sz;
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x"  failto 0x%04"PFMT64x".\n", java_ops[op_byte].name, op->jump, op->fail);
	} else if ( op->type  == R_ANAL_OP_TYPE_JMP ) {
		op->jump = addr + (int)(short)(USHORT (data, 1));
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x".\n", java_ops[op_byte].name, op->jump);
	} else if ( (op->type & R_ANAL_OP_TYPE_CALL) == R_ANAL_OP_TYPE_CALL ) {
		//op->jump = addr + (int)(short)(USHORT (data, 1));
		//op->fail = addr + sz;
		//IFDBG eprintf ("%s callto 0x%04x  failto 0x%04x.\n", java_ops[op_byte].name, op->jump, op->fail);
	}

	// handle lookup and table switch offsets
	if (op_byte == 0xaa || op_byte == 0xab) { 
		java_switch_op(anal, op, addr, data, len);
	}
	//r_java_disasm(addr, data, output, outlen);
	//IFDBG eprintf("%s\n", output);
	return op->size;
}

static RAnalOp * java_op_from_buffer(RAnal *anal, RAnalState *state, ut64 addr) {
	
	RAnalOp *op = r_anal_op_new();
	/* get opcode size */
	if (op == NULL) return 0;
	memset (op, '\0', sizeof (RAnalOp));
	java_op(anal, op, addr, state->buffer, state->len - (addr - state->start) );
	return op;

}

struct r_anal_plugin_t r_anal_plugin_java = {
	.name = "java",
	.desc = "Java bytecode analysis plugin",
	.license = "Apache",
	.arch = R_SYS_ARCH_JAVA,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.custom_fn_anal = 1,

	.analyze_fns = java_analyze_fns,
	.post_anal_bb_cb = java_recursive_descent,
	.revisit_bb_anal = java_revisit_bb_anal_recursive_descent,
	.op = &java_op,
	.bb = NULL,
	.fcn = NULL,
	
	.op_from_buffer = NULL,
	.bb_from_buffer = NULL,
	.fn_from_buffer = NULL,
	

	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,

};

struct r_anal_plugin_t r_anal_plugin_java_ls = {
	.name = "java_ls",
	.desc = "Java bytecode analysis plugin with linear sweep",
	.license = "Apache",
	.arch = R_SYS_ARCH_JAVA,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.custom_fn_anal = 1,

	.analyze_fns = java_analyze_fns,
	.post_anal_bb_cb = java_linear_sweep,
	.post_anal = java_post_anal_linear_sweep, 
	.revisit_bb_anal = java_revisit_bb_anal_recursive_descent,
	.op = &java_op,
	.bb = NULL,
	.fcn = NULL,
	
	.op_from_buffer = NULL,
	.bb_from_buffer = NULL,
	.fn_from_buffer = NULL,
	

	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,

};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	//.data = &r_anal_plugin_java
	.data = &r_anal_plugin_java_ls
};
#endif
/*
static void r_anal_ex_handle_bb_cases(RAnal *anal, RAnalState *state, RAnalBlock *bb, RAnalOp *op);
static void r_anal_ex_handle_control_flow(RAnal *anal, RAnalState *state, RAnalBlock* current_bb);
static void r_anal_ex_handle_binary_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb);
static void r_anal_ex_handle_case_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb);
static void r_anal_ex_handle_call(RAnal *anal, RAnalState *state, RAnalBlock* current_bb);
static void r_anal_ex_handle_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb, ut64 jump_to);



R_API void r_anal_ex_handle_binary_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb) {
	r_anal_ex_handle_jump( anal, state, current_bb, current_bb->jump );
	r_anal_ex_handle_jump( anal, state, current_bb, current_bb->fail );
}

R_API void r_anal_ex_handle_case_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb ) {
	// TODO parse switch caseops
	// for each caseop in the bb->switch_op {
	//	  ut64 jmp_addr = caseop->jump
	//	  r_anal_ex_handle_jump( anal, state, current_bb, jumpaddr );
	//	  if ( jmp_list ){
	//		  i = 0
	//		  // merge results
	//		  // TODO jmp_list[i]->prev = current_bb
	//		  // TODO jmp_list[i]->next = jmp_list[i+1]
	//	  }
	// }
}

R_API void r_anal_ex_handle_jump(RAnal *anal, RAnalState *state, RAnalBlock* current_bb, ut64 jump_to) {
	RList * jmp_list = recursive_descent_jmp( anal, state, current_bb, jump_to );
	if ( jmp_list ){
		r_anal_state_merge_bb_list (state, jmp_list);
	}
}

R_API void r_anal_ex_handle_call(RAnal *anal, RAnalState *state, RAnalBlock* current_bb) {
	RList * caller_list = recursive_descent_jmp( anal, state, current_bb, 0/*jump_to* / );
	if ( caller_list ){
		// TODO merge results
		// TODO set current_bb->jumpbb = jmp_list[0]
		// TODO jmp_list[0]->prev = current_bb
	}
}

R_API void r_anal_ex_handle_control_flow(RAnal *anal, RAnalState *state, RAnalBlock* current_bb ) {
		
	if ( current_bb->type | R_ANAL_BB_TYPE_JMP )		 
		r_anal_ex_handle_binary_jump(anal, state, current_bb);
	else if ( current_bb->type | R_ANAL_BB_TYPE_SWITCH )
		r_anal_ex_handle_case_jump(anal, state, current_bb);
	else if ( current_bb->type | R_ANAL_BB_TYPE_CALL )
		r_anal_ex_handle_call(anal, state, current_bb);
}

R_API RList * recursive_descent_jmp( RAnal *anal, RAnalState *state, RAnalBlock *current_bb, ut64 jmp_addr ) {
	ut64 jmp_len = 0;
	RList *jmp_list = NULL;
	// jmp and recurse through the bb
	// step 1, check jump to see if it is valid
	if (jmp_addr > state->end && jmp_addr < state->start) {
		current_bb->type |= R_ANAL_BB_TYPE_FOOT;
		// Done Processing?
	} else {
		jmp_list = recursive_descent ( anal, state, jmp_addr );				 
	}
	return jmp_list;
}

/*
static void r_anal_ex_handle_bb_cases(RAnal *anal, RAnalState *state, RAnalBlock *bb, RAnalOp *op){
	if (bb->type2 & R_ANAL_EX_ILL_OP) {
		if (anal->cur && anal->cur->bb_ill_op) {
			 anal->cur->bb_ill_op (anal, state, bb, op); 
			 return;
		}
	}
	if (bb->type2 & R_ANAL_EX_COND_OP) {
		if (anal->cur && anal->cur->bb_cond_op) {
			anal->cur->bb_cond_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_UNK_OP) {
		if (anal->cur && anal->cur->bb_unknown_op) {
			 anal->cur->bb_unknown_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_NULL_OP) {
		if (anal->cur && anal->cur->bb_null_op) {
			anal->cur->bb_null_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_NOP_OP) {
		if (anal->cur && anal->cur->bb_nop_op) {
			anal->cur->bb_nop_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_REP_OP) {
		if (anal->cur && anal->cur->bb_rep_op) {
			anal->cur->bb_rep_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_STORE_OP) {
		if (anal->cur && anal->cur->bb_store_op) {
			anal->cur->bb_store_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_LOAD_OP) {
		if (anal->cur && anal->cur->bb_load_op) {
			anal->cur->bb_load_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_REG_OP) {
		if (anal->cur && anal->cur->bb_reg_op) {
			anal->cur->bb_reg_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_OBJ_OP) {
		if (anal->cur && anal->cur->bb_obj_op) {
			anal->cur->bb_obj_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_STACK_OP) {
		if (anal->cur && anal->cur->bb_stack_op) {
			anal->cur->bb_stack_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_BIN_OP) {
		if (anal->cur && anal->cur->bb_bin_op) {
			anal->cur->bb_bin_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_CODE_OP) {
		if (anal->cur && anal->cur->bb_code_op) {
			anal->cur->bb_code_op (anal, state, bb, op); 
		}
	}
	if (bb->type2 & R_ANAL_EX_DATA_OP) {
		if (anal->cur && anal->cur->bb_data_op) {
			anal->cur->bb_data_op (anal, state, bb, op); 
		}
	}
}

static void r_anal_ex_handle_fn_cases(RAnal *anal, RAnalState *state, RAnalBlock *bb, RAnalOp *op){
    
    if (bb->type2 & R_ANAL_EX_ILL_OP) {
        if (anal->cur && anal->cur->bb_ill_op) {
             anal->cur->bb_ill_op (anal, state, bb, op); 
             return;
        }
    }
    if (bb->type2 & R_ANAL_EX_COND_OP) {
        if (anal->cur && anal->cur->bb_cond_op) {
            anal->cur->bb_cond_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_UNK_OP) {
        if (anal->cur && anal->cur->bb_unknown_op) {
             anal->cur->bb_unknown_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_NULL_OP) {
        if (anal->cur && anal->cur->bb_null_op) {
            anal->cur->bb_null_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_NOP_OP) {
        if (anal->cur && anal->cur->bb_nop_op) {
            anal->cur->bb_nop_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_REP_OP) {
        if (anal->cur && anal->cur->bb_rep_op) {
            anal->cur->bb_rep_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_STORE_OP) {
        if (anal->cur && anal->cur->bb_store_op) {
            anal->cur->bb_store_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_LOAD_OP) {
        if (anal->cur && anal->cur->bb_load_op) {
            anal->cur->bb_load_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_REG_OP) {
        if (anal->cur && anal->cur->bb_reg_op) {
            anal->cur->bb_reg_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_OBJ_OP) {
        if (anal->cur && anal->cur->bb_obj_op) {
            anal->cur->bb_obj_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_STACK_OP) {
        if (anal->cur && anal->cur->bb_stack_op) {
            anal->cur->bb_stack_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_BIN_OP) {
        if (anal->cur && anal->cur->bb_bin_op) {
            anal->cur->bb_bin_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_CODE_OP) {
        if (anal->cur && anal->cur->bb_code_op) {
            anal->cur->bb_code_op (anal, state, bb, op); 
        }
    }
    if (bb->type2 & R_ANAL_EX_DATA_OP) {
        if (anal->cur && anal->cur->bb_data_op) {
            anal->cur->bb_data_op (anal, state, bb, op); 
        }
    }
}
*/
