/* radare - Apache 2.0 - Copyright 2010-2015 - pancake and
 Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_anal_ex.h>
#include <r_cons.h>

#include "../../../shlr/java/code.h"
#include "../../../shlr/java/class.h"

#ifdef IFDBG
#define dprintf eprintf
#endif

#define DO_THE_DBG 0
#define IFDBG  if(DO_THE_DBG)
#define IFINT  if(0)

struct r_anal_java_access_t;

typedef struct r_anal_java_access_t {
	char *method;
	ut64 addr;
	ut64 value;
	ut64 op_type;
	struct r_anal_java_access_t *next;
	struct r_anal_java_access_t *previous;
} RAnalJavaAccess;

typedef struct r_anal_java_local_var_t {
	char *name;
	char *type;
	RList *writes;
	RList *reads;
	RList *binops;
} RAnalJavaLocalVar;

typedef struct r_anal_ex_java_lin_sweep {
	RList *cfg_node_addrs;
}RAnalJavaLinearSweep;

ut64 METHOD_START = 0;

// XXX - TODO add code in the java_op that is aware of when it is in a
// switch statement, like in the shlr/java/code.c so that this does not 
// report bad blocks.  currently is should be easy to ignore these blocks,
// in output for the pdj

//static int java_print_ssa_bb (RAnal *anal, char *addr);
static int java_reset_counter (RAnal *anal, ut64 addr);
static int java_new_method (ut64 addr);
static void java_update_anal_types (RAnal *anal, RBinJavaObj *bin_obj);
static void java_set_function_prototype (RAnal *anal, RAnalFunction *fcn, RBinJavaField *method);

static int java_cmd_ext(RAnal *anal, const char* input);
static int analyze_from_code_buffer (RAnal *anal, RAnalFunction *fcn, ut64 addr, const ut8 *code_buf, ut64 code_length);
static int analyze_from_code_attr (RAnal *anal, RAnalFunction *fcn, RBinJavaField *method, ut64 loadaddr);
static int analyze_method(RAnal *anal, RAnalFunction *fcn, RAnalState *state);

static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len);
//static int java_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype);
//static int java_fn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype);

static int java_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr);
static int handle_bb_cf_recursive_descent (RAnal *anal, RAnalState *state);

static int java_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr);
static int handle_bb_cf_linear_sweep (RAnal *anal, RAnalState *state);
static int java_post_anal_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr);
static RBinJavaObj * get_java_bin_obj(RAnal *anal);
static RList * get_java_bin_obj_list(RAnal *anal);

static int java_analyze_fns( RAnal *anal, ut64 start, ut64 end, int reftype, int depth);

//static RAnalOp * java_op_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);
//static RAnalBlock * java_bb_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);
//static RAnalFunction * java_fn_from_buffer(RAnal *anal, RAnalState *state, ut64 addr);

static int check_addr_in_code (RBinJavaField *method, ut64 addr);
static int check_addr_less_end (RBinJavaField *method, ut64 addr);
static int check_addr_less_start (RBinJavaField *method, ut64 addr);

static int java_revisit_bb_anal_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr);

static RBinJavaObj * get_java_bin_obj(RAnal *anal) {
	RBin *b = anal->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->o ? b->cur->o->plugin : NULL;
	ut8 is_java = (plugin && strcmp (plugin->name, "java") == 0) ? 1 : 0;
	return is_java ? b->cur->o->bin_obj : NULL;
}

static RList * get_java_bin_obj_list(RAnal *anal) {
	RBinJavaObj *bin_obj = (RBinJavaObj * )get_java_bin_obj(anal);
	// See libr/bin/p/bin_java.c to see what is happening here.  The original intention
	// was to use a shared global db variable from shlr/java/class.c, but the
	// BIN_OBJS_ADDRS variable kept getting corrupted on Mac, so I (deeso) switched the
	// way the access to the db was taking place by using the bin_obj as a proxy back
	// to the BIN_OBJS_ADDRS which is instantiated in libr/bin/p/bin_java.c
	// not the easiest way to make sausage, but its getting made.
	return  r_bin_java_get_bin_obj_list_thru_obj (bin_obj);
}

static int check_addr_less_end (RBinJavaField *method, ut64 addr) {
	ut64 end = r_bin_java_get_method_code_size (method);
	return (addr < end);
}

static int check_addr_in_code (RBinJavaField *method, ut64 addr) {
	return !check_addr_less_start (method, addr) && \
		check_addr_less_end ( method, addr);
}

static int check_addr_less_start (RBinJavaField *method, ut64 addr) {
	ut64 start = r_bin_java_get_method_code_offset (method);
	return (addr < start);
}


static int java_new_method (ut64 method_start) {
	METHOD_START = method_start;
	// reset the current bytes consumed counter
	r_java_new_method ();
	return 0;
}

static ut64 java_get_method_start () {
	return METHOD_START;
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

static int java_recursive_descent(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalBlock *bb;
	RAnalBlock *current_head;

	if (!anal || !state || !state->current_bb || state->current_bb_head)
		return 0;

	bb = state->current_bb;
	current_head = state->current_bb_head;

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
	return 0;
}

static int java_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr) {
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
	return 0;
}

static int handle_bb_cf_recursive_descent (RAnal *anal, RAnalState *state) {

	RAnalBlock *bb = state->current_bb;

	ut64 addr = 0;
	int result = 0;
	if (!bb) {
		eprintf ("Error: unable to handle basic block @ 0x%08"PFMT64x"\n", addr);
		return R_ANAL_RET_ERROR;
	} else if (state->max_depth <= state->current_depth) {
		return R_ANAL_RET_ERROR;
	}

	state->current_depth++;
	addr = bb->addr;
	IFDBG eprintf ("Handling a control flow change @ 0x%04"PFMT64x".\n", addr);
	ut64 control_type = r_anal_ex_map_anal_ex_to_anal_op_type (bb->type2);

	// XXX - transition to type2 control flow condtions
	switch (control_type) {
		case R_ANAL_OP_TYPE_CALL:
			IFDBG eprintf (" - Handling a call @ 0x%04"PFMT64x".\n", addr);
			r_anal_fcn_xref_add (anal, state->current_fcn, bb->addr, bb->jump, R_ANAL_REF_TYPE_CALL);
			result = R_ANAL_RET_ERROR;
			break;
		case R_ANAL_OP_TYPE_JMP:
			{
				RList * jmp_list;
				IFDBG eprintf (" - Handling a jmp @ 0x%04"PFMT64x" to 0x%04"PFMT64x".\n", addr, bb->jump);

				// visited some other time
				if (!r_anal_state_search_bb (state, bb->jump)) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->jump );
					if (jmp_list)
						bb->jumpbb = (RAnalBlock *) r_list_get_n (jmp_list, 0);
					if (bb->jumpbb)
						bb->jump = bb->jumpbb->addr;
				} else {
					bb->jumpbb = r_anal_state_search_bb (state, bb->jump);
					if (bb->jumpbb)
						bb->jump = bb->jumpbb->addr;
				}

				if (state->done == 1) {
					IFDBG eprintf (" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
				}
				result = R_ANAL_RET_END;
			}
			break;
		case R_ANAL_OP_TYPE_CJMP:
			{
				RList *jmp_list;
				ut8 encountered_stop = 0;
				IFDBG eprintf (" - Handling a cjmp @ 0x%04"PFMT64x" jmp to 0x%04"PFMT64x" and fail to 0x%04"PFMT64x".\n", addr, bb->jump, bb->fail);
				IFDBG eprintf (" - Handling jmp to 0x%04"PFMT64x".\n", bb->jump);
				// visited some other time
				if (!r_anal_state_search_bb (state, bb->jump)) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->jump );
					if (jmp_list)
						bb->jumpbb = (RAnalBlock *) r_list_get_n (jmp_list, 0);
					if (bb->jumpbb) {
						bb->jump = bb->jumpbb->addr;
					}
				} else {
					bb->jumpbb = r_anal_state_search_bb (state, bb->jump);
					bb->jump = bb->jumpbb->addr;
				}

				if (state->done == 1) {
					IFDBG eprintf (" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
					state->done = 0;
					encountered_stop = 1;
				}

				if (!r_anal_state_search_bb (state, bb->fail)) {
					jmp_list = r_anal_ex_perform_analysis ( anal, state, bb->fail );
					if (jmp_list)
						bb->failbb = (RAnalBlock *) r_list_get_n (jmp_list, 0);
					if (bb->failbb) {
						bb->fail = bb->failbb->addr;
					}
				} else {
					bb->failbb = r_anal_state_search_bb (state, bb->fail);
					if (bb->failbb) {
						bb->fail = bb->failbb->addr;
					}
				}

				IFDBG eprintf (" - Handling an cjmp @ 0x%04"PFMT64x" jmp to 0x%04"PFMT64x" and fail to 0x%04"PFMT64x".\n", addr, bb->jump, bb->fail);
				IFDBG eprintf (" - Handling fail to 0x%04"PFMT64x".\n", bb->fail);
				// r_anal_state_merge_bb_list (state, fail_list);
				if (state->done == 1) {
					IFDBG eprintf (" Looks like this fail (bb @ 0x%04"PFMT64x") found a return.\n", addr);
				}

				result = R_ANAL_RET_END;
				if (encountered_stop) state->done = 1;
			}
			break;

		case R_ANAL_OP_TYPE_SWITCH:
		{
			IFDBG eprintf (" - Handling an switch @ 0x%04"PFMT64x".\n", addr);
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				RList *jmp_list = NULL;
				ut8 encountered_stop = 0;
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					if (caseop) {
						if (r_anal_state_addr_is_valid (state, caseop->jump) ) {
							jmp_list = r_anal_ex_perform_analysis ( anal, state, caseop->jump );
							if (jmp_list)
								caseop->jumpbb = (RAnalBlock *) r_list_get_n (jmp_list, 0);
							if (state->done == 1) {
								IFDBG eprintf (" Looks like this jmp (bb @ 0x%04"PFMT64x") found a return.\n", addr);
								state->done = 0;
								encountered_stop = 1;
							}
						}
					}
				}
				r_list_free (jmp_list);
				if (encountered_stop) state->done = 1;
			}

			result = R_ANAL_RET_END;
		}
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_RET:
		case R_ANAL_OP_TYPE_ILL:
			IFDBG eprintf (" - Handling an ret @ 0x%04"PFMT64x".\n", addr);
			state->done = 1;
			result = R_ANAL_RET_END;
			break;
		default: break;
	}

	state->current_depth--;
	return result;
}

static int java_post_anal_linear_sweep(RAnal *anal, RAnalState *state, ut64 addr) {
	RAnalJavaLinearSweep *nodes = state->user_state;
	RList *jmp_list = NULL;
	ut64 *paddr64;

	state->done = 0;
	if (!nodes || !nodes->cfg_node_addrs) {
		state->done = 1;
		return R_ANAL_RET_ERROR;
	}

	while (r_list_length (nodes->cfg_node_addrs) > 0) {
		paddr64 = r_list_get_n (nodes->cfg_node_addrs, 0);
		r_list_del_n (nodes->cfg_node_addrs, 0);
		if (paddr64 && !r_anal_state_search_bb (state, *paddr64)) {
			ut64 list_length = 0;
			IFDBG eprintf (" - Visiting 0x%04"PFMT64x" for analysis.\n", *paddr64);
			jmp_list = r_anal_ex_perform_analysis ( anal, state, *paddr64 );
			list_length = r_list_length (jmp_list);
			r_list_free (jmp_list);
			if ( list_length > 0) {
				IFDBG eprintf (" - Found %"PFMT64d" more basic blocks missed on the initial pass.\n", *paddr64);
			}
		}

	}
	return R_ANAL_RET_END;
}


static int handle_bb_cf_linear_sweep (RAnal *anal, RAnalState *state) {
	ut64 * paddr64;
	RAnalBlock *bb = state->current_bb;
	RAnalJavaLinearSweep *nodes = state->user_state;

	if (!nodes || !nodes->cfg_node_addrs) {
		state->done = 1;
		return R_ANAL_RET_ERROR;
	}

	ut64 addr = 0;
	int result = 0;
	if (!bb) {
		eprintf ("Error: unable to handle basic block @ 0x%08"PFMT64x"\n", addr);
		return R_ANAL_RET_ERROR;
	} else if (state->max_depth <= state->current_depth) {
		return R_ANAL_RET_ERROR;
	}

	state->current_depth++;
	addr = bb->addr;
	IFDBG eprintf ("Handling a control flow change @ 0x%04"PFMT64x".\n", addr);
	ut32 control_type = r_anal_ex_map_anal_ex_to_anal_op_type (bb->type2);

	// XXX - transition to type2 control flow condtions
	switch (control_type) {
		case R_ANAL_OP_TYPE_CALL:
			IFDBG eprintf (" - Handling a call @ 0x%04"PFMT64x"\n", addr);
			r_anal_fcn_xref_add (anal, state->current_fcn, bb->addr, bb->jump, R_ANAL_REF_TYPE_CALL);
			result = R_ANAL_RET_ERROR;
			break;
		case R_ANAL_OP_TYPE_JMP:
			paddr64 = malloc (sizeof(ut64));
			*paddr64 = bb->jump;
			IFDBG eprintf (" - Handling a jmp @ 0x%04"PFMT64x", adding for future visit\n", addr);
			r_list_append (nodes->cfg_node_addrs, paddr64);
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			paddr64 = malloc (sizeof(ut64));
			*paddr64 = bb->jump;
			IFDBG eprintf (" - Handling a bb->jump @ 0x%04"PFMT64x", adding 0x%04"PFMT64x" for future visit\n", addr, *paddr64);
			r_list_append (nodes->cfg_node_addrs, paddr64);
			paddr64 = malloc (sizeof(ut64));
			*paddr64 = bb->fail;
			IFDBG eprintf (" - Handling a bb->fail @ 0x%04"PFMT64x", adding 0x%04"PFMT64x" for future visit\n", addr, *paddr64);
			r_list_append (nodes->cfg_node_addrs, paddr64);
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_SWITCH:
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				//RList *jmp_list = NULL;
				IFDBG eprintf (" - Handling a switch_op @ 0x%04"PFMT64x":\n", addr);
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					ut64 * paddr64;
					if (caseop) {
						paddr64 = malloc (sizeof(ut64));
						*paddr64 = caseop->jump;
						IFDBG eprintf ("Adding 0x%04"PFMT64x" for future visit\n", *paddr64);
						r_list_append (nodes->cfg_node_addrs, paddr64);
					}
				}
			}
			result = R_ANAL_RET_END;
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_RET:
			IFDBG eprintf (" - Handling an ret @ 0x%04"PFMT64x".\n", addr);
			state->done = 1;
			result = R_ANAL_RET_END;
			break;
		default: break;
	}

	state->current_depth--;
	return result;
}


//many flaws UAF
static int analyze_from_code_buffer(RAnal *anal, RAnalFunction *fcn, ut64 addr, const ut8 *code_buf, ut64 code_length) {
	char gen_name[1025];
	RListIter *bb_iter;
	RAnalBlock *bb;
	ut64 actual_size = 0;
	RAnalState *state = NULL;
	int result = R_ANAL_RET_ERROR;
	RAnalJavaLinearSweep *nodes;

	free (fcn->name);
	free (fcn->dsc);
	snprintf (gen_name, 1024, "sym.%08"PFMT64x"", addr);

	fcn->name = strdup (gen_name);
	fcn->dsc = strdup ("unknown");
	r_anal_fcn_set_size (fcn, code_length);
	fcn->type = R_ANAL_FCN_TYPE_FCN;
	fcn->addr = addr;
	state = r_anal_state_new (addr, (ut8*) code_buf, code_length);
	nodes = R_NEW0 (RAnalJavaLinearSweep);
	nodes->cfg_node_addrs = r_list_new ();
	nodes->cfg_node_addrs->free = free;
	state->user_state = nodes;
	result = analyze_method (anal, fcn, state);
	r_list_foreach (fcn->bbs, bb_iter, bb) {
		actual_size += bb->size;
	}
	r_anal_fcn_set_size (fcn, state->bytes_consumed);
	result = state->anal_ret_val;
	r_list_free (nodes->cfg_node_addrs);
	free (nodes);
	//leak to avoid UAF is the easy solution otherwise a whole rewrite is needed
	//r_anal_state_free (state);
	if (r_anal_fcn_size (fcn) != code_length) {
		eprintf ("WARNING Analysis of %s Incorrect: Code Length: 0x%"PFMT64x", Function size reported 0x%x\n", fcn->name, code_length, r_anal_fcn_size(fcn));
		eprintf ("Deadcode detected, setting code length to: 0x%"PFMT64x"\n", code_length);
		r_anal_fcn_set_size (fcn, code_length);
	}
	return result;
}

static int analyze_from_code_attr (RAnal *anal, RAnalFunction *fcn, RBinJavaField *method, ut64 loadaddr) {
	RBinJavaAttrInfo* code_attr = method ? r_bin_java_get_method_code_attribute(method) : NULL;
	ut8 * code_buf = NULL;
	int result = false;
	ut64 code_length = 0;
	ut64 code_addr = -1;

	if (!code_attr) {
		fcn->name = strdup ("sym.UNKNOWN");
		fcn->dsc = strdup ("unknown");
		r_anal_fcn_set_size (fcn, code_length);
		fcn->type = R_ANAL_FCN_TYPE_FCN;
		fcn->addr = 0;
		return R_ANAL_RET_ERROR;
	}

	code_length = code_attr->info.code_attr.code_length;
	code_addr = code_attr->info.code_attr.code_offset;
	code_buf = malloc (code_length);

	anal->iob.read_at (anal->iob.io, code_addr + loadaddr, code_buf, code_length);
	result = analyze_from_code_buffer (anal, fcn, code_addr + loadaddr, code_buf, code_length);
	free (code_buf);

	{
		char *cname = NULL;
		char *name = strdup (method->name);
		r_name_filter (name, 80);
		free (fcn->name);
		if (method->class_name) {
			cname = strdup (method->class_name);
			r_name_filter (cname, 50);
			fcn->name = r_str_newf ("sym.%s.%s", cname, name);
		} else {
			fcn->name = r_str_newf ("sym.%s", name);
		}
		free (cname);
		free (name);
	}

	free (fcn->dsc);
	fcn->dsc = strdup (method->descriptor);
	IFDBG eprintf ("Completed analysing code from attr, name: %s, desc: %s", fcn->name, fcn->dsc);

	return result;
}

static int analyze_method(RAnal *anal, RAnalFunction *fcn, RAnalState *state) {
	// deallocate niceties
	r_list_free (fcn->bbs);
	fcn->bbs = r_anal_bb_list_new ();
	java_new_method (fcn->addr);
	state->current_fcn = fcn;
	// Not a resource leak.  Basic blocks should be stored in the state->fcn
	// TODO: ? RList *bbs = 
	r_anal_ex_perform_analysis (anal, state, fcn->addr);
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
		buf_len = anal->iob.desc_size (anal->iob.io->desc);

		if (buf_len == UT64_MAX) buf_len = 1024;

		end = start + buf_len;
	}


	buffer = malloc (buf_len);
	if (!buffer) return R_ANAL_RET_ERROR;


	anal->iob.read_at (anal->iob.io, addr, buffer, buf_len);

	while (offset < buf_len) {
		ut64 length = buf_len - offset;

		RAnalFunction *fcn = r_anal_fcn_new ();
		fcn->cc = r_anal_cc_default (anal);
		result = analyze_from_code_buffer ( anal, fcn, addr, buffer+offset, length );
		if (result == R_ANAL_RET_ERROR) {
			eprintf ("Failed to parse java fn: %s @ 0x%04"PFMT64x"\n", fcn->name, fcn->addr);
			// XXX - TO Stop or not to Stop ??
			break;
		}
		//r_listrange_add (anal->fcnstore, fcn);
		r_list_append (anal->fcns, fcn);
		offset += r_anal_fcn_size (fcn);
		if (!analyze_all) break;
	}
	free (buffer);
	return result;
}


static int java_analyze_fns( RAnal *anal, ut64 start, ut64 end, int reftype, int depth) {
	//anal->iob.read_at (anal->iob.io, op.jump, bbuf, sizeof (bbuf));
	RBinJavaObj *bin = NULL;// = get_java_bin_obj (anal);
	RBinJavaField *method = NULL;
	RListIter *methods_iter, *bin_obs_iter;

	RList * bin_objs_list = get_java_bin_obj_list (anal),
		  * methods_list = NULL;// = bin ? r_bin_java_get_methods_list (bin) : NULL;

	ut8 analyze_all = 0;
	//RAnalRef *ref = NULL;
	int result = R_ANAL_RET_ERROR;

	if (end == UT64_MAX) {
		analyze_all = 1;
	}
	if (!bin_objs_list || r_list_empty (bin_objs_list)) {
		r_list_free (bin_objs_list);
		return java_analyze_fns_from_buffer (anal, start, end, reftype, depth);
	}
	r_list_foreach (bin_objs_list, bin_obs_iter, bin) {
		// loop over all bin object that are loaded
		java_update_anal_types (anal, bin);
		methods_list = (RList *) r_bin_java_get_methods_list (bin);
		if (methods_list) {
			ut64 loadaddr = bin->loadaddr;
			// loop over all methods in the binary object and analyse
			// the functions
			r_list_foreach ( methods_list, methods_iter, method ) {
				if ((method && analyze_all) ||
				    (check_addr_less_start (method, end) ||
				     check_addr_in_code (method, end))) {
					RAnalFunction *fcn = r_anal_fcn_new ();
					fcn->cc = r_anal_cc_default (anal);
					java_set_function_prototype (anal, fcn, method);
					result = analyze_from_code_attr (anal, fcn, method, loadaddr);
					if (result == R_ANAL_RET_ERROR) {
						eprintf ("Failed to parse java fn: %s @ 0x%04"PFMT64x"\n", fcn->name, fcn->addr);
						// XXX - TO Stop or not to Stop ??
					}
					//r_listrange_add (anal->fcnstore, fcn);
					r_list_append (anal->fcns, fcn);
				}
			} // End of methods loop
		}// end of methods_list is valid conditional
	}// end of bin_objs list loop
	return result;
}

/*static int java_fn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	// XXX - this may clash with malloc:// uris because the file name is
	// malloc:// **
	RBinJavaObj *bin = (RBinJavaObj *) get_java_bin_obj (anal);
	RBinJavaField *method = bin ? r_bin_java_get_method_code_attribute_with_addr (bin,  addr) : NULL;
	ut64 loadaddr = bin ? bin->loadaddr : 0;
	IFDBG eprintf ("Analyzing java functions for %s\n", anal->iob.io->fd->name);
	if (method) return analyze_from_code_attr (anal, fcn, method, loadaddr);
	return analyze_from_code_buffer (anal, fcn, addr, buf, len);
}*/

static int java_switch_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_byte = data[0];
	ut64 offset = addr - java_get_method_start ();
	ut8 pos = (offset+1)%4 ? 1 + 4 - (offset+1)%4 : 1;

	if (op_byte == 0xaa) {
		// handle a table switch condition
		if (pos + 8 > len) {
			return op->size;
		}
		int min_val = (ut32)(UINT (data, pos + 4)),
			max_val = (ut32)(UINT (data, pos + 8));

		ut32 default_loc = (ut32) (UINT (data, pos)), cur_case = 0;
		op->switch_op = r_anal_switch_op_new (addr, min_val, default_loc);
		RAnalCaseOp *caseop = NULL;
		pos += 12;
		if (max_val > min_val && ((max_val - min_val)<(UT16_MAX/4))) {
			//caseop = r_anal_switch_op_add_case(op->switch_op, addr+default_loc, -1, addr+offset);
			for (cur_case = 0; cur_case <= max_val - min_val; pos += 4, cur_case++) {
				//ut32 value = (ut32)(UINT (data, pos));
				if (pos + 4 >= len) {
					// switch is too big cant read further
					break;
				}
				int offset = (int)(ut32)(R_BIN_JAVA_UINT (data, pos));
				caseop = r_anal_switch_op_add_case (op->switch_op, addr+pos, cur_case+min_val, addr+offset);
				caseop->bb_ref_to = addr+offset;
				caseop->bb_ref_from = addr; // TODO figure this one out
			}
		} else {
			eprintf ("Invalid switch boundaries at 0x%"PFMT64x"\n", addr);
		}
	}
	op->size = pos;
	return op->size;
}

static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int sz = 1;

	/* get opcode size */
	//ut8 op_byte = data[0];
	ut8 op_byte = data[0];
	sz = JAVA_OPS[op_byte].size;
	if (!op)	return sz;

	memset (op, '\0', sizeof (RAnalOp));

	IFDBG {
		//eprintf ("Extracting op from buffer (%d bytes) @ 0x%04x\n", len, addr);
		//eprintf ("Parsing op: (0x%02x) %s.\n", op_byte, JAVA_OPS[op_byte].name);
	}
	op->addr = addr;
	op->size = sz;
	op->id = data[0];
	op->type2 = JAVA_OPS[op_byte].op_type;
	op->type = r_anal_ex_map_anal_ex_to_anal_op_type (op->type2);
	// handle lookup and table switch offsets
	if (op_byte == 0xaa || op_byte == 0xab) {
		java_switch_op (anal, op, addr, data, len);
		// IN_SWITCH_OP = 1;
	}
	/* TODO: 
	// not sure how to handle the states for IN_SWITCH_OP, SWITCH_OP_CASES,
	// and NUM_CASES_SEEN, because these are dependent on whether or not we
	// are in a switch, and given the non-reentrant state of opcode analysis
	// this can't always be guaranteed.  Below is the pseudo code for handling
	// the easy parts though
	if (IN_SWITCH_OP) {
		NUM_CASES_SEEN++;
		if (NUM_CASES_SEEN == SWITCH_OP_CASES) IN_SWITCH_OP=0;
		op->addr = addr;
		op->size = 4;
		op->type2 = 0;
		op->type = R_ANAL_OP_TYPE_CASE
		op->eob = 0;
		return op->sizes;
	}
	*/

	op->eob = r_anal_ex_is_op_type_eop (op->type2);
	IFDBG {
		const char *ot_str = r_anal_optype_to_string (op->type);
		eprintf ("op_type2: %s @ 0x%04"PFMT64x" 0x%08"PFMT64x" op_type: (0x%02"PFMT64x") %s.\n", JAVA_OPS[op_byte].name, addr, op->type2, op->type,  ot_str);
		//eprintf ("op_eob: 0x%02x.\n", op->eob);
		//eprintf ("op_byte @ 0: 0x%02x op_byte @ 0x%04x: 0x%02x.\n", data[0], addr, data[addr]);
	}

	if (len < 4) {
		// incomplete analysis here
		return 0;
	}
	if (op->type == R_ANAL_OP_TYPE_CJMP) {
		op->jump = addr + (short)(USHORT (data, 1));
		op->fail = addr + sz;
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x"  failto 0x%04"PFMT64x".\n",
			JAVA_OPS[op_byte].name, op->jump, op->fail);
	} else if (op->type  == R_ANAL_OP_TYPE_JMP) {
		op->jump = addr + (short)(USHORT (data, 1));
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x".\n", JAVA_OPS[op_byte].name, op->jump);
	} else if ( (op->type & R_ANAL_OP_TYPE_CALL) == R_ANAL_OP_TYPE_CALL ) {
		op->jump = (int)(short)(USHORT (data, 1));
		op->fail = addr + sz;
		//IFDBG eprintf ("%s callto 0x%04x  failto 0x%04x.\n", JAVA_OPS[op_byte].name, op->jump, op->fail);
	}

	//r_java_disasm(addr, data, len, output, outlen);
	//IFDBG eprintf ("%s\n", output);
	return op->size;
}
/*
static RAnalOp * java_op_from_buffer(RAnal *anal, RAnalState *state, ut64 addr) {

	RAnalOp *op = r_anal_op_new ();
	//  get opcode size 
	if (!op) return 0;
	memset (op, '\0', sizeof (RAnalOp));
	java_op (anal, op, addr, state->buffer, state->len - (addr - state->start) );
	return op;

}
*/

static void java_set_function_prototype (RAnal *anal, RAnalFunction *fcn, RBinJavaField *method) {
	RList *the_list = r_bin_java_extract_type_values (method->descriptor);
	Sdb *D = anal->sdb_types;
	Sdb *A = anal->sdb_args;
	const char *type_fmt = "%08"PFMT64x".arg.%d.type",
	     *namek_fmt = "%08"PFMT64x".var.%d.name",
	     *namev_fmt = "%08"PFMT64x"local.%d";

	char  key_buf[1024], value_buf [1024];
	RListIter *iter;
	char *str;

	if (the_list) {
		ut8 start = 0, stop = 0;
		int idx = 0;
		r_list_foreach (the_list, iter, str) {
			IFDBG eprintf ("Adding type: %s to known types.\n", str);
			if (str && *str == '('){
				start = 1;
				continue;
			}

			if (str && start && *str != ')') {
				// set type
				// set arg type
				snprintf (key_buf, sizeof(key_buf)-1, type_fmt, (ut64)fcn->addr, idx);
				sdb_set (A, str, key_buf, 0);
				sdb_set (D, str, "type", 0);
				// set value
				snprintf (key_buf, sizeof(key_buf)-1, namek_fmt, fcn->addr, idx);
				snprintf (value_buf, sizeof(value_buf)-1, namev_fmt, fcn->addr, idx);
				sdb_set (A, value_buf, key_buf, 0);
				idx ++;
			}
			if (start && str && *str == ')') {
				stop = 1;
				continue;
			}

			if ((start & stop & 1) && str) {
				sdb_set (A, str, "ret.type", 0);
				sdb_set (D, str, "type", 0);
			}
		}
		r_list_free (the_list);
	}
}


static void java_update_anal_types (RAnal *anal, RBinJavaObj *bin_obj) {
	Sdb *D = anal->sdb_types;
	if (D && bin_obj) {
		RListIter *iter;
		char *str;
		RList * the_list = r_bin_java_extract_all_bin_type_values (bin_obj);
		if (the_list) {
			r_list_foreach (the_list, iter, str) {
				IFDBG eprintf ("Adding type: %s to known types.\n", str);
				if (str) sdb_set (D, str, "type", 0);
			}
		}
		r_list_free (the_list);
	}
}

static int java_cmd_ext(RAnal *anal, const char* input) {
	RBinJavaObj *obj = (RBinJavaObj *) get_java_bin_obj (anal);

	if (!obj) {
		eprintf ("Execute \"af\" to set the current bin, and this will bind the current bin\n");
		return -1;
	}
	switch (*input) {
		case 'c':
			// reset bytes counter for case operations
			r_java_new_method ();
			break;
		case 'u':
			switch (*(input+1)) {
				case 't': {java_update_anal_types (anal, obj); return true;}
				default: break;
			}
			break;
		case 's':
			switch (*(input+1)) {
				//case 'e': return java_resolve_cp_idx_b64 (anal, input+2);
				default: break;
			}
			break;

		default: eprintf("Command not supported"); break;
	}
	return 0;
}

static int java_reset_counter (RAnal *anal, ut64 start_addr ) {
	IFDBG eprintf ("Setting the new METHOD_START to 0x%08"PFMT64x" was 0x%08"PFMT64x"\n", start_addr, METHOD_START);
	METHOD_START = start_addr;
	r_java_new_method ();
	return true;
}

RAnalPlugin r_anal_plugin_java = {
	.name = "java",
	.desc = "Java bytecode analysis plugin",
	.license = "Apache",
	.arch = "java",
	.bits = 32,
	.custom_fn_anal = 1,
	.reset_counter = java_reset_counter,
	.analyze_fns = java_analyze_fns,
	.post_anal_bb_cb = java_recursive_descent,
	.revisit_bb_anal = java_revisit_bb_anal_recursive_descent,
	.op = &java_op,
	.cmd_ext = java_cmd_ext,
	0
};

RAnalPlugin r_anal_plugin_java_ls = {
	.name = "java_ls",
	.desc = "Java bytecode analysis plugin with linear sweep",
	.license = "Apache",
	.arch = "java",
	.bits = 32,
	.custom_fn_anal = 1,
	.analyze_fns = java_analyze_fns,
	.post_anal_bb_cb = java_linear_sweep,
	.post_anal = java_post_anal_linear_sweep,
	.revisit_bb_anal = java_revisit_bb_anal_recursive_descent,
	.op = &java_op,
	.cmd_ext = java_cmd_ext,
	0
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	//.data = &r_anal_plugin_java
	.data = &r_anal_plugin_java_ls,
	.version = R2_VERSION
};
#endif
