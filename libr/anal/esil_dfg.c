/* radare - LGPL - Copyright 2019 - condret */

#include <r_util.h>
#include <r_anal.h>
#include <sdb.h>

typedef struct r_anal_esil_dfg_filter_t {
	RAnalEsilDFG *dfg;
	RContRBTree *tree;
	Sdb *results;
} RAnalEsilDFGFilter;

// TODO: simple const propagation - use node->type of srcs to propagate consts of pushed vars

R_API RAnalEsilDFGNode *r_anal_esil_dfg_node_new(RAnalEsilDFG *edf, const char *c) {
	RAnalEsilDFGNode *ret = R_NEW0 (RAnalEsilDFGNode);
	ret->content = r_strbuf_new (c);
	ret->idx = edf->idx++;
	return ret;
}

void _dfg_node_free (RAnalEsilDFGNode *free_me) {
	if (free_me) {
		r_strbuf_free (free_me->content);
	}
	free (free_me);
}

static bool _edf_reg_set(RAnalEsilDFG *edf, const char *reg, RGraphNode *node) {
	return edf ? !sdb_ptr_set (edf->latest_nodes, reg, node, 0) : false;
}

static void* _edf_reg_get(RAnalEsilDFG *edf, const char *reg) {
	return edf ? sdb_ptr_get (edf->latest_nodes, reg, 0) : NULL;
}

static bool edf_consume_2_set_reg(RAnalEsil *esil);
static bool edf_consume_2_push_1(RAnalEsil *esil);
static bool edf_consume_1_push_1(RAnalEsil *esil);
typedef void (*AddConstraintStringUseNewCB) (RStrBuf *result, const char *new_node_str);
static bool edf_use_new_push_1(RAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb);
typedef void (*AddConstraintStringConsume1UseOldNewCB) (RStrBuf *result, const char *consume_str, const char *old_node_str, const char *new_node_str);
static bool edf_consume_1_use_old_new_push_1(RAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb);

static bool edf_eq_weak(RAnalEsil *esil) {
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	RGraphNode *o_old = edf->old; //node for esil->old
	RGraphNode *o_new = edf->cur; //node for esil->cur
	if (!edf_consume_2_set_reg (esil)) {
		return false;
	}
	//work-around
	edf->old = o_old ? o_old : NULL;
	edf->cur = o_new ? o_new : NULL;
	return true;
}

static void edf_zf_constraint(RStrBuf *result, const char *new_node_str) {
	r_strbuf_appendf (result, ":(%s==0)", new_node_str);
}

static bool edf_zf(RAnalEsil *esil) {
	return edf_use_new_push_1 (esil, "$z", edf_zf_constraint);
}

static void edf_pf_constraint(RStrBuf *result, const char *new_node_str) {
	r_strbuf_appendf (result, ":parity_of(%s)", new_node_str);
}

static bool edf_pf(RAnalEsil *esil) {
	return edf_use_new_push_1 (esil, "$p", edf_pf_constraint);
}

static void edf_cf_constraint(RStrBuf *result, const char *consume, const char *o, const char *n) {
	r_strbuf_appendf (result, ":((%s&mask(%s&0x3f))<(%s&mask(%s&0x3f)))",
		n, consume, o, consume);
}

static bool edf_cf(RAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$c", edf_cf_constraint);
}

static void edf_bf_constraint(RStrBuf *result, const char *consume, const char *o, const char *n) {
	r_strbuf_appendf (result, ":((%s&mask((%s+0x3f)&0x3f))<(%s& mask((%s+0x3f)&0x3f)))",
		o, consume, n, consume);
}

static bool edf_bf(RAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$b", edf_bf_constraint);
}

static bool _edf_consume_2_set_reg(RAnalEsil *esil, const bool use_origin) {
	const char *op_string = esil->current_opstr;
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}

	int dst_type = r_anal_esil_get_parm_type (esil, dst);
	if (dst_type == R_ANAL_ESIL_PARM_INVALID) {
		free (dst);
		free (src);
		return false;
	}

	// could be an abstract value
	RGraphNode *src_node = _edf_reg_get (edf, src);
	if (!src_node) {
		int src_type = r_anal_esil_get_parm_type (esil, src);
		if (src_type == R_ANAL_ESIL_PARM_INVALID) {
			free (dst);
			free (src);
			return false;
		}

		if (src_type == R_ANAL_ESIL_PARM_NUM) {
			RGraphNode *n_value = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ec_node = r_anal_esil_dfg_node_new (edf, src);
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, src);
			r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			_edf_reg_set(edf, src, src_node);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	} else {
		eprintf ("abstract: %s:%p\n", src, src_node);
	}

	RGraphNode *dst_node = _edf_reg_get (edf, dst);
	RGraphNode *old_dst_node = NULL;
	if (!dst_node) {
		if (dst_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, dst));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, dst);
			ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
			r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
			dst_node = r_graph_add_node (edf->flow, ev_node);
			ev_node->origin = dst_node; // consider using n_reg instead
			//			_edf_reg_set (edf, dst, ev_node);
			r_graph_add_edge (edf->flow, n_reg, dst_node);
			old_dst_node = dst_node;
		}
	} else {
		old_dst_node = dst_node;
		if ((dst_type == R_ANAL_ESIL_PARM_REG) && use_origin) {
			RAnalEsilDFGNode *ev_node = (RAnalEsilDFGNode *)dst_node->data;
			dst_node = ev_node->origin;
		}
	}

	if (!src_node || !dst_node) {
		free (src);
		free (dst);
		return false;
	}

	RAnalEsilDFGNode *eop_node = r_anal_esil_dfg_node_new (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	free (src);

	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	r_graph_add_edge (edf->flow, dst_node, op_node);
	r_graph_add_edge (edf->flow, src_node, op_node);
	edf->old = old_dst_node;
	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, dst);
	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT | R_ANAL_ESIL_DFG_BLOCK_VAR;
	if (use_origin) {
		result->origin = dst_node;
	} else {
		RAnalEsilDFGNode *ev_node = (RAnalEsilDFGNode *)dst_node->data;
		result->origin = ev_node->origin ? ev_node->origin : dst_node;
	}
	r_strbuf_appendf (result->content, ":var_%d", edf->idx++);
	dst_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, dst_node);
	_edf_reg_set (edf, dst, dst_node);
	edf->cur = dst_node;
	free (dst);
	return true;
}

static bool edf_consume_2_use_set_reg(RAnalEsil *esil) {
	return _edf_consume_2_set_reg (esil, false);
}

static bool edf_consume_2_set_reg(RAnalEsil *esil) {
	return _edf_consume_2_set_reg (esil, true);
}

static bool edf_consume_2_push_1(RAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	char *src[2] = { r_anal_esil_pop (esil), r_anal_esil_pop (esil) };

	if (!src[0] || !src[1]) {
		free (src[0]);
		free (src[1]);
		return false;
	}
	RAnalEsilDFGNode *eop_node = r_anal_esil_dfg_node_new (edf, src[1]);
	r_strbuf_appendf (eop_node->content, ",%s,%s", src[0], op_string);
	eop_node->type = R_ANAL_ESIL_DFG_BLOCK_RESULT | R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	RGraphNode *src_node[2];
	ut32 i;
	for (i = 0; i < 2; i++) {
		src_node[i] = _edf_reg_get (edf, src[i]);
		if (!src_node[i]) {
			int src_type = r_anal_esil_get_parm_type (esil, src[i]);
#if 0
			//TODO: better input validation
			if (src_type == R_ANAL_ESIL_PARM_INVALID) {
				free (dst);
				free (src);
				return 0;
			}
#endif

			if (src_type == R_ANAL_ESIL_PARM_NUM) {
				RGraphNode *n_value = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src[i]));
				RAnalEsilDFGNode *ec_node = r_anal_esil_dfg_node_new (edf, src[i]);
				r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
				ec_node->type = R_ANAL_ESIL_DFG_BLOCK_CONST;
				src_node[i] = r_graph_add_node (edf->flow, ec_node);
				r_graph_add_edge (edf->flow, n_value, src_node[i]);
			}
			if (src_type == R_ANAL_ESIL_PARM_REG) {
				RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src[i]));
				RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, src[i]);
				r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
				ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
				src_node[i] = r_graph_add_node (edf->flow, ev_node);
				_edf_reg_set (edf, src[i], src_node[i]);
				r_graph_add_edge (edf->flow, n_reg, src_node[i]);
			}
			// ignore internal vars for now
		}
		r_graph_add_edge (edf->flow, src_node[i], op_node);
	}

	free (src[0]);
	free (src[1]);

	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, "result_");
	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT;
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, result_node);
	_edf_reg_set (edf, r_strbuf_get (result->content), result_node);
	r_anal_esil_push (esil, r_strbuf_get (result->content));
	return true;
}

static bool edf_consume_1_push_1(RAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	char *src = r_anal_esil_pop (esil);
	if (!src) {
		return false;
	}
	RAnalEsilDFGNode *eop_node = r_anal_esil_dfg_node_new (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s", op_string);
	eop_node->type = R_ANAL_ESIL_DFG_BLOCK_RESULT | R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	RGraphNode *src_node = _edf_reg_get (edf, src);
	if (!src_node) {
		int src_type = r_anal_esil_get_parm_type (esil, src);
#if 0
		//TODO: better input validation
		if (src_type == R_ANAL_ESIL_PARM_INVALID) {
			free (dst);
			free (src);
			return 0;
		}
#endif
		if (src_type == R_ANAL_ESIL_PARM_NUM) {
			RGraphNode *n_value = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ec_node = r_anal_esil_dfg_node_new (edf, src);
			ec_node->type = R_ANAL_ESIL_DFG_BLOCK_CONST;
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, src);
			ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
			r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			_edf_reg_set (edf, src, src_node);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	}

	free (src);

	r_graph_add_edge (edf->flow, src_node, op_node);

	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, "result_");
	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT; //TODO: propgate type from src here
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, result_node);
	_edf_reg_set (edf, r_strbuf_get (result->content), result_node);
	r_anal_esil_push (esil, r_strbuf_get (result->content));
	return true;
}

static bool edf_consume_2_set_mem(RAnalEsil *esil) {
	const char *op_string = esil->current_opstr;
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return 0;
	}

	int dst_type = r_anal_esil_get_parm_type (esil, dst);

	RGraphNode *src_node = _edf_reg_get (edf, src);
	if (!src_node) {
		int src_type = r_anal_esil_get_parm_type (esil, src);
		if (src_type == R_ANAL_ESIL_PARM_INVALID) {
			free (dst);
			free (src);
			return false;
		}

		if (src_type == R_ANAL_ESIL_PARM_NUM) {
			RGraphNode *n_value = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ec_node = r_anal_esil_dfg_node_new (edf, src);
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			ec_node->type = R_ANAL_ESIL_DFG_BLOCK_CONST;
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, src);
			r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
			ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
			src_node = r_graph_add_node (edf->flow, ev_node);
			_edf_reg_set (edf, src, src_node);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	} else {
		eprintf ("abstract: %s:%p\n", src, src_node);
	}

	RGraphNode *dst_node = _edf_reg_get (edf, dst);
	if (!dst_node) {
		if (dst_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, dst));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, dst);
			ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR | R_ANAL_ESIL_DFG_BLOCK_PTR;
			r_strbuf_appendf (ev_node->content, ":var_ptr_%d", edf->idx++);
			dst_node = r_graph_add_node (edf->flow, ev_node);
			//			_edf_reg_set (edf, dst, ev_node);
			r_graph_add_edge (edf->flow, n_reg, dst_node);
		}
		// TODO: const pointers
	}

	if (!src_node || !dst_node) {
		free (src);
		free (dst);
		return false;
	}

	RAnalEsilDFGNode *eop_node = r_anal_esil_dfg_node_new (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s,%s", dst, op_string);
	eop_node->type = R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	free (src);

	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	r_graph_add_edge (edf->flow, dst_node, op_node);
	r_graph_add_edge (edf->flow, src_node, op_node);
	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, dst);
	//	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT | R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
	result->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
	r_strbuf_appendf (result->content, ":var_mem_%d", edf->idx++);
	dst_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, dst_node);
	free (dst);
	return true;
}

static bool edf_use_new_push_1(RAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb) {
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	RGraphNode *op_node = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, op_string));
	RGraphNode *latest_new = _edf_reg_get (edf, "new"); //node for esil->cur
	if (!latest_new) {
		return 0;
	}
	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, "result_");
	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT; // is this generative?
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	if (cb) {
		RAnalEsilDFGNode *e_new_node = (RAnalEsilDFGNode *)latest_new->data;
		cb (result->content, r_strbuf_get (e_new_node->content));
	}
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	_edf_reg_set (edf, r_strbuf_get (result->content), result_node);
	r_graph_add_edge (edf->flow, latest_new, op_node);
	r_graph_add_edge (edf->flow, op_node, result_node);
	return r_anal_esil_push (esil, r_strbuf_get (result->content));
}

static bool edf_consume_1_use_old_new_push_1(RAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb) {
	RAnalEsilDFG *edf = (RAnalEsilDFG *)esil->user;
	char *src = r_anal_esil_pop (esil);

	if (!src) {
		return false;
	}
	RAnalEsilDFGNode *eop_node = r_anal_esil_dfg_node_new (edf, src);
#if 0
	eop_node->type = R_ANAL_ESIL_DFG_BLOCK_GENERATIVE;
#endif
	r_strbuf_appendf (eop_node->content, ",%s", op_string);
	RGraphNode *src_node, *op_node = r_graph_add_node (edf->flow, eop_node);
	src_node = _edf_reg_get (edf, src);
	if (!src_node) {
		int src_type = r_anal_esil_get_parm_type (esil, src);
#if 0
		//TODO: better input validation
		if (src_type == R_ANAL_ESIL_PARM_INVALID) {
			free (dst);
			free (src);
			return 0;
		}
#endif
		if (src_type == R_ANAL_ESIL_PARM_NUM) {
			RGraphNode *n_value = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ec_node = r_anal_esil_dfg_node_new (edf, src);
			ec_node->type = R_ANAL_ESIL_DFG_BLOCK_CONST;
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, r_anal_esil_dfg_node_new (edf, src));
			RAnalEsilDFGNode *ev_node = r_anal_esil_dfg_node_new (edf, src);
			ev_node->type = R_ANAL_ESIL_DFG_BLOCK_VAR;
			r_strbuf_appendf (ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			_edf_reg_set (edf, src, src_node);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	}

	free (src);

	r_graph_add_edge (edf->flow, src_node, op_node);

	RGraphNode *latest_new = edf->cur;
	RGraphNode *latest_old = edf->old;
	RAnalEsilDFGNode *result = r_anal_esil_dfg_node_new (edf, "result_");
	result->type = R_ANAL_ESIL_DFG_BLOCK_RESULT; // propagate type here
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	if (cb) {
		RAnalEsilDFGNode *e_src_node = (RAnalEsilDFGNode *)src_node->data;
		RAnalEsilDFGNode *e_new_node = (RAnalEsilDFGNode *)latest_new->data;
		RAnalEsilDFGNode *e_old_node = (RAnalEsilDFGNode *)latest_old->data;
		cb (result->content, r_strbuf_get (e_src_node->content),
			r_strbuf_get (e_new_node->content), r_strbuf_get (e_old_node->content));
	}
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	_edf_reg_set (edf, r_strbuf_get (result->content), result_node);
	r_graph_add_edge (edf->flow, latest_new, op_node);
	r_graph_add_edge (edf->flow, latest_old, op_node);
	r_graph_add_edge (edf->flow, op_node, result_node);
	return r_anal_esil_push (esil, r_strbuf_get (result->content));
}

R_API RAnalEsilDFG *r_anal_esil_dfg_new() {
	RAnalEsilDFG *dfg = R_NEW0 (RAnalEsilDFG);
	if (!dfg) {
		return NULL;
	}
	dfg->flow = r_graph_new ();
	if (!dfg->flow) {
		free (dfg);
		return NULL;
	}
	dfg->latest_nodes = sdb_new0 ();
	if (!dfg->latest_nodes) {
		r_graph_free (dfg->flow);
		free (dfg);
		return NULL;
	}
	return dfg;
}

R_API void r_anal_esil_dfg_free(RAnalEsilDFG *dfg) {
	if (dfg) {
		if (dfg->flow) {
			RGraphNode *n;
			RListIter *iter;
			r_list_foreach (r_graph_get_nodes (dfg->flow), iter, n) {
				n->free = (RListFree)_dfg_node_free;
			}
			r_graph_free (dfg->flow);
		}
		sdb_free (dfg->latest_nodes);
		free (dfg);
	}
}

R_API RAnalEsilDFG *r_anal_esil_dfg_expr(RAnal *anal, RAnalEsilDFG *dfg, const char *expr) {
	if (!expr) {
		return NULL;
	}
	RAnalEsil *esil = r_anal_esil_new (4096, 0, 1);
	if (!esil) {
		return NULL;
	}
	esil->anal = anal;

	RAnalEsilDFG *edf = dfg ? dfg : r_anal_esil_dfg_new ();
	if (!edf) {
		r_anal_esil_free (esil);
		return NULL;
	}

	r_anal_esil_set_op (esil, "=", edf_consume_2_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, ":=", edf_eq_weak, 0, 2, R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "$z", edf_zf, 1, 0, R_ANAL_ESIL_OP_TYPE_UNKNOWN);
	r_anal_esil_set_op (esil, "$p", edf_pf, 1, 0, R_ANAL_ESIL_OP_TYPE_UNKNOWN);
	r_anal_esil_set_op (esil, "$c", edf_cf, 1, 1, R_ANAL_ESIL_OP_TYPE_UNKNOWN);
	r_anal_esil_set_op (esil, "$b", edf_bf, 1, 1, R_ANAL_ESIL_OP_TYPE_UNKNOWN);
	r_anal_esil_set_op (esil, "^=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "-=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "+=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "*=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "/=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "&=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "|=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "^=", edf_consume_2_use_set_reg, 0, 2, R_ANAL_ESIL_OP_TYPE_MATH | R_ANAL_ESIL_OP_TYPE_REG_WRITE);
	r_anal_esil_set_op (esil, "+", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "-", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "&", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "|", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "^", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "%", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "*", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "/", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, ">>", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "<<", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, ">>>", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, ">>>", edf_consume_2_push_1, 1, 2, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "!", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MATH);
	r_anal_esil_set_op (esil, "[1]", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MEM_READ);
	r_anal_esil_set_op (esil, "[2]", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MEM_READ);
	r_anal_esil_set_op (esil, "[4]", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MEM_READ);
	r_anal_esil_set_op (esil, "[8]", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MEM_READ);
	r_anal_esil_set_op (esil, "[16]", edf_consume_1_push_1, 1, 1, R_ANAL_ESIL_OP_TYPE_MEM_READ);
	r_anal_esil_set_op (esil, "=[1]", edf_consume_2_set_mem, 0, 2, R_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	r_anal_esil_set_op (esil, "=[2]", edf_consume_2_set_mem, 0, 2, R_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	r_anal_esil_set_op (esil, "=[4]", edf_consume_2_set_mem, 0, 2, R_ANAL_ESIL_OP_TYPE_MEM_WRITE);
	r_anal_esil_set_op (esil, "=[8]", edf_consume_2_set_mem, 0, 2, R_ANAL_ESIL_OP_TYPE_MEM_WRITE);

	esil->user = edf;

	r_anal_esil_parse (esil, expr);
	r_anal_esil_free (esil);
	return edf;
}

static int _dfg_node_filter_insert_cmp(void *incoming, void *in, void *user) {
	RAnalEsilDFGNode *incoming_node = (RAnalEsilDFGNode *)incoming;
	RAnalEsilDFGNode *in_node = (RAnalEsilDFGNode *)in;
	return incoming_node->idx - in_node->idx;
}

static void _dfg_rev_dfs_cb(RGraphNode *n, RGraphVisitor *vi) {
	RAnalEsilDFGNode *node = (RAnalEsilDFGNode *)n->data;
	RAnalEsilDFGFilter *filter = (RAnalEsilDFGFilter *)vi->data;
	switch (node->type) {
	case R_ANAL_ESIL_DFG_BLOCK_CONST:
	case R_ANAL_ESIL_DFG_BLOCK_VAR:
	case R_ANAL_ESIL_DFG_BLOCK_PTR:
		break;
	case R_ANAL_ESIL_DFG_BLOCK_GENERATIVE:
		r_rbtree_cont_insert (filter->tree, node, _dfg_node_filter_insert_cmp, NULL);
		break;
	case R_ANAL_ESIL_DFG_BLOCK_RESULT: // outnode must be result generator here
	{
		RGraphNode *previous = (RGraphNode *)r_list_get_top (n->in_nodes);
		if (previous) {
			sdb_ptr_set (filter->results, r_strbuf_get (node->content), previous, 0);
		}
	} break;
	}
}

static char *condrets_strtok(char *str, const char tok) {
	if (!str) {
		return NULL;
	}
	ut32 i = 0;
	while (1 == 1) {
		if (!str[i]) {
			break;
		}
		if (str[i] == tok) {
			str[i] = '\0';
			return &str[i + 1];
		}
		i++;
	}
	return NULL;
}

static RStrBuf *get_resolved_expr(RAnalEsilDFGFilter *filter, RAnalEsilDFGNode *node) {
	char *expr = strdup (r_strbuf_get (node->content));
	RStrBuf *res = r_strbuf_new ("");
	if (!expr) { //empty expressions. can this happen?
		return res;
	}
	char *p, *q;
	// we can do this bc every generative node MUST end with an operator
	for (p = expr; (q = condrets_strtok (p, ',')); p = q) {
		RGraphNode *gn = sdb_ptr_get (filter->results, p, 0);
		if (!gn) {
			r_strbuf_appendf (res, ",%s,", p);
		} else {
			eprintf ("resolving %s\n", p);
			RStrBuf *r = get_resolved_expr (filter, (RAnalEsilDFGNode *)gn->data);
			r_strbuf_appendf (res, ",%s,", r_strbuf_get (r));
			r_strbuf_free (r);
		}
	}
	r_strbuf_appendf (res, "%s", p);
	free (expr);
	return res;
}

R_API RStrBuf *r_anal_esil_dfg_filter(RAnalEsilDFG *dfg, const char *reg) {
	if (!dfg || !reg) {
		return NULL;
	}
	RGraphNode *resolve_me = _edf_reg_get (dfg, reg);
	if (!resolve_me) {
		return NULL;
	}

	// allocate stuff
	RAnalEsilDFGFilter filter = { dfg, r_rbtree_cont_new (), sdb_new0 () };
	RStrBuf *filtered = r_strbuf_new ("");
	RGraphVisitor vi = { _dfg_rev_dfs_cb, NULL, NULL, NULL, NULL, &filter };

	// dfs the graph starting at node of esp-register
	r_graph_dfs_node_reverse (dfg->flow, resolve_me, &vi);

	RBIter ator;
	RAnalEsilDFGNode *node;
	r_rbtree_cont_foreach (filter.tree, ator, node) {
		// resolve results to opstr here
		RStrBuf *resolved = get_resolved_expr (&filter, node);
		r_strbuf_append (filtered, r_strbuf_get (resolved));
		r_strbuf_free (resolved);
	}
	{
		char *sanitized = r_str_replace (r_str_replace (strdup (r_strbuf_get (filtered)), ",,", ",", 1), ",,", ",", 1);
		r_strbuf_set (filtered, (sanitized[0] == ',') ? &sanitized[1] : sanitized);
		free (sanitized);
	}
	r_rbtree_cont_free (filter.tree);
	sdb_free (filter.results);
	return filtered;
}

R_API RStrBuf *r_anal_esil_dfg_filter_expr(RAnal *anal, const char *expr, const char *reg) {
	if (!reg) {
		return NULL;
	}
	RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (anal, NULL, expr);
	if (!dfg) {
		return NULL;
	}
	RStrBuf *filtered = r_anal_esil_dfg_filter (dfg, reg);
	r_anal_esil_dfg_free (dfg);
	return filtered;
}
