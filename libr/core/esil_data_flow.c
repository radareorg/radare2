/* radare - LGPL - Copyright 2019 - condret */

#include <r_core.h>
#include <r_util.h>
#include <r_anal.h>
#include <sdb.h>


typedef struct esil_data_flow_t {
	ut32 idx;
	Sdb *latest_nodes;
	RGraph *flow;
} EsilDataFlow;

typedef struct esil_data_flow_node_t {
	// add more info here
	ut32 idx;
	RStrBuf *content;
} EsilDataFlowNode;

EsilDataFlowNode *new_edf_node (EsilDataFlow *edf, const char *c) {
	EsilDataFlowNode *ret = R_NEW(EsilDataFlowNode);
	ret->content = r_strbuf_new(c);
	ret->idx = edf->idx++;
	return ret;
}

void edf_node_free (EsilDataFlowNode *free_me) {
	if (free_me) {
		r_strbuf_free (free_me->content);
	}
	free (free_me);
}

static int edf_consume_2_set_reg (RAnalEsil *esil, const char *op_string);
static int edf_consume_2_push_1 (RAnalEsil *esil, const char *op_string);
static int edf_consume_1_push_1 (RAnalEsil *esil, const char *op_string);
typedef void (*AddConstraintStringUseNewCB)(RStrBuf *result, const char *new_node_str);
static int edf_use_new_push_1 (RAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb);
typedef void (*AddConstraintStringConsume1UseOldNewCB)(RStrBuf *result, const char *consume_str, const char *old_node_str, const char *new_node_str);
static int edf_consume_1_use_old_new_push_1 (RAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb);

static int edf_eq_weak (RAnalEsil *esil) {
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	RGraphNode *o_old = sdb_ptr_get (edf->latest_nodes, "old", 0);	//node for esil->old
	RGraphNode *o_new = sdb_ptr_get (edf->latest_nodes, "new", 0);	//node for esil->cur
	if (!edf_consume_2_set_reg (esil, ":=")) {
		return 0;
	}
	//work-around
	if (o_old) {
		sdb_ptr_set (edf->latest_nodes, "old", o_old, 0);
	} else {
		sdb_remove (edf->latest_nodes, "old", 0);
	}
	if (o_new) {
		sdb_ptr_set (edf->latest_nodes, "new", o_new, 0);
	} else {
		sdb_remove (edf->latest_nodes, "new", 0);
	}
	return 1;
}

static int edf_eq (RAnalEsil *esil) {
	return edf_consume_2_set_reg (esil, "=");
}

static int edf_xoreq (RAnalEsil *esil) {
	return edf_consume_2_set_reg (esil, "^=");
}

static int edf_subeq (RAnalEsil *esil) {
	return edf_consume_2_set_reg (esil, "-=");
}

static int edf_addeq (RAnalEsil *esil) {
	return edf_consume_2_set_reg (esil, "+=");
}

static int edf_add (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "+");
}

static int edf_sub (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "-");
}

#if 0
static int edf_and (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "&");
}

static int edf_or (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "|");
}
#endif

static int edf_xor (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "^");
}

static int edf_mod (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "%");
}

static int edf_mul (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "*");
}

static int edf_div (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "/");
}

static int edf_shr (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, ">>");
}

static int edf_shl (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "<<");
}

static int edf_rotr (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, ">>>");
}

static int edf_rotl (RAnalEsil *esil) {
	return edf_consume_2_push_1 (esil, "<<<");
}

static int edf_not (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "!");
}

static int edf_peek_1 (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "[1]");
}

static int edf_peek_2 (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "[2]");
}

static int edf_peek_4 (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "[4]");
}

static int edf_peek_8 (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "[8]");
}

static int edf_peek_16 (RAnalEsil *esil) {
	return edf_consume_1_push_1 (esil, "[16]");
}

static void edf_zf_constraint (RStrBuf *result, const char *new_node_str) {
	r_strbuf_appendf (result, ":(%s==0)", new_node_str);
}

static int edf_zf (RAnalEsil *esil) {
	return edf_use_new_push_1 (esil, "$z", edf_zf_constraint);
}

static void edf_cf_constraint (RStrBuf *result, const char *consume, const char *o, const char *n) {
	r_strbuf_appendf (result, ":((%s&mask(%s&0x3f))<(%s&mask(%s&0x3f)))",
			n, consume, o, consume);
}

static int edf_cf (RAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$c", edf_cf_constraint);
}

#if 0
static void edf_bf_constraint (RStrBuf *result, const char *consume, const char *o, const char *n) {
	r_strbuf_appendf (result, ":((%s&mask((%s+0x3f)&0x3f))<(%s& mask((%s+0x3f)&0x3f)))",
			o, consume, n, consume);
}
#endif

static int edf_bf (RAnalEsil *esil) {
	return edf_consume_1_use_old_new_push_1 (esil, "$b", edf_cf_constraint);
}

static int edf_consume_2_set_reg (RAnalEsil *esil, const char *op_string) {
	if (!esil) {
		return 0;
	}
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);

	int dst_type = r_anal_esil_get_parm_type (esil, dst);
	if (dst_type == R_ANAL_ESIL_PARM_INVALID) {
		free (dst);
		free (src);
		return 0;
	}
	
	if (!src) {
		free (dst);
		return 0;
	}
	// could be an abstract value
	RGraphNode *src_node = sdb_ptr_get (edf->latest_nodes, src, 0);
	if (!src_node) {
		int src_type = r_anal_esil_get_parm_type (esil, src);
		if (src_type == R_ANAL_ESIL_PARM_INVALID) {
			free (dst);
			free (src);
			return 0;
		}
	
		if (src_type == R_ANAL_ESIL_PARM_NUM) {
			RGraphNode *n_value = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ec_node = new_edf_node (edf, src);
			r_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ev_node = new_edf_node (edf, src);
			r_strbuf_appendf(ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			sdb_ptr_set (edf->latest_nodes, src, src_node, 0);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	} else {
		eprintf ("abstract: %s:%p\n", src, src_node);
	}

	RGraphNode *dst_node = sdb_ptr_get (edf->latest_nodes, dst, 0);
	if (!dst_node) {
		if (dst_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, new_edf_node (edf, dst));
			EsilDataFlowNode *ev_node = new_edf_node (edf, dst);
			r_strbuf_appendf(ev_node->content, ":var_%d", edf->idx++);
			dst_node = r_graph_add_node (edf->flow, ev_node);
//			sdb_ptr_set (edf->latest_nodes, dst, ev_node, 0);
			r_graph_add_edge (edf->flow, n_reg, dst_node);
		}
	}

	if (!src_node || !dst_node) {
		free (src);
		free (dst);
		return 0;
	}

	EsilDataFlowNode *eop_node = new_edf_node (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s,%s", dst, op_string);
	free (src);

	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	r_graph_add_edge (edf->flow, dst_node, op_node);
	r_graph_add_edge (edf->flow, src_node, op_node);
	sdb_ptr_set (edf->latest_nodes, "old", dst_node, 0);		//esil->old
	EsilDataFlowNode *result = new_edf_node (edf, dst);
	r_strbuf_appendf(result->content, ":var_%d", edf->idx++);
	dst_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, dst_node);
	sdb_ptr_set (edf->latest_nodes, dst, dst_node, 0);
	sdb_ptr_set (edf->latest_nodes, "new", dst_node, 0);		//esil->new
	free (dst);
	return 1;
}

static int edf_consume_2_push_1 (RAnalEsil *esil, const char *op_string) {
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	char *src[2] = {r_anal_esil_pop (esil), r_anal_esil_pop (esil)};

	if (!src[0] || !src[1]) {
		free (src[0]);
		free (src[1]);
		return 0;
	}
	EsilDataFlowNode *eop_node = new_edf_node (edf, src[0]);
	r_strbuf_appendf (eop_node->content, ",%s,%s", src[1], op_string);
	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	RGraphNode *src_node[2];
	ut32 i; 
	for (i = 0; i < 2; i++) {
		src_node[i] = sdb_ptr_get (edf->latest_nodes, src[i], 0);
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
				RGraphNode *n_value = r_graph_add_node (edf->flow, new_edf_node (edf, src[i]));
				EsilDataFlowNode *ec_node = new_edf_node (edf, src[i]);
				r_strbuf_appendf(ec_node->content, ":const_%d", edf->idx++);
				src_node[i] = r_graph_add_node (edf->flow, ec_node);
				r_graph_add_edge (edf->flow, n_value, src_node[i]);
			}
			if (src_type == R_ANAL_ESIL_PARM_REG) {
				RGraphNode *n_reg = r_graph_add_node (edf->flow, new_edf_node (edf, src[i]));
				EsilDataFlowNode *ev_node = new_edf_node (edf, src[i]);
				r_strbuf_appendf(ev_node->content, ":var_%d", edf->idx++);
				src_node[i] = r_graph_add_node (edf->flow, ev_node);
				sdb_ptr_set (edf->latest_nodes, src[i], src_node[i], 0);
				r_graph_add_edge (edf->flow, n_reg, src_node[i]);
			}
			// ignore internal vars for now
		}
		r_graph_add_edge (edf->flow, src_node[i], op_node);
	}

	free (src[0]);
	free (src[1]);

	EsilDataFlowNode *result = new_edf_node (edf, "result_");
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, result_node);
	sdb_ptr_set (edf->latest_nodes, r_strbuf_get (result->content), result_node, 0);
	r_anal_esil_push (esil, r_strbuf_get (result->content));
	return 1;
}

static int edf_consume_1_push_1(RAnalEsil *esil, const char *op_string) {
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	char *src = r_anal_esil_pop (esil);
	if (!src) {
		return 0;
	}
	EsilDataFlowNode *eop_node = new_edf_node (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s", op_string);
	RGraphNode *op_node = r_graph_add_node (edf->flow, eop_node);
	RGraphNode *src_node = sdb_ptr_get (edf->latest_nodes, src, 0);
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
			RGraphNode *n_value = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ec_node = new_edf_node (edf, src);
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ev_node = new_edf_node (edf, src);
			r_strbuf_appendf(ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			sdb_ptr_set (edf->latest_nodes, src, src_node, 0);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	}
	
	free (src);

	r_graph_add_edge (edf->flow, src_node, op_node);

	EsilDataFlowNode *result = new_edf_node (edf, "result_");
	r_strbuf_appendf (result->content, "%d", edf->idx++);
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	r_graph_add_edge (edf->flow, op_node, result_node);
	sdb_ptr_set (edf->latest_nodes, r_strbuf_get (result->content), result_node, 0);
	r_anal_esil_push (esil, r_strbuf_get (result->content));
	return 1;
}

static int edf_use_new_push_1(RAnalEsil *esil, const char *op_string, AddConstraintStringUseNewCB cb) {
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	RGraphNode *op_node = r_graph_add_node (edf->flow, new_edf_node (edf, op_string));
	RGraphNode *latest_new = sdb_ptr_get (edf->latest_nodes, "new", 0);	//node for esil->cur
	if (!latest_new) {
		return 0;
	}
	EsilDataFlowNode *result = new_edf_node (edf, "result_");
	r_strbuf_appendf(result->content, "%d", edf->idx++);
	if (cb) {
		EsilDataFlowNode *e_new_node = (EsilDataFlowNode *)latest_new->data;
		cb (result->content, r_strbuf_get (e_new_node->content));
	}
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	sdb_ptr_set (edf->latest_nodes, r_strbuf_get(result->content), result_node, 0);
	r_graph_add_edge (edf->flow, latest_new, op_node);
	r_graph_add_edge (edf->flow, op_node, result_node);
	return r_anal_esil_push (esil, r_strbuf_get(result->content));
}

static int edf_consume_1_use_old_new_push_1 (RAnalEsil *esil, const char *op_string, AddConstraintStringConsume1UseOldNewCB cb) {
	EsilDataFlow *edf = (EsilDataFlow *)esil->user;
	char *src = r_anal_esil_pop (esil);

	if (!src) {
		free (src);
		return 0;
	}
	EsilDataFlowNode *eop_node = new_edf_node (edf, src);
	r_strbuf_appendf (eop_node->content, ",%s", op_string);
	RGraphNode *src_node, *op_node = r_graph_add_node (edf->flow, eop_node);
	src_node = sdb_ptr_get (edf->latest_nodes, src, 0);
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
			RGraphNode *n_value = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ec_node = new_edf_node (edf, src);
			r_strbuf_appendf (ec_node->content, ":const_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ec_node);
			r_graph_add_edge (edf->flow, n_value, src_node);
		}
		if (src_type == R_ANAL_ESIL_PARM_REG) {
			RGraphNode *n_reg = r_graph_add_node (edf->flow, new_edf_node (edf, src));
			EsilDataFlowNode *ev_node = new_edf_node (edf, src);
			r_strbuf_appendf(ev_node->content, ":var_%d", edf->idx++);
			src_node = r_graph_add_node (edf->flow, ev_node);
			sdb_ptr_set (edf->latest_nodes, src, src_node, 0);
			r_graph_add_edge (edf->flow, n_reg, src_node);
		}
		// ignore internal vars for now
	}

	free (src);

	r_graph_add_edge (edf->flow, src_node, op_node);

	RGraphNode *latest_new = sdb_ptr_get(edf->latest_nodes, "new", 0);
	RGraphNode *latest_old = sdb_ptr_get(edf->latest_nodes, "old", 0);
	EsilDataFlowNode *result = new_edf_node (edf, "result_");
	r_strbuf_appendf(result->content, "%d", edf->idx++);
	if (cb) {
		EsilDataFlowNode *e_src_node = (EsilDataFlowNode *)src_node->data;
		EsilDataFlowNode *e_new_node = (EsilDataFlowNode *)latest_new->data;
		EsilDataFlowNode *e_old_node = (EsilDataFlowNode *)latest_old->data;
		cb (result->content, r_strbuf_get (e_src_node->content),
				r_strbuf_get (e_new_node->content), r_strbuf_get (e_old_node->content));
	}
	RGraphNode *result_node = r_graph_add_node (edf->flow, result);
	sdb_ptr_set (edf->latest_nodes, r_strbuf_get(result->content), result_node, 0);
	r_graph_add_edge (edf->flow, latest_new, op_node);
	r_graph_add_edge (edf->flow, latest_old, op_node);
	r_graph_add_edge (edf->flow, op_node, result_node);
	return r_anal_esil_push (esil, r_strbuf_get(result->content));
}

#if 0
void entry(void *user) {
	RCore *core = (RCore *)user;
#if 0
	RAnal *anal = r_anal_new();
	RAnalEsil *esil = r_anal_esil_new(256, 0, 64);
	
	r_anal_use (anal, "x86");
	r_anal_set_bits(anal, 64);
	r_anal_esil_setup (esil, anal, 0, 0, 0);
#endif
#endif
R_API void r_core_anal_esil_graph(RCore *core, const char *expr) {
	RAnalEsil *esil = r_anal_esil_new (4096, 0, 1);
	esil->anal = core->anal;
	EsilDataFlow *edf = R_NEW0 (EsilDataFlow);
	if (!edf) {
		return;
	}
	edf->latest_nodes = sdb_new0 ();
	edf->flow = r_graph_new();

	r_anal_esil_set_op (esil, "=", edf_eq);
	r_anal_esil_set_op (esil, ":=", edf_eq_weak);
	r_anal_esil_set_op (esil, "$z", edf_zf);
	r_anal_esil_set_op (esil, "$c", edf_cf);
	r_anal_esil_set_op (esil, "$b", edf_bf);
	r_anal_esil_set_op (esil, "^=", edf_xoreq);
	r_anal_esil_set_op (esil, "-=", edf_subeq);
	r_anal_esil_set_op (esil, "+=", edf_addeq);
	r_anal_esil_set_op (esil, "+", edf_add);
	r_anal_esil_set_op (esil, "-", edf_sub);
	r_anal_esil_set_op (esil, "&", edf_sub);
	r_anal_esil_set_op (esil, "|", edf_sub);
	r_anal_esil_set_op (esil, "^", edf_xor);
	r_anal_esil_set_op (esil, "%", edf_mod);
	r_anal_esil_set_op (esil, "*", edf_mul);
	r_anal_esil_set_op (esil, "/", edf_div);
	r_anal_esil_set_op (esil, ">>", edf_shr);
	r_anal_esil_set_op (esil, "<<", edf_shl);
	r_anal_esil_set_op (esil, ">>>", edf_rotr);
	r_anal_esil_set_op (esil, ">>>", edf_rotl);
	r_anal_esil_set_op (esil, "!", edf_not);
	r_anal_esil_set_op (esil, "[1]", edf_peek_1);
	r_anal_esil_set_op (esil, "[2]", edf_peek_2);
	r_anal_esil_set_op (esil, "[4]", edf_peek_4);
	r_anal_esil_set_op (esil, "[8]", edf_peek_8);
	r_anal_esil_set_op (esil, "[16]", edf_peek_16);

	esil->user = edf;

	r_anal_esil_parse (esil, expr);
//	r_anal_esil_parse (esil, "1,c,+=,3,$c,H,:=,$z,Z,:=,0,N,:=");			//inc c
//	r_anal_esil_parse (esil, "1,a,<<,C,|,a,=,7,$c,C,:=,$z,Z,:=,0,H,:=,0,N,:=");	//rla
//	r_anal_esil_parse (esil, "rsp,[8],rsi,=,8,rsp,+=");
//	r_anal_esil_parse (esil, "rsp,[8],rax,=,8,rsp,+=");
//	r_anal_esil_parse (esil, "rsi,rax,-,[8],!,!,rbx,=");

	RListIter *iter, *ator;
	RGraphNode *node, *edon;
	r_list_foreach (r_graph_get_nodes (edf->flow), iter, node) {
		const EsilDataFlowNode *enode = (EsilDataFlowNode *)node->data;
		char *esc_str = r_str_escape (r_strbuf_get(enode->content));
		r_cons_printf ("\"agn %d %s\"\n", enode->idx, esc_str);
		node->free = (RListFree)edf_node_free;
		free (esc_str);
	}

	r_list_foreach (r_graph_get_nodes(edf->flow), iter, node) {
		const EsilDataFlowNode *enode = (EsilDataFlowNode *)node->data;
		r_list_foreach (r_graph_get_neighbours(edf->flow, node), ator, edon) {
			const EsilDataFlowNode *edone = (EsilDataFlowNode *)edon->data;
			r_cons_printf ("age %d %d\n", enode->idx, edone->idx);
		}
	}

	r_graph_free (edf->flow);
	sdb_free (edf->latest_nodes);
	free (edf);
	r_anal_esil_free (esil);
}
