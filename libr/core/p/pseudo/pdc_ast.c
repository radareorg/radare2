/* radare - LGPL - Copyright 2026 - pancake, phix33 */

// Region-AST structuring pass for the native pdc decompiler.
// Builds an if/else/loop/switch region tree over the function CFG using the
// dominator/post-dominator trees and DFS back edges, and dumps it (pdct).
// It changes no pdc output: consumers land in later milestones.

#include <r_core.h>
#include "pdc_ast.h"

typedef enum {
	PDC_R_BB,	// leaf basic block
	PDC_R_SEQ,	// ordered run of sub-regions
	PDC_R_IF,	// single-armed conditional
	PDC_R_IFELSE,	// two-armed conditional (children: then, else)
	PDC_R_WHILE,	// top-test loop
	PDC_R_DOWHILE,	// tail/self test loop
	PDC_R_SWITCH,	// jump table (children: one per unique case target)
	PDC_R_GOTO	// irreducible / already-emitted fallback, never fails
} PdcRegionType;

typedef struct pdc_region_t PdcRegion;
R_VEC_TYPE (RVecPdcRegionPtr, PdcRegion *);

struct pdc_region_t {
	PdcRegionType type;
	ut64 addr;
	RVecPdcRegionPtr children;
};

typedef struct {
	RCore *core;
	RAnal *anal;
	RAnalFunction *fcn;
	HtUU *idom;	// block addr => immediate dominator addr (entry => UT64_MAX)
	HtUU *ipdom;	// block addr => immediate post-dominator addr (UT64_MAX => exit)
	HtUU *headers;	// loop-header addr => 1
	HtUU *emitted;	// block addr => 1 (each block heads a region at most once)
	int build_calls;
	int cap;
} PdcCtx;

static PdcRegion *region_new(PdcRegionType type, ut64 addr) {
	PdcRegion *r = R_NEW0 (PdcRegion);
	r->type = type;
	r->addr = addr;
	RVecPdcRegionPtr_init (&r->children);
	return r;
}

static void region_free(PdcRegion *r) {
	if (!r) {
		return;
	}
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		region_free (*it);
	}
	RVecPdcRegionPtr_fini (&r->children);
	free (r);
}

static void region_add_child(PdcRegion *parent, PdcRegion *child) {
	if (child) {
		RVecPdcRegionPtr_push_back (&parent->children, &child);
	}
}

static ut64 htuu_get(HtUU *m, ut64 key, ut64 dflt) {
	bool found = false;
	const ut64 v = ht_uu_find (m, key, &found);
	return found? v: dflt;
}

// a is on the dominator chain of b (inclusive)
static bool dominates(PdcCtx *ctx, ut64 a, ut64 b) {
	ut64 x = b;
	int guard = ctx->cap;
	while (x != UT64_MAX && guard-- > 0) {
		if (x == a) {
			return true;
		}
		x = htuu_get (ctx->idom, x, UT64_MAX);
	}
	return false;
}

typedef struct {
	PdcCtx *ctx;
} BackEdgeCtx;

static void back_edge_cb(const RGraphEdge *e, RGraphVisitor *vis) {
	BackEdgeCtx *bc = vis->data;
	RAnalBlock *header = e->to? (RAnalBlock *)e->to->data: NULL;
	if (header) {
		ht_uu_update (bc->ctx->headers, header->addr, 1);
	}
}

// dom/pdom tree node data is the *CFG* graph node, whose data is the RAnalBlock
static RAnalBlock *treenode_block(RGraphNode *tn) {
	RGraphNode *cnode = tn? (RGraphNode *)tn->data: NULL;
	return cnode? (RAnalBlock *)cnode->data: NULL;
}

// fill dst[block addr] = tree-parent block addr (UT64_MAX for the root / sink)
static void collect_idom(HtUU *dst, RGraph *tree) {
	RListIter *it;
	RGraphNode *tn;
	r_list_foreach (tree->nodes, it, tn) {
		RAnalBlock *bb = treenode_block (tn);
		if (!bb) {
			continue;
		}
		ut64 parent = UT64_MAX;
		if (!RVecGraphNodePtr_empty (&tn->in_nodes)) {
			RGraphNode **p = RVecGraphNodePtr_at (&tn->in_nodes, 0);
			RAnalBlock *pb = p? treenode_block (*p): NULL;
			if (pb) {
				parent = pb->addr;
			}
		}
		ht_uu_update (dst, bb->addr, parent);
	}
}

static bool block_is_exit(RAnalBlock *bb) {
	return bb->jump == UT64_MAX && bb->fail == UT64_MAX
		&& (!bb->switch_op || r_list_empty (bb->switch_op->cases));
}

static PdcRegion *region_seq(PdcCtx *ctx, ut64 addr, ut64 stop);
static PdcRegion *build_region(PdcCtx *ctx, ut64 cur, ut64 stop, ut64 *next);

static PdcRegion *build_loop(PdcCtx *ctx, RAnalBlock *bb, ut64 *next) {
	const ut64 h = bb->addr;
	const ut64 j = bb->jump;
	const ut64 f = bb->fail;
	const ut64 ipd = htuu_get (ctx->ipdom, h, UT64_MAX);
	ut64 body_start = UT64_MAX;
	ut64 exit = ipd;
	PdcRegionType lt = PDC_R_WHILE;
	if (j != UT64_MAX && f != UT64_MAX) {
		// two-way header: the successor left by ipdom is the exit, the other the body
		if (f == ipd) {
			body_start = j;
			exit = f;
		} else if (j == ipd) {
			body_start = f;
			exit = j;
		} else if (!dominates (ctx, h, f) && dominates (ctx, h, j)) {
			body_start = j;
			exit = f;
		} else if (!dominates (ctx, h, j) && dominates (ctx, h, f)) {
			body_start = f;
			exit = j;
		} else {
			body_start = j;
			exit = f;
		}
		if (j == h || f == h) {
			lt = PDC_R_DOWHILE;
		}
	} else {
		body_start = (j != UT64_MAX)? j: f;
		lt = PDC_R_DOWHILE;
	}
	PdcRegion *loop = region_new (lt, h);
	if (body_start != UT64_MAX && body_start != h) {
		region_add_child (loop, region_seq (ctx, body_start, h));
	}
	*next = exit;
	return loop;
}

static PdcRegion *build_switch(PdcCtx *ctx, RAnalBlock *bb, ut64 *next) {
	const ut64 join = htuu_get (ctx->ipdom, bb->addr, UT64_MAX);
	PdcRegion *sw = region_new (PDC_R_SWITCH, bb->addr);
	HtUU *seen = ht_uu_new0 ();
	RListIter *it;
	RAnalCaseOp *co;
	r_list_foreach (bb->switch_op->cases, it, co) {
		if (co->jump == UT64_MAX || htuu_get (seen, co->jump, 0)) {
			continue;
		}
		ht_uu_update (seen, co->jump, 1);
		region_add_child (sw, region_seq (ctx, co->jump, join));
	}
	const ut64 defv = bb->switch_op->def_val;
	if (defv != UT64_MAX && !htuu_get (seen, defv, 0)) {
		region_add_child (sw, region_seq (ctx, defv, join));
	}
	ht_uu_free (seen);
	*next = join;
	return sw;
}

// build the region headed by cur; *next is where control continues after it
static PdcRegion *build_region(PdcCtx *ctx, ut64 cur, ut64 stop, ut64 *next) {
	*next = UT64_MAX;
	if (cur == UT64_MAX || cur == stop) {
		return NULL;
	}
	if (++ctx->build_calls > ctx->cap || htuu_get (ctx->emitted, cur, 0)) {
		return region_new (PDC_R_GOTO, cur);
	}
	RAnalBlock *bb = r_anal_get_block_at (ctx->anal, cur);
	if (!bb) {
		return region_new (PDC_R_GOTO, cur);
	}
	ht_uu_update (ctx->emitted, cur, 1);

	if (htuu_get (ctx->headers, cur, 0)) {
		return build_loop (ctx, bb, next);
	}
	if (bb->switch_op && !r_list_empty (bb->switch_op->cases)) {
		return build_switch (ctx, bb, next);
	}
	if (bb->jump != UT64_MAX && bb->fail != UT64_MAX) {
		const ut64 join = htuu_get (ctx->ipdom, cur, UT64_MAX);
		PdcRegion *then_r = (bb->jump == join)? NULL: region_seq (ctx, bb->jump, join);
		PdcRegion *else_r = (bb->fail == join)? NULL: region_seq (ctx, bb->fail, join);
		*next = join;
		if (!then_r && !else_r) {
			return region_new (PDC_R_BB, cur);
		}
		if (then_r && else_r) {
			PdcRegion *r = region_new (PDC_R_IFELSE, cur);
			region_add_child (r, then_r);
			region_add_child (r, else_r);
			return r;
		}
		PdcRegion *r = region_new (PDC_R_IF, cur);
		region_add_child (r, then_r? then_r: else_r);
		return r;
	}
	// one-way (continue the enclosing seq) or return block; a block may carry
	// only a fail edge (fall-through split) with no jump
	*next = (bb->jump != UT64_MAX)? bb->jump: bb->fail;
	return region_new (PDC_R_BB, cur);
}

static PdcRegion *region_seq(PdcCtx *ctx, ut64 addr, ut64 stop) {
	PdcRegion *seq = region_new (PDC_R_SEQ, addr);
	ut64 cur = addr;
	int guard = ctx->cap;
	while (cur != UT64_MAX && cur != stop && guard-- > 0) {
		if (htuu_get (ctx->emitted, cur, 0)) {
			region_add_child (seq, region_new (PDC_R_GOTO, cur));
			break;
		}
		ut64 next = UT64_MAX;
		PdcRegion *r = build_region (ctx, cur, stop, &next);
		if (!r) {
			break;
		}
		region_add_child (seq, r);
		cur = next;
	}
	const ut64 n = RVecPdcRegionPtr_length (&seq->children);
	if (n == 0) {
		region_free (seq);
		return NULL;
	}
	if (n == 1) {
		PdcRegion *only = *RVecPdcRegionPtr_at (&seq->children, 0);
		RVecPdcRegionPtr_fini (&seq->children);
		free (seq);
		return only;
	}
	return seq;
}

static const char *region_kind(PdcRegionType t) {
	switch (t) {
	case PDC_R_BB: return "bb";
	case PDC_R_SEQ: return "seq";
	case PDC_R_IF: return "if";
	case PDC_R_IFELSE: return "if-else";
	case PDC_R_WHILE: return "while";
	case PDC_R_DOWHILE: return "do-while";
	case PDC_R_SWITCH: return "switch";
	case PDC_R_GOTO: return "goto";
	}
	return "?";
}

static void dump_region(PdcRegion *r, int indent, RStrBuf *sb) {
	r_strbuf_appendf (sb, "%*s%s 0x%08" PFMT64x "\n",
		indent * 2, "", region_kind (r->type), r->addr);
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		dump_region (*it, indent + 1, sb);
	}
}

char *pdc_ast_dump(RCore *core, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (core && fcn, NULL);
	RGraphNode *entry = NULL;
	RGraph *g = r_anal_function_get_graph (fcn, &entry, fcn->addr);
	if (!g || !entry) {
		r_graph_free (g);
		return NULL;
	}
	PdcCtx ctx = {
		.core = core,
		.anal = core->anal,
		.fcn = fcn,
		.idom = ht_uu_new0 (),
		.ipdom = ht_uu_new0 (),
		.headers = ht_uu_new0 (),
		.emitted = ht_uu_new0 (),
		.cap = 4 * r_list_length (fcn->bbs) + 64
	};

	RGraph *dt = r_graph_dom_tree (g, entry);
	if (dt) {
		collect_idom (ctx.idom, dt);
	}
	BackEdgeCtx bc = { &ctx };
	RGraphVisitor vis = { .back_edge = back_edge_cb, .data = &bc };
	r_graph_dfs_node (g, entry, &vis);

	// add a virtual sink (addr UT64_MAX reads as "past function exit") so
	// post-dominance is well-defined on multi-exit functions
	RAnalBlock sink_bb = { .addr = UT64_MAX, .jump = UT64_MAX, .fail = UT64_MAX };
	RGraphNode *sink = r_graph_add_node (g, &sink_bb);
	if (sink) {
		RListIter *it;
		RGraphNode *cn;
		r_list_foreach (g->nodes, it, cn) {
			if (cn == sink) {
				continue;
			}
			RAnalBlock *bb = (RAnalBlock *)cn->data;
			if (bb && block_is_exit (bb)) {
				r_graph_add_edge (g, cn, sink);
			}
		}
		RGraph *pdt = r_graph_pdom_tree (g, sink);
		if (pdt) {
			collect_idom (ctx.ipdom, pdt);
			r_graph_free (pdt);
		}
	}

	PdcRegion *root = region_seq (&ctx, fcn->addr, UT64_MAX);
	RStrBuf *sb = r_strbuf_new ("");
	if (root) {
		dump_region (root, 0, sb);
		region_free (root);
	}

	r_graph_free (dt);
	r_graph_free (g);
	ht_uu_free (ctx.idom);
	ht_uu_free (ctx.ipdom);
	ht_uu_free (ctx.headers);
	ht_uu_free (ctx.emitted);
	return r_strbuf_drain (sb);
}
