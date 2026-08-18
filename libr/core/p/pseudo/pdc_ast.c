/* radare - LGPL - Copyright 2026 - pancake, phix33 */

// Region-AST structuring pass for the native pdc decompiler.
// Builds an if/else/loop/switch region tree over the function CFG using the
// dominator/post-dominator trees and DFS back edges. The `pdct` command dumps
// it; the structured pdc renderer (pdc.structured) consumes the tree.

#include <r_core.h>
#include "pdc_ast.h"

typedef struct {
	RAnal *anal;
	HtUU *idom;	// block addr => immediate dominator addr (entry => UT64_MAX)
	HtUU *ipdom;	// block addr => immediate post-dominator addr (UT64_MAX => exit)
	HtUP *loops;	// natural-loop header addr => HtUU* member set
	HtUU *cur_loop;	// members of the innermost loop being walked (NULL outside one)
	HtUU *emitted;	// block addr => 1 (each block heads a region at most once)
	int build_calls;
	int cap;
} PdcCtx;

static PdcRegion *region_new(PdcRegionType type, ut64 addr) {
	PdcRegion *r = R_NEW0 (PdcRegion);
	r->type = type;
	r->addr = addr;
	r->exit = UT64_MAX;
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

static void region_add_child(PdcRegion *parent, PdcRegion *child, PdcRole role) {
	if (child) {
		child->role = role;
		RVecPdcRegionPtr_push_back (&parent->children, &child);
	}
}

// the conditional headed by addr, or NULL when neither arm yields a region
static PdcRegion *region_cond(ut64 addr, PdcRegion *then_r, PdcRegion *else_r) {
	if (then_r && else_r) {
		PdcRegion *r = region_new (PDC_R_IFELSE, addr);
		region_add_child (r, then_r, PDC_ROLE_JUMP);
		region_add_child (r, else_r, PDC_ROLE_FAIL);
		return r;
	}
	if (!then_r && !else_r) {
		return NULL;
	}
	PdcRegion *r = region_new (PDC_R_IF, addr);
	region_add_child (r, then_r? then_r: else_r, then_r? PDC_ROLE_JUMP: PDC_ROLE_FAIL);
	return r;
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

// grow the natural loop of a dominating header: header plus every node that
// reaches the latch without passing through the header (needs idom filled)
static void back_edge_cb(const RGraphEdge *e, RGraphVisitor *vis) {
	PdcCtx *ctx = vis->data;
	RAnalBlock *hb = e->to? e->to->data: NULL;
	RAnalBlock *tb = e->from? e->from->data: NULL;
	if (!hb || !tb || !dominates (ctx, hb->addr, tb->addr)) {
		return;
	}
	HtUU *set = ht_up_find (ctx->loops, hb->addr, NULL);
	if (!set) {
		set = ht_uu_new0 ();
		ht_uu_update (set, hb->addr, 1);
		ht_up_update (ctx->loops, hb->addr, set);
	}
	if (htuu_get (set, tb->addr, 0)) {
		return;
	}
	ht_uu_update (set, tb->addr, 1);
	RList *wl = r_list_new ();
	r_list_push (wl, e->from);
	RGraphNode *n;
	while ((n = r_list_pop (wl))) {
		RGraphNode **pit;
		R_VEC_FOREACH (&n->in_nodes, pit) {
			RAnalBlock *pb = (*pit)->data;
			if (pb && !htuu_get (set, pb->addr, 0)) {
				ht_uu_update (set, pb->addr, 1);
				r_list_push (wl, *pit);
			}
		}
	}
	r_list_free (wl);
}

static bool free_loop_set_cb(void *user, const ut64 k, const void *v) {
	ht_uu_free ((HtUU *)v);
	return true;
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
static PdcRegion *build_switch(PdcCtx *ctx, RAnalBlock *bb, ut64 *next);

// first post-dominator of h outside the loop: where control merges after it
static ut64 loop_exit_addr(PdcCtx *ctx, HtUU *set, ut64 h) {
	ut64 x = htuu_get (ctx->ipdom, h, UT64_MAX);
	int guard = ctx->cap;
	while (x != UT64_MAX && htuu_get (set, x, 0) && guard-- > 0) {
		x = htuu_get (ctx->ipdom, x, UT64_MAX);
	}
	return x;
}

static PdcRegion *build_loop(PdcCtx *ctx, RAnalBlock *bb, HtUU *set, ut64 *next) {
	const ut64 h = bb->addr;
	const ut64 j = bb->jump;
	const ut64 f = bb->fail;
	const bool j_in = j != UT64_MAX && htuu_get (set, j, 0);
	const bool f_in = f != UT64_MAX && htuu_get (set, f, 0);
	ut64 body_start = UT64_MAX;
	ut64 exit = UT64_MAX;
	PdcRegionType lt = PDC_R_DOWHILE;
	// a dispatcher header loops over its own jump table, not a j/f test
	const bool sw_head = bb->switch_op && !r_list_empty (bb->switch_op->cases);
	if (!sw_head && j != UT64_MAX && f != UT64_MAX && j_in != f_in) {
		body_start = j_in? j: f;
		exit = j_in? f: j;
		if (body_start != h) {
			lt = PDC_R_WHILE;
		}
	} else {
		// header does not test the exit: one-way, or both successors stay in
		body_start = j_in? j: (f_in? f: UT64_MAX);
		exit = loop_exit_addr (ctx, set, h);
	}
	PdcRegion *loop = region_new (lt, h);
	loop->exit = exit;
	HtUU *prev = ctx->cur_loop;
	ctx->cur_loop = set;
	if (sw_head) {
		ut64 swnext = UT64_MAX;
		region_add_child (loop, build_switch (ctx, bb, &swnext), PDC_ROLE_HEAD);
	} else if (j_in && f_in) {
		// both edges stay inside, so the header's own conditional is the body
		PdcRegion *then_r = region_seq (ctx, j, h);	// order is load-bearing
		PdcRegion *else_r = region_seq (ctx, f, h);
		region_add_child (loop, region_cond (h, then_r, else_r), PDC_ROLE_HEAD);
	} else if (body_start != UT64_MAX && body_start != h) {
		region_add_child (loop, region_seq (ctx, body_start, h),
			(body_start == j)? PDC_ROLE_JUMP: PDC_ROLE_FAIL);
	}
	ctx->cur_loop = prev;
	*next = exit;
	return loop;
}

static PdcRegion *build_switch(PdcCtx *ctx, RAnalBlock *bb, ut64 *next) {
	const ut64 join = htuu_get (ctx->ipdom, bb->addr, UT64_MAX);
	PdcRegion *sw = region_new (PDC_R_SWITCH, bb->addr);
	sw->exit = join;
	HtUU *seen = ht_uu_new0 ();
	RListIter *it;
	RAnalCaseOp *co;
	r_list_foreach (bb->switch_op->cases, it, co) {
		if (co->jump == UT64_MAX || htuu_get (seen, co->jump, 0)) {
			continue;
		}
		ht_uu_update (seen, co->jump, 1);
		region_add_child (sw, region_seq (ctx, co->jump, join), PDC_ROLE_CASE);
	}
	const ut64 defv = bb->switch_op->def_val;
	if (valid_addr (defv) && !htuu_get (seen, defv, 0)) {
		region_add_child (sw, region_seq (ctx, defv, join), PDC_ROLE_CASE);
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

	HtUU *loop_set = ht_up_find (ctx->loops, cur, NULL);
	if (loop_set) {
		return build_loop (ctx, bb, loop_set, next);
	}
	if (bb->switch_op && !r_list_empty (bb->switch_op->cases)) {
		return build_switch (ctx, bb, next);
	}
	if (bb->jump != UT64_MAX && bb->fail != UT64_MAX) {
		const ut64 join = htuu_get (ctx->ipdom, cur, UT64_MAX);
		PdcRegion *then_r = (bb->jump == join)? NULL: region_seq (ctx, bb->jump, join);
		PdcRegion *else_r = (bb->fail == join)? NULL: region_seq (ctx, bb->fail, join);
		*next = join;
		PdcRegion *r = region_cond (cur, then_r, else_r);
		return r? r: region_new (PDC_R_BB, cur);
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
		// leaving the loop or hitting an owned block ends the run with a jump
		const bool left = ctx->cur_loop && !htuu_get (ctx->cur_loop, cur, 0);
		if (left || htuu_get (ctx->emitted, cur, 0)) {
			region_add_child (seq, region_new (PDC_R_GOTO, cur), PDC_ROLE_SEQ);
			break;
		}
		ut64 next = UT64_MAX;
		PdcRegion *r = build_region (ctx, cur, stop, &next);
		if (!r) {
			break;
		}
		region_add_child (seq, r, PDC_ROLE_SEQ);
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
	case PDC_R_BREAK: return "break";
	case PDC_R_CONTINUE: return "continue";
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

typedef struct pdc_scope_t {
	const struct pdc_scope_t *up;
	ut64 brk;	// where break leaves this scope
	ut64 cont;	// where continue restarts it, UT64_MAX for a switch
} PdcScope;

// break binds to the innermost loop or switch and continue to the innermost
// loop, which the CFG walk cannot tell apart
static void classify_transfers(PdcRegion *r, const PdcScope *scope) {
	if (r->type == PDC_R_GOTO && scope) {
		const PdcScope *s = scope;
		while (s && s->cont == UT64_MAX) {	// continue skips switch scopes
			s = s->up;
		}
		if (s && r->addr == s->cont) {
			r->type = PDC_R_CONTINUE;
		} else if (r->addr == scope->brk) {
			r->type = PDC_R_BREAK;
		}
	}
	PdcScope inner = { scope, r->exit, r->addr };
	const PdcScope *sub = scope;
	if (r->type == PDC_R_WHILE || r->type == PDC_R_DOWHILE) {
		sub = &inner;
	} else if (r->type == PDC_R_SWITCH) {
		inner.cont = UT64_MAX;
		sub = &inner;
	}
	PdcRegion **it;
	R_VEC_FOREACH (&r->children, it) {
		classify_transfers (*it, sub);
	}
}

void pdc_plan_free(PdcPlan *plan) {
	if (plan) {
		region_free (plan->root);
		free (plan);
	}
}

// a two-way block left to the orphan pass would lose one of its successors
static bool blocks_are_owned(RAnalFunction *fcn, HtUU *emitted) {
	RListIter *it;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, it, bb) {
		if (bb->jump != UT64_MAX && bb->fail != UT64_MAX
				&& !htuu_get (emitted, bb->addr, 0)) {
			return false;
		}
	}
	return true;
}

PdcPlan *pdc_plan_build(RCore *core, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (core && fcn, NULL);
	RGraphNode *entry = NULL;
	RGraph *g = r_anal_function_get_graph (fcn, &entry, fcn->addr);
	if (!g || !entry) {
		r_graph_free (g);
		return NULL;
	}
	PdcCtx ctx = {
		.anal = core->anal,
		.idom = ht_uu_new0 (),
		.ipdom = ht_uu_new0 (),
		.loops = ht_up_new0 (),
		.emitted = ht_uu_new0 (),
		.cap = 4 * r_list_length (fcn->bbs) + 64
	};

	RGraph *dt = r_graph_dom_tree (g, entry);
	if (dt) {
		collect_idom (ctx.idom, dt);
	}
	RGraphVisitor vis = { .back_edge = back_edge_cb, .data = &ctx };
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
	// the orphan renderer drops a successor, so give unreached blocks a region
	if (root) {
		RListIter *bit;
		RAnalBlock *b;
		PdcRegion *extra = NULL;
		r_list_foreach (fcn->bbs, bit, b) {
			if (htuu_get (ctx.emitted, b->addr, 0)) {
				continue;
			}
			PdcRegion *r = region_seq (&ctx, b->addr, UT64_MAX);
			if (!r) {
				continue;
			}
			if (!extra) {
				extra = region_new (PDC_R_SEQ, root->addr);
				region_add_child (extra, root, PDC_ROLE_SEQ);
				root = extra;
			}
			region_add_child (extra, r, PDC_ROLE_SEQ);
		}
	}

	r_graph_free (dt);
	r_graph_free (g);
	ht_uu_free (ctx.idom);
	ht_uu_free (ctx.ipdom);
	ht_up_foreach (ctx.loops, free_loop_set_cb, NULL);
	ht_up_free (ctx.loops);
	if (root) {
		classify_transfers (root, NULL);
	}
	PdcPlan *plan = R_NEW0 (PdcPlan);
	plan->root = root;
	plan->complete = blocks_are_owned (fcn, ctx.emitted);
	ht_uu_free (ctx.emitted);
	return plan;
}

char *pdc_ast_dump(RCore *core, RAnalFunction *fcn) {
	PdcPlan *plan = pdc_plan_build (core, fcn);
	RStrBuf *sb = r_strbuf_new ("");
	if (plan && plan->root) {
		dump_region (plan->root, 0, sb);
	}
	pdc_plan_free (plan);
	return r_strbuf_drain (sb);
}
