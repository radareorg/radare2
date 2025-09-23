/* radare - LGPL - pancake - Copyright 2025 */

#include <r_anal.h>
#include <r_core.h>
#include <r_vec.h>

R_VEC_TYPE(RVecAnalRef, RAnalRef);

typedef struct {
	RAnal *anal;
	RAnalBlock *cur_parent;
	ut64 dstbb_addr;
	RPVector/*<RAnalBlock>*/ *next_visit; // blocks for next BFS level
	HtUP/*<RAnalBlock>*/ *visited; // maps bb addr -> previous block (or NULL for entry)
} PathCtx;

static ut64 bb_addr_for (RAnal *a, ut64 n) {
	RListIter *iter;
	RAnalBlock *bb;
	RList *blocks = r_anal_get_blocks_in (a, n);
	r_list_foreach (blocks, iter, bb) {
		return bb->addr;
	}
	return n;
}

static bool succ_add_addr_cb (ut64 addr, void *user) {
	PathCtx *ctx = (PathCtx *)user;
	if (addr == UT64_MAX) {
		return true;
	}
	if (ht_up_find_kv (ctx->visited, addr, NULL)) {
		return true;
	}
	ht_up_insert (ctx->visited, addr, ctx->cur_parent);
	RAnalBlock *nb = r_anal_get_block_at (ctx->anal, addr);
	if (nb) {
		r_pvector_push (ctx->next_visit, nb);
	}
	return addr != ctx->dstbb_addr;
}

static bool succ_add_calls (RAnalBlock *block, void *user) {
	PathCtx *ctx = (PathCtx *)user;
	RAnalFunction *f = r_anal_get_fcn_in (ctx->anal, block->addr, 0);
	if (!f) {
		return true;
	}
	RVecAnalRef *refs = r_anal_function_get_refs (f);
	if (!refs) {
		return true;
	}
	RAnalRef *refi;
	R_VEC_FOREACH (refs, refi) {
		int rt = R_ANAL_REF_TYPE_MASK (refi->type);
		if (rt == R_ANAL_REF_TYPE_CALL) {
			if (r_anal_block_contains (block, refi->at)) {
				ut64 addr = refi->addr;
				if (!ht_up_find_kv (ctx->visited, addr, NULL)) {
					ht_up_insert (ctx->visited, addr, block);
					RAnalBlock *nb = r_anal_get_block_at (ctx->anal, addr);
					if (nb) {
						r_pvector_push (ctx->next_visit, nb);
					}
					if (addr == ctx->dstbb_addr) {
						RVecAnalRef_free (refs);
						return false;
					}
				}
			}
		}
	}
	RVecAnalRef_free (refs);
	return true;
}

static RList /*<RAnalBlock*>*/ * shortest_path_blocks (RAnal *anal, ut64 src, ut64 dst) {
	RAnalBlock *start = r_anal_get_block_at (anal, src);
	if (!start) {
		return NULL;
	}
	ut64 dstbb = bb_addr_for (anal, dst);

	RList *ret = NULL;
	PathCtx ctx;
	ctx.anal = anal;
	ctx.dstbb_addr = dstbb;

	RPVector visit_a; r_pvector_init (&visit_a, NULL);
	RPVector visit_b; r_pvector_init (&visit_b, NULL);
	ctx.next_visit = &visit_a;
	RPVector *cur_visit = &visit_b;

	ctx.visited = ht_up_new0 ();
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert (ctx.visited, start->addr, NULL);
	r_pvector_push (cur_visit, start);

	// BFS across BB edges, switch cases and calls
	while (!r_pvector_empty (cur_visit)) {
		void **it;
		r_pvector_foreach (cur_visit, it) {
			RAnalBlock *cur = (RAnalBlock *)*it;
			ctx.cur_parent = cur;
			// add jump/fail/switch successors
			if (!r_anal_block_successor_addrs_foreach (cur, succ_add_addr_cb, &ctx)) {
				goto done_bfs;
			}
			// add call destinations within this block
			if (!succ_add_calls (cur, &ctx)) {
				goto done_bfs;
			}
		}
		RPVector *tmp = cur_visit;
		cur_visit = ctx.next_visit;
		ctx.next_visit = tmp;
		r_pvector_clear (ctx.next_visit);
	}

done_bfs:;
	 bool found = false;
	 RAnalBlock *prev = ht_up_find (ctx.visited, dstbb, &found);
	 RAnalBlock *dst_block = r_anal_get_block_at (anal, dstbb);
	 if (found && dst_block) {
		 ret = r_list_newf ((RListFree)r_anal_block_unref);
		 r_anal_block_ref (dst_block);
		 r_list_prepend (ret, dst_block);
		 while (prev) {
			 r_anal_block_ref (prev);
			 r_list_prepend (ret, prev);
			 prev = ht_up_find (ctx.visited, prev->addr, NULL);
		 }
	 }

beach:
	 ht_up_free (ctx.visited);
	 r_pvector_clear (&visit_a);
	 r_pvector_clear (&visit_b);
	 return ret;
}

static bool pathcmd (RAnal *anal, const char *input) {
	RCore *core = (RCore *)anal->coreb.core;
	if (!r_str_startswith (input, "path")) {
		return false;
	}
	static RCoreHelpMessage help_msg_path = {
		"Usage:", "a:path", "[src] [dst]",
		"a:path", " [src] [dst]", "find shortest BB path (following xrefs and edges)",
		NULL
	};
	if (input[4] == '?' || !input[4]) {
		anal->coreb.help (core, help_msg_path);
		return true;
	}
	char *args = (char *)(input + 4);
	while (*args == ' ') { args++; }
	char *sp = strchr (args, ' ');
	if (!sp) {
		anal->coreb.help (core, help_msg_path);
		return true;
	}
	*sp = 0;
	ut64 src = r_num_math (core->num, args);
	ut64 dst = r_num_math (core->num, sp + 1);
	*sp = ' ';
	if (src == UT64_MAX || dst == UT64_MAX) {
		R_LOG_ERROR ("Invalid addresses");
		return true;
	}
	RList *path = shortest_path_blocks (anal, src, dst);
	if (!path) {
		R_LOG_ERROR ("No path or no basic block at source");
		return true;
	}
	RAnalBlock *bb;
	RListIter *it;
	r_list_foreach (path, it, bb) {
		r_cons_printf (core->cons, "0x%08"PFMT64x"\n", bb->addr);
	}
	r_list_free (path);
	return true;
}

RAnalPlugin r_anal_plugin_path = {
	.meta = {
		.name = "path",
		.author = "pancake",
		.desc = "Find shortest path between two addresses (bb+xrefs)",
		.license = "MIT",
	},
	.cmd = pathcmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_path,
	.version = R2_VERSION
};
#endif
