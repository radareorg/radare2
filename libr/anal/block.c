/* radare - LGPL - Copyright 2019 - pancake */

#include <r_anal.h>
#include <r_util/pj.h>

#define NEWBBAPI 1

#if NEWBBAPI
#define BBAPI_PRELUDE(x)
#else
#define BBAPI_PRELUDE(x) return x
#endif

static int __bb_addr_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_addr = *(ut64 *)incoming;
	const RAnalBlock *in_tree_block = container_of (in_tree, const RAnalBlock, rb);
	if (incoming_addr < in_tree_block->addr) {
		return -1;
	}
	if (incoming_addr > in_tree_block->addr) {
		return 1;
	}
	return 0;
}

#define D if (anal && anal->verbose)

R_API void r_anal_block_ref(RAnalBlock *bb) {
	bb->ref++;
}

R_API RAnalBlock *r_anal_block_split(RAnalBlock *bb, ut64 addr) {
	eprintf ("TODO: blockk.split not yet implemented\n");
	// R_API int r_anal_fcn_split_bb (RAnal *anal, RAnalFunction *fcn, RAnalBlock *bbi, ut64 addr) {
	return NULL;
}

R_API RAnalBlock *r_anal_block_new(RAnal *a, ut64 addr, ut64 size) {
	RAnalBlock *b = r_anal_bb_new ();
	if (!b) {
		return NULL;
	}
	b->addr = addr;
	b->size = size;
	b->anal = a;
	return b;
}

static void __block_free(RAnalBlock *bb) {
	r_anal_bb_free (bb);
}

void __block_free_rb(RBNode *node, void *user) {
	RAnalBlock *block = container_of (node, RAnalBlock, rb);
	__block_free (block);
}

R_API RAnalBlock *r_anal_get_block_at(RAnal *anal, ut64 addr) {
	// TODO: this might be a bit faster using a ht
	RBNode *node = r_rbtree_find (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	if (!node) {
		return NULL;
	}
	return container_of (node, RAnalBlock, rb);
}

R_API RAnalBlock *r_anal_get_block_in(RAnal *anal, ut64 addr) {
	BBAPI_PRELUDE(x)
	RBNode *node = r_rbtree_lower_bound (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	if (!node) {
		return NULL;
	}
	RAnalBlock *block = container_of (node, RAnalBlock, rb);
	if (addr - block->addr < block->size) {
		return block;
	}
	return NULL;
}

R_API RList *r_anal_get_blocks_intersect(RAnal *anal, ut64 addr, ut64 size) {
	BBAPI_PRELUDE (x)
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	// TODO: should we ref every returned block and use unref as free in the returned list?
	RBIter it = r_rbtree_lower_bound_forward (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	while (r_rbtree_iter_has (&it)) {
		RAnalBlock *block = r_rbtree_iter_get (&it, RAnalBlock, rb);
		if (block->addr >= addr + size) {
			break;
		}
		if (block->addr + size > addr) {
			r_list_push (ret, block);
		}
		r_rbtree_iter_next (&it);
	}
	return ret;
}

R_API bool r_anal_add_block(RAnal *anal, RAnalBlock *bb) {
	BBAPI_PRELUDE (NULL);
	r_return_val_if_fail (anal && bb, false);
	RList *intersecting = r_anal_get_blocks_intersect (anal, bb->addr, bb->size);
	if (intersecting && intersecting->length) {
D eprintf ("TODO SPLIT\n");
		r_list_free (intersecting);
		return false;
	}
	r_list_free (intersecting);
	bb->anal = anal;
	r_anal_block_ref (bb);
	r_rbtree_insert (&anal->bb_tree, &bb->addr, &bb->rb, __bb_addr_cmp, NULL);
	return true;
}

R_API void r_anal_del_block(RAnal *anal, RAnalBlock *bb) {
	r_return_if_fail (anal && bb);
D eprintf ("del block (%d) %llx\n", bb->ref, bb->addr);
	BBAPI_PRELUDE (NULL);
	r_anal_block_ref (bb);
	r_list_free (bb->fcns);
	r_anal_block_unref (bb);
}

R_API void r_anal_block_unref(RAnalBlock *bb) {
	RAnal *anal = bb->anal;
	bb->ref--;
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	D eprintf("unref bb %d\n", bb->ref);
	r_list_foreach_safe (bb->fcns, iter, iter2, fcn) {
		D eprintf("miss unref\n");
		r_list_delete (bb->fcns, iter);
		//r_anal_function_unref (fcn);
	}
	D eprintf("unref2 bb %d\n", bb->ref);
	if (bb->ref < 1) {
		r_anal_del_block (bb->anal, bb);
		//r_anal_block_free (bb);
	}
}

typedef bool (*RAnalBlockCb)(RAnalBlock *block, void *user);
typedef bool (*RAnalAddrCb)(ut64 addr, void *user);

R_API bool r_anal_block_successor_addrs_foreach(RAnalBlock *block, RAnalAddrCb cb, void *user) {
#define CB_ADDR(addr) do { \
		if (addr == UT64_MAX) { \
			break; \
		} \
		if (!cb (addr, user)) { \
			return false; \
		} \
	} while(0);

	CB_ADDR (block->jump);
	CB_ADDR (block->fail);
	if (block->switch_op && block->switch_op->cases) {
		RListIter *iter;
		RAnalCaseOp *caseop;
		r_list_foreach (block->switch_op->cases, iter, caseop) {
			CB_ADDR (caseop->jump);
		}
	}
	// TODO: please review if there can be any other successors of a block

	return true;
#undef CB_ADDR
}

typedef struct r_anal_block_recurse_context_t {
	RAnal *anal;
	RPVector/*<RAnalBlock>*/ to_visit;
	HtUP *visited;
} RAnalBlockRecurseContext;

static bool block_recurse_successor_cb(ut64 addr, void *user) {
	RAnalBlockRecurseContext *ctx = user;
	if (ht_up_find_kv (ctx->visited, addr, NULL)) {
		// already visited
		return true;
	}
	ht_up_insert (ctx->visited, addr, NULL);
	RAnalBlock *block = r_anal_get_block_at (ctx->anal, addr);
	if (!block) {
		return true;
	}
	r_pvector_push (&ctx->to_visit, block);
	return true;
}

R_API bool r_anal_block_recurse(RAnalBlock *block, RAnalBlockCb cb, void *user) {
	bool breaked = false;
	RAnalBlockRecurseContext ctx;
	ctx.anal = block->anal;
	r_pvector_init (&ctx.to_visit, NULL);
	ctx.visited = ht_up_new0 ();
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert (ctx.visited, block->addr, NULL);
	r_pvector_push (&ctx.to_visit, block);

	while (!r_pvector_empty (&ctx.to_visit)) {
		RAnalBlock *cur = r_pvector_pop (&ctx.to_visit);
		breaked = !cb (cur, user);
		if (breaked) {
			break;
		}
		r_anal_block_successor_addrs_foreach (cur, block_recurse_successor_cb, &ctx);
	}

beach:
	ht_up_free (ctx.visited);
	r_pvector_clear (&ctx.to_visit);
	return !breaked;
}

static bool recurse_list_cb(RAnalBlock *block, void *user) {
	RList *list = user;
	r_anal_block_ref (block);
	r_list_push (list, block);
	return true;
}

R_API RList *r_anal_block_recurse_list(RAnalBlock *block) {
	RList *ret = r_list_newf ((RListFree)r_anal_block_unref);
	if (!ret) {
		return NULL;
	}
	r_anal_block_recurse (block, recurse_list_cb, ret);
	return ret;
}
