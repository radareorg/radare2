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

R_API void r_anal_get_blocks_intersect(RAnal *anal, ut64 addr, ut64 size, R_OUT RPVector *out) {
	BBAPI_PRELUDE(x)
	r_pvector_clear (out);
	RBIter it = r_rbtree_lower_bound_forward (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	while (r_rbtree_iter_has (&it)) {
		RAnalBlock *block = r_rbtree_iter_get (&it, RAnalBlock, rb);
		if (block->addr >= addr + size) {
			break;
		}
		if (block->addr + size > addr) {
			r_pvector_push (out, block);
		}
		r_rbtree_iter_next (&it);
	}
}

R_API bool r_anal_add_block(RAnal *anal, RAnalBlock *bb) {
	BBAPI_PRELUDE (NULL);
	r_return_val_if_fail (anal && bb, false);
	RPVector intersecting;
	r_pvector_init (&intersecting, NULL);
	r_anal_get_blocks_intersect (anal, bb->addr, bb->size, &intersecting);
	if (!r_pvector_empty (&intersecting)) {
D eprintf ("TODO SPLIT\n");
		r_pvector_clear (&intersecting);
		return false;
	}
	r_pvector_clear (&intersecting);
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
	/*
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (list) {
		RAnalBlock *b;
		RAnalFunction *f;
		RListIter *iter, *iter2;
		r_list_foreach_safe (list, iter, iter2, b) {
			// TODO: wtf, why R_BETWEEN?
			if (R_BETWEEN (b->addr, bb->addr, b->addr + b->size)) {
#if 0
				r_list_foreach (b->fcns, iter2, f) {
if (b != bb)
					r_anal_block_unref (b);
				}
#endif
D eprintf ("DELETE BLOCK\n");
				r_list_delete (list, iter);
			//	break;
			}
		}
	}*/
	r_list_free (bb->fcns);
	r_anal_block_unref (bb);
	// bbs.del(bb);
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
