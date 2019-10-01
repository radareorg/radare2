/* radare - LGPL - Copyright 2019 - pancake */

#include <r_anal.h>

#define NEWBBAPI 1

#if NEWBBAPI
#define BBAPI_PRELUDE(x)
#else
#define BBAPI_PRELUDE(x) return x
#endif

#define D if (anal && anal->verbose)

R_API void r_anal_block_ref(RAnalBlock *bb) {
	bb->ref++;
}

R_API RAnalBlock *r_anal_block_split(RAnalBlock *bb, ut64 addr) {
	eprintf ("TODO: blockk.split not yet implemented\n");
	// R_API int r_anal_fcn_split_bb (RAnal *anal, RAnalFunction *fcn, RAnalBlock *bbi, ut64 addr) {
	return NULL;
}

R_API RAnalBlock *r_anal_block_new(RAnal *a, ut64 addr, int size) {
	RAnalBlock *b = r_anal_bb_new ();
	if (b) {
		b->addr = addr;
		b->size = size;
	}
	b->anal = a;
	return b;
}

R_API void r_anal_block_free(RAnalBlock *bb) {
	r_anal_bb_free (bb);
}

static ut64 __bbHashKey(ut64 addr) {
	return addr >> 4;
}

R_API RAnalBlock *r_anal_get_block(RAnal *anal, ut64 addr) {
	BBAPI_PRELUDE (NULL);
	// XXX use the rbtree api
	const ut64 k = __bbHashKey (addr);
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (list) {
		RAnalBlock *b;
		RListIter *iter;
		r_list_foreach (list, iter, b) {
			if (addr >= b->addr && addr < (b->addr + b->size)) {
				return b;
			}
		}
	}
	return NULL;
}

R_API bool r_anal_add_block(RAnal *anal, RAnalBlock *bb) {
	BBAPI_PRELUDE (NULL);
	r_return_val_if_fail (anal && bb, false);
	const ut64 k = __bbHashKey (bb->addr);
	RAnalBlock *b = r_anal_get_block (anal, bb->addr);
	if (b) {
D eprintf ("TODO SPLIT\n");
		return false;
	}
	bb->anal = anal;
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (!list) {
		list = r_list_newf ((RListFree)r_anal_block_unref);
		ht_up_insert (anal->ht_bbs, k, list);
	}
	r_anal_block_ref (bb);
	r_list_append (list, bb);
	return true;
}

R_API void r_anal_del_block(RAnal *anal, RAnalBlock *bb) {
	r_return_if_fail (anal && bb);
D eprintf ("del block (%d) %llx\n", bb->ref, bb->addr);
	BBAPI_PRELUDE (NULL);
	const ut64 k = __bbHashKey (bb->addr);
	r_anal_block_ref (bb);
	r_list_free (bb->fcns);
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (list) {
		RAnalBlock *b;
		RAnalFunction *f;
		RListIter *iter, *iter2;
		r_list_foreach_safe (list, iter, iter2, b) {
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
	}
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
