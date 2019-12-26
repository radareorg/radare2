/* radare - LGPL - Copyright 2019 - pancake */

#include <r_anal.h>
#include <r_util/pj.h>

#include <assert.h>

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
	assert (bb->ref > 0); // 0-refd must already be freed.
	bb->ref++;
}


#define DFLT_NINSTR 3

// TODO: this should be private, new blocks should should be created from outside using only r_anal_create_block()
R_API RAnalBlock *r_anal_block_new(RAnal *a, ut64 addr, ut64 size) {
	RAnalBlock *block = R_NEW0 (RAnalBlock);
	if (!block) {
		return NULL;
	}
	block->addr = addr;
	block->size = size;
	block->anal = a;
	block->ref = 1;
	block->jump = UT64_MAX;
	block->fail = UT64_MAX;
	block->type = R_ANAL_BB_TYPE_NULL;
	block->op_pos = R_NEWS0 (ut16, DFLT_NINSTR);
	block->op_pos_size = DFLT_NINSTR;
	block->stackptr = 0;
	block->parent_stackptr = INT_MAX;
	block->cmpval = UT64_MAX;
	block->fcns = r_list_new ();
	return block;
}

// TODO: this should be private, from outside only unref must be used
R_API void r_anal_block_free(RAnalBlock *block) {
	if (!block) {
		return;
	}
	r_anal_cond_free (block->cond);
	free (block->fingerprint);
	r_anal_diff_free (block->diff);
	free (block->op_bytes);
	r_anal_switch_op_free (block->switch_op);
	r_list_free (block->fcns);
	free (block->label);
	free (block->op_pos);
	free (block->parent_reg_arena);
	free (block);
}

// TODO: this can be moved to unit tests later
R_API void r_anal_block_check_invariants(RAnal *anal) {
#define DEEPCHECKS 0
#if DEEPCHECKS
	RBIter iter;
	RAnalBlock *block;
	ut64 last_start = UT64_MAX;
	ut64 last_end = 0;
	RAnalBlock *last_block = NULL;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, rb) {
		if (block->addr < last_end) {
			eprintf ("FUCK: Overlapping block @ 0x%"PFMT64x" of size %"PFMT64u" with %"PFMT64u"\n", block->addr, block->size, last_block->size);
		}
		if (last_start != UT64_MAX && block->addr < last_start) {
			eprintf ("FUUUUUUCK: Binary tree is corrupted!!!!\n");
		}
		if (last_start != UT64_MAX && block->addr == last_start) {
			eprintf ("FUUUUUUUUUUCK: Double blocks!!!!!!\n");
		}
		last_start = block->addr;
		last_end = block->addr + block->size;
		last_block = block;

		if (block->ref < 1) {
			eprintf ("FUCK: block->ref < 1, but it is still in the tree\n");
		}
		if (block->ref < r_list_length (block->fcns)) {
			eprintf ("FUCK: block->ref < r_list_length (block->fcns)\n");
		}
		RListIter *fcniter;
		RAnalFunction *fcn;
		r_list_foreach (block->fcns, fcniter, fcn) {
			RListIter *fcniter2;
			RAnalFunction *fcn2;
			for (fcniter2 = fcniter->n; fcniter2 && (fcn2 = fcniter2->data, 1); fcniter2 = fcniter2->n) {
				if (fcn == fcn2) {
					eprintf ("FUCK: Duplicate function %s in basic block @ 0x%"PFMT64x"\n", fcn->name, block->addr);
					break;
				}
			}
			if (!r_list_contains (fcn->bbs, block)) {
				eprintf ("FUCK: Fcn %s is referenced by block @ 0x%"PFMT64x", but block is not referenced by function\n", fcn->name, block->addr);
			}
		}
	}

	RListIter *fcniter;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, fcniter, fcn) {
		RListIter *blockiter;
		ut64 min = UT64_MAX;
		ut64 max = UT64_MIN;
		ut64 realsz = 0;
		r_list_foreach (fcn->bbs, blockiter, block) {
			RListIter *blockiter2;
			RAnalBlock *block2;
			if (block->addr < min) {
				min = block->addr;
			}
			if (block->addr + block->size > max) {
				max = block->addr + block->size;
			}
			realsz += block->size;
			for (blockiter2 = blockiter->n; blockiter2 && (block2 = blockiter2->data, 1); blockiter2 = blockiter2->n) {
				if (block == block2) {
					eprintf("FUCK: Duplicate basic block @ 0x%"PFMT64x" in function %s\n", block->addr, fcn->name);
					break;
				}
			}
			if (!r_list_contains (block->fcns, fcn)) {
				eprintf("FUCK: block @ 0x%"PFMT64x" is referenced by Fcn %s, not the other way around\n", block->addr, fcn->name);
			}
		}

		if (fcn->meta._min != UT64_MAX && (fcn->meta._min != min || fcn->meta._max != max)) {
			eprintf("SHIP: min/max wrong!!!!!\n");
		}
		if (r_anal_fcn_realsize (fcn) != realsz) {
			eprintf("SHIP: realsize wrong!!!!!!\n");
		}
	}
#endif
}

void __block_free_rb(RBNode *node, void *user) {
	RAnalBlock *block = container_of (node, RAnalBlock, rb);
	r_anal_block_free (block);
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
	r_anal_block_check_invariants (anal);
	RBNode *node = r_rbtree_upper_bound (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
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
	RList *ret = r_list_newf ((RListFree)r_anal_block_unref);
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
			r_anal_block_ref (block);
			r_list_push (ret, block);
		}
		r_rbtree_iter_next (&it);
	}
	return ret;
}

// TODO: unit-test this HARD!!
R_API RList *r_anal_block_create(RAnal *anal, ut64 addr, ut64 size) {
	BBAPI_PRELUDE (NULL);
	r_return_val_if_fail (anal, NULL);

	RList *ret = r_list_newf ((RListFree)r_anal_block_unref);
	if (!ret) {
		return NULL;
	}

	// get all intersecting blocks
	RList *intersecting = r_anal_get_blocks_intersect (anal, addr, size);
	if (!r_list_empty (intersecting)) {
		// split the first at addr if necessary and ignore the first part
		RAnalBlock *first = r_list_first (intersecting);
		if (first->addr < addr) {
			r_list_pop_head (intersecting);
			RAnalBlock *newfirst = r_anal_block_split (first, addr);
			r_list_prepend (intersecting, newfirst);
			r_anal_block_unref (first);
		}
		// split the last at addr + size if necessary and ignore the second part
		RAnalBlock *last = r_list_last (intersecting);
		if (last->addr + size > addr + size) {
			RAnalBlock *tail = r_anal_block_split (last, addr + size);
			r_anal_block_unref (tail);
		}
	}

	// create blocks in the holes and fill the return list
	ut64 cur = addr;
	ut64 end = addr + size;
	while (cur < end) {
		RAnalBlock *newblock = NULL;
		RAnalBlock *insect = NULL;
		if (r_list_empty (intersecting)) {
			newblock = r_anal_block_new (anal, cur, end - cur);
			cur = end;
		} else {
			insect = r_list_pop_head (intersecting);
			if (insect->addr > cur) {
				newblock = r_anal_block_new (anal, cur, insect->addr - cur);
			}
			cur = insect->addr + insect->size;
		}
		if (newblock) {
			r_rbtree_insert (&anal->bb_tree, &newblock->addr, &newblock->rb, __bb_addr_cmp, NULL);
			r_list_push (ret, newblock);
		}
		if (insect) {
			r_list_push (ret, insect);
		}
		r_anal_block_check_invariants (anal);
	}
	r_list_free (intersecting);
	r_anal_block_check_invariants (anal);
	return ret;
}

R_API void r_anal_del_block(RAnal *anal, RAnalBlock *bb) {
	r_return_if_fail (anal && bb);
D eprintf ("del block (%d) %llx\n", bb->ref, bb->addr);
	BBAPI_PRELUDE (NULL);
	r_anal_block_ref (bb);
	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (bb->fcns, iter, fcn) {
		r_list_delete_data (fcn->bbs, bb);
	}
	r_list_free (bb->fcns);
	r_anal_block_unref (bb);
}

R_API bool r_anal_block_try_resize_atomic(RAnalBlock *bb, ut64 addr, ut64 size) {
	RAnal *anal = bb->anal;
	if (addr == bb->addr) {
		// easier if the address stays the same
		if (size > bb->size) {
			// find the next block
			ut64 searchaddr = addr + 1;
			RBNode *node = r_rbtree_lower_bound (anal->bb_tree, &searchaddr, __bb_addr_cmp, NULL);
			if (node && container_of (node, RAnalBlock, rb)->addr < addr + size) {
				// would overlap with the next block
				return false;
			}
		}
		r_anal_block_check_invariants (bb->anal);

		RAnalFunction *fcn;
		RListIter *iter;
		r_list_foreach (bb->fcns, iter, fcn) {
			if (fcn->meta._min != UT64_MAX && fcn->meta._max == bb->addr + bb->size) {
				fcn->meta._max = bb->addr + size;
			}
		}

		bb->size = size;
		r_anal_block_check_invariants (bb->anal);
		return true;
	}
	eprintf("r_anal_block_try_resize_atomic with different addr not implemented\n");
	return false;
}

R_API RAnalBlock *r_anal_block_split(RAnalBlock *bbi, ut64 addr) {
	RAnal *anal = bbi->anal;
	r_return_val_if_fail (bbi && addr >= bbi->addr && addr < bbi->addr + bbi->size && addr != UT64_MAX, 0);
	if (addr == bbi->addr) {
		return bbi;
	}

	// create the second block
	RAnalBlock *bb = r_anal_block_new (anal, addr, bbi->addr + bbi->size - addr);
	if (!bb) {
		return NULL;
	}
	bb->jump = bbi->jump;
	bb->fail = bbi->fail;
	bb->conditional = bbi->conditional;
	bb->parent_stackptr = bbi->stackptr;

	// resize the first block
	bool success = r_anal_block_try_resize_atomic (bbi, bbi->addr, addr - bbi->addr);
	r_return_val_if_fail (success, NULL);
	bbi->jump = addr;
	bbi->fail = UT64_MAX;
	bbi->conditional = false;

	// insert the second block into the tree
	r_rbtree_insert (&anal->bb_tree, &bb->addr, &bb->rb, __bb_addr_cmp, NULL);

	// insert the second block into all functions of the first
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (bbi->fcns, iter, fcn) {
		r_anal_function_block_add (fcn, bb);
	}

	// recalculate offset of instructions in both bb and bbi
	int i;
	i = 0;
	while (i < bbi->ninstr && r_anal_bb_offset_inst (bbi, i) < bbi->size) {
		i++;
	}
	int new_bbi_instr = i;
	if (bb->addr - bbi->addr == r_anal_bb_offset_inst (bbi, i)) {
		bb->ninstr = 0;
		while (i < bbi->ninstr) {
			ut16 off_op = r_anal_bb_offset_inst (bbi, i);
			if (off_op >= bbi->size + bb->size) {
				break;
			}
			r_anal_bb_set_offset (bb, bb->ninstr, off_op - bbi->size);
			bb->ninstr++;
			i++;
		}
	}
	bbi->ninstr = new_bbi_instr;
	return bb;
}

R_API bool r_anal_block_merge(RAnalBlock *a, RAnalBlock *b) {
	r_anal_block_check_invariants (a->anal);
	if (a->addr + a->size != b->addr) {
		return false;
	}

	// check if function lists are identical
	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (a->fcns, iter, fcn) {
		if (!r_list_contains (b->fcns, fcn)) {
			return false;
		}
	}
	r_list_foreach (b->fcns, iter, fcn) {
		if (!r_list_contains (a->fcns, fcn)) {
			return false;
		}
	}

	// Keep a ref to b, but remove all references of b from its functions
	r_anal_block_ref (b);
	while (!r_list_empty (b->fcns)) {
		r_anal_function_block_remove (r_list_first (b->fcns), b);
	}

	// merge ops from b into a
	size_t i;
	for (i = 0; i < b->ninstr; i++) {
		r_anal_bb_set_offset (a, a->ninstr++, a->size + r_anal_bb_offset_inst (b, i));
	}

	// merge everything else into a
	a->size += b->size;
	a->jump = b->jump;
	a->fail = b->fail;

	// kill b completely
	r_rbtree_delete (&a->anal->bb_tree, &b->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL);

	// invalidate ranges of a's functions
	r_list_foreach (a->fcns, iter, fcn) {
		fcn->meta._min = UT64_MAX;
	}

	r_anal_block_check_invariants (a->anal);
	return true;
}

R_API void r_anal_block_unref(RAnalBlock *bb) {
	assert (bb->ref > 0);
	r_anal_block_check_invariants (bb->anal);
	bb->ref--;
	assert (bb->ref >= r_list_length (bb->fcns));
	if (bb->ref < 1) {
		RAnal *anal = bb->anal;
		D eprintf("unref bb %d\n", bb->ref);
		assert (!bb->fcns || r_list_empty (bb->fcns)); // on
		D eprintf("unref2 bb %d\n", bb->ref);
		r_rbtree_delete (&anal->bb_tree, &bb->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL);
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
