/* radare - LGPL - Copyright 2019 - pancake, thestr4ng3r */

#include <r_anal.h>

#include <assert.h>

#define unwrap(rbnode) container_of (rbnode, RAnalBlock, _rb)

static void __max_end(RBNode *node) {
	RAnalBlock *block = unwrap (node);
	block->_max_end = block->addr + block->size;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap (node->child[i])->_max_end;
			if (end > block->_max_end) {
				block->_max_end = end;
			}
		}
	}
}

static int __bb_addr_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_addr = *(ut64 *)incoming;
	const RAnalBlock *in_tree_block = container_of (in_tree, const RAnalBlock, _rb);
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

static RAnalBlock *block_new(RAnal *a, ut64 addr, ut64 size) {
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

static void block_free(RAnalBlock *block) {
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

void __block_free_rb(RBNode *node, void *user) {
	RAnalBlock *block = unwrap (node);
	block_free (block);
}

R_API RAnalBlock *r_anal_get_block_at(RAnal *anal, ut64 addr) {
	RBNode *node = r_rbtree_find (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	if (!node) {
		return NULL;
	}
	return unwrap (node);
}

// This is a special case of what r_interval_node_all_in() does
static bool all_in(RAnalBlock *node, ut64 addr, RAnalBlockCb cb, void *user) {
	while (node && addr < node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->_rb.child[0]);
	}
	if (!node) {
		return true;
	}
	if (addr >= node->_max_end) {
		return true;
	}
	if (addr < node->addr + node->size) {
		if (!cb (node, user)) {
			return false;
		}
	}
	// This can be done more efficiently by building the stack manually
	if (!all_in (unwrap (node->_rb.child[0]), addr, cb, user)) {
		return false;
	}
	if (!all_in (unwrap (node->_rb.child[1]), addr, cb, user)) {
		return false;
	}
	return true;
}

R_API bool r_anal_blocks_foreach_in(RAnal *anal, ut64 addr, RAnalBlockCb cb, void *user) {
	return all_in (anal->bb_tree ? unwrap (anal->bb_tree) : NULL, addr, cb, user);
}

static bool block_list_cb(RAnalBlock *block, void *user) {
	RList *list = user;
	r_anal_block_ref (block);
	r_list_push (list, block);
	return true;
}

R_API RList *r_anal_get_blocks_in(RAnal *anal, ut64 addr) {
	RList *list = r_list_newf ((RListFree)r_anal_block_unref);
	if (!list) {
		return NULL;
	}
	r_anal_blocks_foreach_in (anal, addr, block_list_cb, list);
	return list;
}

static void all_intersect(RAnalBlock *node, ut64 addr, ut64 size, RAnalBlockCb cb, void *user) {
	ut64 end = addr + size;
	while (node && end <= node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->_rb.child[0]);
	}
	if (!node) {
		return;
	}
	if (addr >= node->_max_end) {
		return;
	}
	if (addr < node->addr + node->size) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	all_intersect (unwrap (node->_rb.child[0]), addr, size, cb, user);
	all_intersect (unwrap (node->_rb.child[1]), addr, size, cb, user);
}

R_API void r_anal_blocks_foreach_intersect(RAnal *anal, ut64 addr, ut64 size, RAnalBlockCb cb, void *user) {
	all_intersect (anal->bb_tree ? unwrap (anal->bb_tree) : NULL, addr, size, cb, user);
}

R_API RList *r_anal_get_blocks_intersect(RAnal *anal, ut64 addr, ut64 size) {
	RList *list = r_list_newf ((RListFree)r_anal_block_unref);
	if (!list) {
		return NULL;
	}
	r_anal_blocks_foreach_intersect (anal, addr, size, block_list_cb, list);
	return list;
}

R_API RAnalBlock *r_anal_create_block(RAnal *anal, ut64 addr, ut64 size) {
	if (r_anal_get_block_at (anal, addr)) {
		return NULL;
	}
	RAnalBlock *block = block_new (anal, addr, size);
	if (!block) {
		return NULL;
	}
	r_rbtree_aug_insert (&anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return block;
}

R_API void r_anal_delete_block(RAnalBlock *bb) {
	r_anal_block_ref (bb);
	while (!r_list_empty (bb->fcns)) {
		r_anal_function_remove_block (r_list_first (bb->fcns), bb);
	}
	r_anal_block_unref (bb);
}

R_API void r_anal_block_set_size(RAnalBlock *block, ut64 size) {
	if (block->size == size) {
		return;
	}

	// Update the block's function's cached ranges
	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (block->fcns, iter, fcn) {
		if (fcn->meta._min != UT64_MAX && fcn->meta._max == block->addr + block->size) {
			fcn->meta._max = block->addr + size;
		}
	}

	// Do the actual resize
	block->size = size;
	r_rbtree_aug_update_sum (block->anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
}

R_API bool r_anal_block_relocate(RAnalBlock *block, ut64 addr, ut64 size) {
	if (block->addr == addr) {
		r_anal_block_set_size (block, size);
		return true;
	}
	if (r_anal_get_block_at (block->anal, addr)) {
		// Two blocks at the same addr is illegle you know...
		return false;
	}

	// Update the block's function's cached ranges
	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (block->fcns, iter, fcn) {
		if (fcn->meta._min != UT64_MAX) {
			if (addr + size > fcn->meta._max) {
				// we extend after the maximum, so we are the maximum afterwards.
				fcn->meta._max = addr + size;
			} else if (block->addr + block->size == fcn->meta._max && addr + size != block->addr + block->size) {
				// we were the maximum before and may not be it afterwards, not trivial to recalculate.
				fcn->meta._min = UT64_MAX;
				continue;
			}
			if (block->addr < fcn->meta._min) {
				// less than the minimum, we know that we are the minimum afterwards.
				fcn->meta._min = addr;
			} else if (block->addr == fcn->meta._min && addr != block->addr) {
				// we were the minimum before and may not be it afterwards, not trivial to recalculate.
				fcn->meta._min = UT64_MAX;
			}
		}
	}

	r_rbtree_aug_delete (&block->anal->bb_tree, &block->addr, __bb_addr_cmp, NULL, NULL, NULL, __max_end);
	block->addr = addr;
	block->size = size;
	r_rbtree_aug_insert (&block->anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return true;
}

R_API RAnalBlock *r_anal_block_split(RAnalBlock *bbi, ut64 addr) {
	RAnal *anal = bbi->anal;
	r_return_val_if_fail (bbi && addr >= bbi->addr && addr < bbi->addr + bbi->size && addr != UT64_MAX, 0);
	if (addr == bbi->addr) {
		r_anal_block_ref (bbi); // ref to be consistent with splitted return refcount
		return bbi;
	}

	if (r_anal_get_block_at (bbi->anal, addr)) {
		// can't have two bbs at the same addr
		return NULL;
	}

	// create the second block
	RAnalBlock *bb = block_new (anal, addr, bbi->addr + bbi->size - addr);
	if (!bb) {
		return NULL;
	}
	bb->jump = bbi->jump;
	bb->fail = bbi->fail;
	bb->conditional = bbi->conditional;
	bb->parent_stackptr = bbi->stackptr;

	// resize the first block
	r_anal_block_set_size (bbi, addr - bbi->addr);
	bbi->jump = addr;
	bbi->fail = UT64_MAX;
	bbi->conditional = false;

	// insert the second block into the tree
	r_rbtree_aug_insert (&anal->bb_tree, &bb->addr, &bb->_rb, __bb_addr_cmp, NULL, __max_end);

	// insert the second block into all functions of the first
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (bbi->fcns, iter, fcn) {
			r_anal_function_add_block (fcn, bb);
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
	if (a->addr + a->size != b->addr) {
		return false;
	}

	// check if function lists are identical
	if (r_list_length (a->fcns) != r_list_length (b->fcns)) {
		return false;
	}
	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (a->fcns, iter, fcn) {
		if (!r_list_contains (b->fcns, fcn)) {
			return false;
		}
	}

	// Keep a ref to b, but remove all references of b from its functions
	r_anal_block_ref (b);
	while (!r_list_empty (b->fcns)) {
		r_anal_function_remove_block (r_list_first (b->fcns), b);
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
	r_rbtree_aug_delete (&a->anal->bb_tree, &b->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);

	// invalidate ranges of a's functions
	r_list_foreach (a->fcns, iter, fcn) {
		fcn->meta._min = UT64_MAX;
	}

	return true;
}

R_API void r_anal_block_unref(RAnalBlock *bb) {
	assert (bb->ref > 0);
	bb->ref--;
	assert (bb->ref >= r_list_length (bb->fcns)); // all of the block's functions must hold a reference to it
	if (bb->ref < 1) {
		RAnal *anal = bb->anal;
		assert (!bb->fcns || r_list_empty (bb->fcns));
		r_rbtree_aug_delete (&anal->bb_tree, &bb->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);
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
