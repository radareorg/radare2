
static int find_bb_cmp(RAnalBlock *const *a, const void *b) {
	return *a != b;
}

static bool block_check_invariants(RAnal *anal) {
	RBIter iter;
	RAnalBlock *block;
	ut64 last_start = UT64_MAX;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		if (last_start != UT64_MAX) {
			mu_assert ("corrupted binary tree", block->addr >= last_start);
			mu_assert_neq (block->addr, last_start, "double blocks");
		}
		last_start = block->addr;

		mu_assert ("block->refcount < 1, but it is still in the tree", r_ref_count (block) >= 1);
		mu_assert ("block->refcount < r_list_length (block->fcns)", r_ref_count (block) >= r_list_length (block->fcns));

		RListIter *fcniter;
		RAnalFunction *fcn;
		r_list_foreach (block->fcns, fcniter, fcn) {
			RListIter *fcniter2;
			RAnalFunction *fcn2;
			for (fcniter2 = fcniter->n; fcniter2 && (fcn2 = fcniter2->data, 1); fcniter2 = fcniter2->n) {
				mu_assert_ptrneq (fcn, fcn2, "duplicate function in basic block");
			}
			mu_assert ("block references function, but function does not reference block", RVecAnalBlockPtr_find (&fcn->bbs, block, find_bb_cmp));
		}
	}

	RListIter *fcniter;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, fcniter, fcn) {
		RAnalBlock **blockiter;
		ut64 min = UT64_MAX;
		ut64 max = UT64_MIN;
		ut64 realsz = 0;
		R_VEC_FOREACH (&fcn->bbs, blockiter) {
			block = *blockiter;
			if (fcn->bbs_sorted && blockiter != R_VEC_START_ITER (&fcn->bbs)) {
				mu_assert ("function blocks out of address order", blockiter[-1]->addr < block->addr);
			}
			RAnalBlock **blockiter2;
			RAnalBlock *block2;
			if (block->addr < min) {
				min = block->addr;
			}
			if (block->addr + block->size > max) {
				max = block->addr + block->size;
			}
			realsz += block->size;
			for (blockiter2 = blockiter + 1; blockiter2 != R_VEC_END_ITER (&fcn->bbs) && (block2 = *blockiter2, 1); blockiter2++) {
				mu_assert_ptrneq (block, block2, "duplicate basic block in function");
			}
			mu_assert ("function references block, but block does not reference function", r_list_contains (block->fcns, fcn));
		}

		if (fcn->meta._min != UT64_MAX) {
			mu_assert_eq (fcn->meta._min, min, "function min wrong");
			mu_assert_eq (fcn->meta._max, max, "function max wrong");
		}

		mu_assert_eq (r_anal_function_realsize (fcn), realsz, "realsize wrong");
	}
	return true;
}

static bool block_check_leaks(RAnal *anal) {
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		if (r_ref_count (block) != r_list_length (block->fcns))  {
			mu_assert ("leaked basic block", false);
		}
	}
	return true;
}
