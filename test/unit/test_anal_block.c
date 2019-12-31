#include <r_anal.h>
#include "minunit.h"

static bool check_invariants(RAnal *anal) {
	RBIter iter;
	RAnalBlock *block;
	ut64 last_start = UT64_MAX;
	ut64 last_end = 0;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		if (last_start != UT64_MAX) {
			mu_assert ("corrupted binary tree", block->addr >= last_start);
			mu_assert_neq (block->addr, last_start, "double blocks");
		}
		last_start = block->addr;
		last_end = block->addr + block->size;

		mu_assert ("block->ref < 1, but it is still in the tree", block->ref >= 1);
		mu_assert ("block->ref < r_list_length (block->fcns)", block->ref >= r_list_length (block->fcns));

		RListIter *fcniter;
		RAnalFunction *fcn;
		r_list_foreach (block->fcns, fcniter, fcn) {
			RListIter *fcniter2;
			RAnalFunction *fcn2;
			for (fcniter2 = fcniter->n; fcniter2 && (fcn2 = fcniter2->data, 1); fcniter2 = fcniter2->n) {
				mu_assert_ptrneq (fcn, fcn2, "duplicate function in basic block");
			}
			mu_assert ("block references function, but function does not reference block", r_list_contains (fcn->bbs, block));
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

static bool check_leaks(RAnal *anal) {
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		if (block->ref != r_list_length (block->fcns))  {
			mu_assert ("leaked basic block", false);
		}
	}
	return true;
}

static size_t blocks_count(RAnal *anal) {
	size_t count = 0;
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach(anal->bb_tree, iter, block, RAnalBlock, _rb) {
		count++;
	}
	return count;
}


#define assert_invariants(anal) do { if (!check_invariants (anal)) { return false; } } while (0)
#define assert_leaks(anal) do { if (!check_leaks (anal)) { return false; } } while (0)

bool test_r_anal_block_create() {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	mu_assert_eq (blocks_count (anal), 0, "initial count");

	RAnalBlock *block = r_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert ("created block", block);
	mu_assert_eq (block->addr, 0x1337, "created addr");
	mu_assert_eq (block->size, 42, "created size");
	mu_assert_eq (block->ref, 1, "created initial ref");
	mu_assert_eq (blocks_count (anal), 1, "count after create");

	RAnalBlock *block2 = r_anal_create_block (anal, 0x133f, 100);
	assert_invariants (anal);
	mu_assert ("created block (overlap)", block2);
	mu_assert_eq (block2->addr, 0x133f, "created addr");
	mu_assert_eq (block2->size, 100, "created size");
	mu_assert_eq (block2->ref, 1, "created initial ref");
	mu_assert_eq (blocks_count (anal), 2, "count after create");

	RAnalBlock *block3 = r_anal_create_block (anal, 0x1337, 5);
	assert_invariants (anal);
	mu_assert ("no double create on same start", !block3);
	mu_assert_eq (blocks_count (anal), 2, "count after failed create");

	r_anal_block_unref (block);
	r_anal_block_unref (block2);

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_contains() {
	RAnalBlock dummy = { 0 };
	dummy.addr = 0x1337;
	dummy.size = 42;
	mu_assert ("contains before", !r_anal_block_contains (&dummy, 100));
	mu_assert ("contains start", r_anal_block_contains (&dummy, 0x1337));
	mu_assert ("contains inside", r_anal_block_contains (&dummy, 0x1339));
	mu_assert ("contains last", r_anal_block_contains (&dummy, 0x1337 + 42 - 1));
	mu_assert ("contains after", !r_anal_block_contains (&dummy, 0x1337 + 42));
	mu_end;
}

bool test_r_anal_block_split() {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	// TODO: check block in fcn!

	RAnalBlock *block = r_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 1, "count after create");

	RAnalBlock *second = r_anal_block_split (block, 0x1337);
	assert_invariants (anal);
	mu_assert_ptreq (second, block, "nop split on first addr");
	mu_assert_eq (blocks_count (anal), 1, "count after nop split");
	mu_assert_eq (block->ref, 2, "ref after nop split");
	r_anal_block_unref (block);

	second = r_anal_block_split (block, 0x1339);
	assert_invariants (anal);
	mu_assert_ptrneq (second, block, "non-nop split");
	mu_assert_eq (blocks_count (anal), 2, "count after non-nop split");

	mu_assert_eq (block->addr, 0x1337, "first addr after split");
	mu_assert_eq (block->size, 2, "first size after split");
	mu_assert_eq (second->addr, 0x1339, "first addr after split");
	mu_assert_eq (second->size, 40, "first size after split");

	// TODO: test jump/fail, instructions

	r_anal_block_unref (block);
	r_anal_block_unref (second);

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_resize_atomic(void) {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	// TODO

	assert_invariants (anal);
	r_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_block_create);
	mu_run_test (test_r_anal_block_contains);
	mu_run_test (test_r_anal_block_split);
	mu_run_test (test_r_anal_block_resize_atomic);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
