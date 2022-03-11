#ifndef INCLUDE_ANAL_ABI
#define INCLUDE_ANAL_ABI

#if R2_VERSION_MAJOR >= 5 && R2_VERSION_MINOR >= 7
#define R_ABI
#else
#define R_ABI static
#endif

R_ABI int r_anal_function_instrcount(RAnalFunction *fcn) {
	int count = 0;
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		count += bb->ninstr;
	}
	return count;
}

R_ABI bool r_anal_function_islineal(RAnalFunction *fcn) {
	if (r_anal_function_linear_size (fcn) != r_anal_function_realsize (fcn)) {
		return false;
	}
	RListIter *iter;
	RAnalBlock *bb;
	ut64 at = r_anal_function_min_addr (fcn);
	bool found;
	ut64 end = r_anal_function_max_addr (fcn);
	for (at = fcn->addr; at < end; at ++) {
		found = false;
		r_list_foreach (fcn->bbs, iter, bb) {
			if (r_anal_block_contains (bb, at)) {
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
		at = bb->addr + bb->size - 1;
	}
	return true;
}

#endif
