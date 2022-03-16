#ifndef INCLUDE_ANAL_ABI
#define INCLUDE_ANAL_ABI

#if R2_VERSION_MAJOR >= 5 && R2_VERSION_MINOR >= 7
#define R_ABI R_API
#else
#define R_ABI R_UNUSED static
#endif

R_ABI int r_anal_function_instrcount(RAnalFunction *fcn) {
	int amount = 0;
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		amount += bb->ninstr;
	}
	return amount;
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

// pin.c

#define DB a->sdb_pins
R_ABI const char *r_anal_pin_get(RAnal *a, const char *name) {
	r_strf_buffer (128);
	char *ckey = r_strf ("cmd.%s", name);
	return sdb_const_get (DB, ckey, NULL);
}

R_ABI const char *r_anal_pin_at(RAnal *a, ut64 addr) {
	char buf[64];
	const char *key = sdb_itoa (addr, buf, 16);
	return sdb_const_get (DB, key, NULL);
}

R_ABI bool r_anal_pin_set(RAnal *a, const char *name, const char *cmd) {
	r_strf_buffer (128);
	char *ckey = r_strf ("cmd.%s", name);
	return sdb_add (DB, ckey, cmd, 0);
}
#undef DB

#endif
