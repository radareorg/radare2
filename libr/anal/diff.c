/* radare - LGPL - Copyright 2010-2025 - nibble, pancake */

#define R_LOG_ORIGIN "anal.diff"

#include <r_anal.h>
#include <r_core.h>

R_API RAnalDiff *r_anal_diff_new(void) {
	RAnalDiff *diff = R_NEW0 (RAnalDiff);
	if (diff) {
		diff->type = R_ANAL_DIFF_TYPE_NULL;
		diff->addr = UT64_MAX;
		diff->dist = 0;
		diff->name = NULL;
		diff->size = 0;
	}
	return diff;
}

R_API void r_anal_diff_free(RAnalDiff *diff) {
	if (diff) {
		free (diff->name);
		free (diff);
	}
}

R_API void r_anal_diff_setup(RAnal *anal, bool doops, double thbb, double thfcn) {
	R_RETURN_IF_FAIL (anal);
	anal->diff_ops = doops;
	anal->diff_thbb = (thbb >= 0)? thbb: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn >= 0)? thfcn: R_ANAL_THRESHOLDFCN;
}

R_API void r_anal_diff_setup_i(RAnal *anal, bool doops, int thbb, int thfcn) {
	R_RETURN_IF_FAIL (anal);
	anal->diff_ops = doops;
	anal->diff_thbb = (thbb >= 0)? ((double)thbb) / 100: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn >= 0)? ((double)thfcn) / 100: R_ANAL_THRESHOLDFCN;
}

// Fingerprint function basic block
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb) {
	R_RETURN_VAL_IF_FAIL (anal && bb, 0);
	RAnalOp *op;
	ut8 *buf;
	int oplen, idx = 0;

	if (anal->cur && anal->cur->fingerprint_bb) {
		return (anal->cur->fingerprint_bb (anal, bb));
	}
	if (!(bb->fingerprint = malloc (1 + bb->size))) {
		return 0;
	}
	if (!(buf = malloc (bb->size + 1))) {
		free (bb->fingerprint);
		return 0;
	}
	if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size)) {
		memcpy (bb->fingerprint, buf, bb->size);
		if (anal->diff_ops) { // diff using only the opcode
			if (!(op = r_anal_op_new ())) {
				free (bb->fingerprint);
				free (buf);
				return 0;
			}
			while (idx < bb->size) {
				if ((oplen = r_anal_op (anal, op, 0, buf+idx, bb->size-idx, R_ARCH_OP_MASK_BASIC)) < 1) {
					break;
				}
				if (op->nopcode != 0) {
					memset (bb->fingerprint+idx+op->nopcode, 0, oplen-op->nopcode);
				}
				idx += oplen;
			}
			free (op);
		}
	}
	free (buf);
	return bb->size;
}

static int bb_sort_by_addr(const void *x, const void *y) {
	ut64 a_addr = ((RAnalBlock *)x)->addr;
	ut64 b_addr = ((RAnalBlock *)y)->addr;
	if (a_addr > b_addr) {
		return 1;
	}
	if (a_addr < b_addr) {
		return -1;
	}
	return 0;
}

R_API size_t r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, 0);
	RAnalBlock *bb;
	RListIter *iter;

	if (anal->cur && anal->cur->fingerprint_fcn) {
		return (anal->cur->fingerprint_fcn (anal, fcn));
	}

	fcn->fingerprint = NULL;
	fcn->fingerprint_size = 0;
	r_list_sort (fcn->bbs, &bb_sort_by_addr);
	r_list_foreach (fcn->bbs, iter, bb) {
		fcn->fingerprint_size += bb->size;
		fcn->fingerprint = realloc (fcn->fingerprint, fcn->fingerprint_size + 1);
		if (!fcn->fingerprint) {
			return 0;
		}
		memcpy (fcn->fingerprint + fcn->fingerprint_size - bb->size, bb->fingerprint, bb->size);
	}
	return fcn->fingerprint_size;
}

R_API bool r_anal_diff_bb(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && fcn2, false);
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	double t, ot;

	if (anal->cur && anal->cur->diff_bb) {
		return (anal->cur->diff_bb (anal, fcn, fcn2));
	}
	fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
	r_list_sort (fcn->bbs, &bb_sort_by_addr);
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->diff && bb->diff->type != R_ANAL_DIFF_TYPE_NULL) {
			continue;
		}
		ot = 0;
		mbb = mbb2 = NULL;
		r_list_sort (fcn2->bbs, &bb_sort_by_addr);
		r_list_foreach (fcn2->bbs, iter2, bb2) {
			if (!bb2->diff || bb2->diff->type == R_ANAL_DIFF_TYPE_NULL) {
				r_diff_buffers_distance (NULL, bb->fingerprint, bb->size,
						bb2->fingerprint, bb2->size, NULL, &t);
				if (t > anal->diff_thbb && t > ot) {
					ot = t;
					mbb = bb;
					mbb2 = bb2;
					if (t == 1) {
						break;
					}
				}
			}
		}
		if (mbb && mbb2) {
			if (!mbb->diff) {
				mbb->diff = r_anal_diff_new ();
			}
			if (!mbb2->diff) {
				mbb2->diff = r_anal_diff_new ();
			}
			if (!mbb->diff || !mbb2->diff) {
				return false;
			}
			if (ot == 1 || t > anal->diff_thfcn) {
				mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
			} else {
				mbb->diff->type = mbb2->diff->type = \
				fcn->diff->type = fcn2->diff->type = \
					R_ANAL_DIFF_TYPE_UNMATCH;
			}
			R_FREE (mbb->fingerprint);
			R_FREE (mbb2->fingerprint);
			mbb->diff->addr = mbb2->addr;
			mbb2->diff->addr = mbb->addr;
			mbb->diff->size = mbb2->size;
			mbb2->diff->size = mbb->size;
		} else {
			fcn->diff->type = fcn2->diff->type = (fcn->diff->dist >= 0.6)
				? R_ANAL_DIFF_TYPE_MATCH
				: R_ANAL_DIFF_TYPE_UNMATCH;
		}
	}
	return true;
}

R_API int r_anal_diff_fcn(RAnal *anal, RList *fcns, RList *fcns2) {
	R_RETURN_VAL_IF_FAIL (anal && fcns, false);
	RAnalFunction *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	ut64 maxsize, minsize;
	double t = 0, ot = 0;
	if (!fcns2) {
		fcns2 = fcns;
	}

	if (anal->cur && anal->cur->diff_fcn) {
		return anal->cur->diff_fcn (anal, fcns, fcns2);
	}
	if (fcns == fcns2 || (r_list_length (fcns) == 1 && 1 == r_list_length (fcns2))) {
		RCore *core = anal->coreb.core;
		RCons *cons = core->cons;
		double threshold = 0.8; // XXX make this configurable by the user
		// inplace diffing
		r_list_foreach (fcns, iter, fcn) {
			if (!fcn->fingerprint) {
				r_anal_diff_fingerprint_fcn (anal, fcn);
			}
			r_list_foreach (fcns2, iter2, fcn2) {
				if (fcn == fcn2 || fcn->addr == fcn2->addr) {
					continue;
				}
				if (!fcn->name || !fcn2->name || !strcmp (fcn->name, fcn2->name)) {
					continue;
				}
				if (!fcn2->fingerprint) {
					r_anal_diff_fingerprint_fcn (anal, fcn2);
				}
				if (fcn->fingerprint && fcn2->fingerprint) {
					r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->fingerprint_size,
							fcn2->fingerprint, fcn2->fingerprint_size,
							NULL, &t);
					/* Set flag in matched functions */
					fcn->diff->type = fcn2->diff->type = (t >= threshold)
						? R_ANAL_DIFF_TYPE_MATCH
						: R_ANAL_DIFF_TYPE_UNMATCH;
					fcn->diff->dist = fcn2->diff->dist = t;
					if (fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH) {
						// R_LOG_INFO ("match %lf %s", t, fcn2->name);
						r_kons_printf (cons, "match %lf %s\n", t, fcn2->name);
					}
					R_FREE (fcn->fingerprint);
					R_FREE (fcn2->fingerprint);
				}
				fcn->diff->addr = fcn2->addr;
				fcn2->diff->addr = fcn->addr;
				fcn->diff->size = r_anal_function_linear_size (fcn2);
				fcn2->diff->size = r_anal_function_linear_size (fcn);
				R_FREE (fcn->diff->name);
				if (fcn2->name) {
					fcn->diff->name = strdup (fcn2->name);
				}
				R_FREE (fcn2->diff->name);
				if (fcn->name) {
					fcn2->diff->name = strdup (fcn->name);
				}
				r_anal_diff_bb (anal, fcn, fcn2);
				break;
			}
		}
		return false;
	}
	/* Compare functions with the same name */
	if (fcns) {
		r_list_foreach (fcns, iter, fcn) {
			if (!fcn->fingerprint) {
				r_anal_diff_fingerprint_fcn (anal, fcn);
			}
			r_list_foreach (fcns2, iter2, fcn2) {
				if (fcn == fcn2) {
					continue;
				}
				if (!fcn->name || !fcn2->name || strcmp (fcn->name, fcn2->name)) {
					continue;
				}
				if (!fcn2->fingerprint) {
					r_anal_diff_fingerprint_fcn (anal, fcn2);
				}
				if (fcn->fingerprint && fcn2->fingerprint) {
					r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->fingerprint_size,
							fcn2->fingerprint, fcn2->fingerprint_size,
							NULL, &t);
					/* Set flag in matched functions */
					fcn->diff->type = fcn2->diff->type = (t >= 1)
						? R_ANAL_DIFF_TYPE_MATCH
						: R_ANAL_DIFF_TYPE_UNMATCH;
					fcn->diff->dist = fcn2->diff->dist = t;
					R_FREE (fcn->fingerprint);
					R_FREE (fcn2->fingerprint);
				}
				fcn->diff->addr = fcn2->addr;
				fcn2->diff->addr = fcn->addr;
				fcn->diff->size = r_anal_function_linear_size (fcn2);
				fcn2->diff->size = r_anal_function_linear_size (fcn);
				R_FREE (fcn->diff->name);
				if (fcn2->name) {
					fcn->diff->name = strdup (fcn2->name);
				}
				R_FREE (fcn2->diff->name);
				if (fcn->name) {
					fcn2->diff->name = strdup (fcn->name);
				}
				r_anal_diff_bb (anal, fcn, fcn2);
				break;
			}
		}
	}
	/* Compare remaining functions */
	r_list_foreach (fcns, iter, fcn) {
/*
		if ((fcn->type != R_ANAL_FCN_TYPE_FCN &&
			fcn->type != R_ANAL_FCN_TYPE_SYM) ||
			fcn->diff->type != R_ANAL_DIFF_TYPE_NULL) {
			continue;
		}
*/
		if (fcn->diff->type != R_ANAL_DIFF_TYPE_NULL) {
			continue;
		}
		ot = 0;
		mfcn = mfcn2 = NULL;
		r_list_foreach (fcns2, iter2, fcn2) {
			ut64 fcn_size = r_anal_function_linear_size (fcn);
			ut64 fcn2_size = r_anal_function_linear_size (fcn2);
			if (fcn_size > fcn2_size) {
				maxsize = fcn_size;
				minsize = fcn2_size;
			} else {
				maxsize = fcn2_size;
				minsize = fcn_size;
			}
			if (maxsize * anal->diff_thfcn > minsize) {
				R_LOG_DEBUG ("Exceeded anal threshold while diffing %s and %s", fcn->name, fcn2->name);
				continue;
			}
			if (fcn2->diff->type != R_ANAL_DIFF_TYPE_NULL) {
				R_LOG_DEBUG ("Function %s already diffed", fcn2->name);
				continue;
			}
			if ((fcn2->type != R_ANAL_FCN_TYPE_FCN && fcn2->type != R_ANAL_FCN_TYPE_SYM)) {
				R_LOG_DEBUG ("Function %s type not supported", fcn2->name);
				continue;
			}
			if (fcn->fingerprint && fcn2->fingerprint) {
				r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->fingerprint_size,
						fcn2->fingerprint, fcn2->fingerprint_size, NULL, &t);
			}
			fcn->diff->dist = fcn2->diff->dist = t;
			if (t > anal->diff_thfcn && t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
				if (t == 1) {
					break;
				}
			}
		}
		if (mfcn && mfcn2) {
			/* Set flag in matched functions */
			mfcn->diff->type = mfcn2->diff->type = (ot == 1)
				? R_ANAL_DIFF_TYPE_MATCH
				: R_ANAL_DIFF_TYPE_UNMATCH;
			R_FREE (mfcn->fingerprint);
			R_FREE (mfcn2->fingerprint);
			mfcn->diff->addr = mfcn2->addr;
			mfcn2->diff->addr = mfcn->addr;
			mfcn->diff->size = r_anal_function_linear_size (mfcn2);
			mfcn2->diff->size = r_anal_function_linear_size (mfcn);
			R_FREE (mfcn->diff->name);
			if (mfcn2->name) {
				mfcn->diff->name = strdup (mfcn2->name);
			}
			R_FREE (mfcn2->diff->name);
			if (mfcn->name) {
				mfcn2->diff->name = strdup (mfcn->name);
			}
			r_anal_diff_bb (anal, mfcn, mfcn2);
		}
	}
	return true;
}
