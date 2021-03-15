/* radare - LGPL - Copyright 2010-2020 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_diff.h>

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

R_API void* r_anal_diff_free(RAnalDiff *diff) {
	if (diff && diff->name) {
		R_FREE (diff->name);
	}
	free (diff);
	return NULL;
}

/* 0-1 */
R_API void r_anal_diff_setup(RAnal *anal, int doops, double thbb, double thfcn) {
	if (doops >= 0) {
		anal->diff_ops = doops;
	}
	anal->diff_thbb = (thbb>=0)? thbb: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn>=0)? thfcn: R_ANAL_THRESHOLDFCN;
}

/* 0-100 */
R_API void r_anal_diff_setup_i(RAnal *anal, int doops, int thbb, int thfcn) {
	if (doops >= 0) {
		anal->diff_ops = doops;
	}
	anal->diff_thbb = (thbb>=0)? ((double)thbb) / 100: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn>=0)? ((double)thfcn) / 100: R_ANAL_THRESHOLDFCN;
}

// Fingerprint function basic block
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb) {
	RAnalOp *op;
	ut8 *buf;
	int oplen, idx = 0;

	if (!anal) {
		return false;
	}
	if (anal->cur && anal->cur->fingerprint_bb) {
		return (anal->cur->fingerprint_bb (anal, bb));
	}
	if (!(bb->fingerprint = malloc (1 + bb->size))) {
		return false;
	}
	if (!(buf = malloc (bb->size + 1))) {
		free (bb->fingerprint);
		return false;
	}
	if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size)) {
		memcpy (bb->fingerprint, buf, bb->size);
		if (anal->diff_ops) { // diff using only the opcode
			if (!(op = r_anal_op_new ())) {
				free (bb->fingerprint);
				free (buf);
				return false;
			}
			while (idx < bb->size) {
				if ((oplen = r_anal_op (anal, op, 0, buf+idx, bb->size-idx, R_ANAL_OP_MASK_BASIC)) < 1) {
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

R_API size_t r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;

	if (anal && anal->cur && anal->cur->fingerprint_fcn) {
		return (anal->cur->fingerprint_fcn (anal, fcn));
	}

	fcn->fingerprint = NULL;
	fcn->fingerprint_size = 0;
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
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	double t, ot;

	if (!anal || !fcn || !fcn2) {
		return false;
	}
	if (anal->cur && anal->cur->diff_bb) {
		return (anal->cur->diff_bb (anal, fcn, fcn2));
	}
	fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->diff && bb->diff->type != R_ANAL_DIFF_TYPE_NULL) {
			continue;
		}
		ot = 0;
		mbb = mbb2 = NULL;
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
				mbb->diff = r_anal_diff_new();
			}
			if (!mbb2->diff) {
				mbb2->diff = r_anal_diff_new();
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
	RAnalFunction *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	ut64 maxsize, minsize;
	double t, ot;

	if (!anal) {
		return false;
	}
	if (anal->cur && anal->cur->diff_fcn) {
		return (anal->cur->diff_fcn (anal, fcns, fcns2));
	}
	/* Compare functions with the same name */
	if (fcns) {
		r_list_foreach (fcns, iter, fcn) {
			r_list_foreach (fcns2, iter2, fcn2) {
				if (!fcn->name || !fcn2->name || strcmp (fcn->name, fcn2->name)) {
					continue;
				}
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
				eprintf ("Exceeded anal threshold while diffing %s and %s\n", fcn->name, fcn2->name);
				continue;
			}
			if (fcn2->diff->type != R_ANAL_DIFF_TYPE_NULL) {
				eprintf ("Function %s already diffed\n", fcn2->name);
				continue;
			}
			if ((fcn2->type != R_ANAL_FCN_TYPE_FCN && fcn2->type != R_ANAL_FCN_TYPE_SYM)) {
				eprintf ("Function %s type not supported\n", fcn2->name);
				continue;
			}
			r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->fingerprint_size, fcn2->fingerprint, fcn2->fingerprint_size, NULL, &t);
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

R_API int r_anal_diff_eval(RAnal *anal) {
	if (anal && anal->cur && anal->cur->diff_eval) {
		return (anal->cur->diff_eval (anal));
	}
	return true; // XXX: shouldn't this be false?
}
