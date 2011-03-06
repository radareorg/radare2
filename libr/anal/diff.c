/* radare - LGPL - Copyright 2010 - nibble<.ds@gmail.com> */

#include <r_anal.h>
#include <r_util.h>
#include <r_diff.h>

R_API RAnalDiff *r_anal_diff_new() {
	RAnalDiff *diff = R_NEW (RAnalDiff);
	if (diff) {
		diff->type = R_ANAL_DIFF_TYPE_NULL;
		diff->addr = -1;
		diff->name = NULL;
	}
	return diff;
}

R_API void* r_anal_diff_free(RAnalDiff *diff) {
	if (diff && diff->name)
		free (diff->name);
	free (diff);
	return NULL;
}

R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb) {
	RAnalOp *op;
	ut8 *buf;
	int oplen, idx = 0;

	if (anal && anal->cur && anal->cur->fingerprint_bb)
		return (anal->cur->fingerprint_bb (anal, bb));

	if (!(bb->fingerprint = malloc (bb->size)))
		return R_FALSE;
	if (!(buf = malloc (bb->size))) {
		free (bb->fingerprint);
		return 0;
	}
	if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size) == bb->size) {
		memcpy (bb->fingerprint, buf, bb->size);
		if (!(op = r_anal_op_new ())) {
			free (bb->fingerprint);
			free (buf);
			return 0;
		}
		while (idx < bb->size) {
			if ((oplen = r_anal_op (anal, op, 0, buf+idx, bb->size-idx)) == 0)
				break;
			if (op->nopcode != 0)
				memset (bb->fingerprint+idx+op->nopcode, 0, oplen-op->nopcode);
			idx += oplen;
		}
		free (op);
	}
	free (buf);
	return bb->size;
}

R_API int r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFcn *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	int len = 0;
	
	if (anal && anal->cur && anal->cur->fingerprint_fcn)
		return (anal->cur->fingerprint_fcn (anal, fcn));

	iter = r_list_iterator (fcn->bbs), fcn->fingerprint = NULL;
	while (r_list_iter_next (iter)) {
		bb = r_list_iter_get (iter);
		len += bb->size;
		fcn->fingerprint = realloc (fcn->fingerprint, len);
		if (!fcn->fingerprint)
			return 0;
		memcpy (fcn->fingerprint+len-bb->size, bb->fingerprint, bb->size);
	}
	return len;
}

R_API int r_anal_diff_bb(RAnal *anal, RAnalFcn *fcn, RAnalFcn *fcn2) {
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	double t, ot;

	if (anal && anal->cur && anal->cur->diff_bb)
		return (anal->cur->diff_bb (anal, fcn, fcn2));

	fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
	iter = r_list_iterator (fcn->bbs);
	while (r_list_iter_next (iter)) {
		bb = r_list_iter_get (iter);
		if (bb->diff->type != R_ANAL_DIFF_TYPE_NULL)
			continue;
		ot = 0;
		mbb = mbb2 = NULL;
		iter2 = r_list_iterator (fcn2->bbs);
		while (r_list_iter_next (iter2)) {
			bb2 = r_list_iter_get (iter2);
			if (bb2->diff->type == R_ANAL_DIFF_TYPE_NULL) {
				r_diff_buffers_distance (NULL, bb->fingerprint, bb->size,
						bb2->fingerprint, bb2->size, NULL, &t);
#if 0
				eprintf ("BB: %llx - %llx => %lli - %lli => %f\n", bb->addr, bb2->addr,
						bb->size, bb->size, t);
#endif 
				if (t > R_ANAL_THRESHOLDBB && t > ot) {
					ot = t;
					mbb = bb;
					mbb2 = bb2;
					if (t == 1) break;
				}
			}
		}
		if (mbb != NULL && mbb2 != NULL) {
			if (ot == 1)
				mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
			else {
				mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			}
			R_FREE (mbb->fingerprint);
			R_FREE (mbb2->fingerprint);
			mbb->diff->addr = mbb2->addr;
			mbb2->diff->addr = mbb->addr;
		} else
			fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
	}
	return R_TRUE;
}

R_API int r_anal_diff_fcn(RAnal *anal, RList *fcns, RList *fcns2) {
	RAnalFcn *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	ut64 maxsize, minsize;
	double t, ot;

	if (anal && anal->cur && anal->cur->diff_fcn)
		return (anal->cur->diff_fcn (anal, fcns, fcns2));

	/* Compare functions with the same name */
	iter = r_list_iterator (fcns);
	while (r_list_iter_next (iter)) {
		fcn = r_list_iter_get (iter);
		if (fcn->type != R_ANAL_FCN_TYPE_SYM || fcn->name == NULL)
			continue;
		iter2 = r_list_iterator (fcns2);
		while (r_list_iter_next (iter2)) {
			fcn2 = r_list_iter_get (iter2);
			if (fcn2->type != R_ANAL_FCN_TYPE_SYM || fcn2->name == NULL ||
				strcmp (fcn->name, fcn2->name))
				continue;
			r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->size,
					fcn2->fingerprint, fcn2->size, NULL, &t);
#if 1
			eprintf ("FCN NAME (NAME): %s - %s => %lli - %lli => %f\n", fcn->name, fcn2->name,
					fcn->size, fcn2->size, t);
#endif 
			/* Set flag in matched functions */
			if (t == 1)
				fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
			else
				fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			R_FREE (fcn->fingerprint);
			R_FREE (fcn2->fingerprint);
			fcn->diff->addr = fcn2->addr;
			fcn2->diff->addr = fcn->addr;
			R_FREE (fcn->diff->name);
			if (fcn2->name)
				fcn->diff->name = strdup (fcn2->name);
			R_FREE (fcn2->diff->name);
			if (fcn->name)
				fcn2->diff->name = strdup (fcn->name);
			r_anal_diff_bb (anal, fcn, fcn2);
			break;
		}
	}
	/* Compare remaining functions */
	iter = r_list_iterator (fcns);
	while (r_list_iter_next (iter)) {
		fcn = r_list_iter_get (iter);
		if ((fcn->type != R_ANAL_FCN_TYPE_FCN && fcn->type != R_ANAL_FCN_TYPE_SYM) ||
			fcn->diff->type != R_ANAL_DIFF_TYPE_NULL)
			continue;
		ot = 0;
		mfcn = mfcn2 = NULL;
		iter2 = r_list_iterator (fcns2);
		while (r_list_iter_next (iter2)) {
			fcn2 = r_list_iter_get (iter2);
			if (fcn->size > fcn2->size) {
				maxsize = fcn->size;
				minsize = fcn2->size;
			} else {
				maxsize = fcn2->size;
				minsize = fcn->size;
			}
			if ((fcn2->type != R_ANAL_FCN_TYPE_FCN && fcn2->type != R_ANAL_FCN_TYPE_SYM) ||
				fcn2->diff->type != R_ANAL_DIFF_TYPE_NULL || (maxsize * R_ANAL_THRESHOLDFCN > minsize))
				continue;
			r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->size,
					fcn2->fingerprint, fcn2->size, NULL, &t);
#if 1
			eprintf ("FCN: %s - %s => %lli - %lli => %f\n", fcn->name, fcn2->name,
					fcn->size, fcn2->size, t);
#endif 
			if (t > R_ANAL_THRESHOLDFCN && t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
				if (t == 1) break;
			}
		}
		if (mfcn != NULL && mfcn2 != NULL) {
#if 0
			eprintf ("Match => %s - %s\n", mfcn->name, mfcn2->name);
#endif
			/* Set flag in matched functions */
			if (ot == 1)
				mfcn->diff->type = mfcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
			else
				mfcn->diff->type = mfcn2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			R_FREE (mfcn->fingerprint);
			R_FREE (mfcn2->fingerprint);
			mfcn->diff->addr = mfcn2->addr;
			mfcn2->diff->addr = mfcn->addr;
			R_FREE (mfcn->diff->name);
			if (mfcn2->name)
				mfcn->diff->name = strdup (mfcn2->name);
			R_FREE (mfcn2->diff->name);
			if (mfcn->name)
				mfcn2->diff->name = strdup (mfcn->name);
			r_anal_diff_bb (anal, mfcn, mfcn2);
		}
	}
	return R_TRUE;
}

R_API int r_anal_diff_eval(RAnal *anal) {
	/*TODO*/
	if (anal && anal->cur && anal->cur->diff_eval)
		return (anal->cur->diff_eval (anal));
	return R_TRUE;
}
