/* radare - LGPL - Copyright 2010-2014 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_diff.h>

R_API RAnalDiff *r_anal_diff_new() {
	RAnalDiff *diff = R_NEW (RAnalDiff);
	if (diff) {
		diff->type = R_ANAL_DIFF_TYPE_NULL;
		diff->addr = -1;
		diff->dist = 0;
		diff->name = NULL;
	}
	return diff;
}

R_API void* r_anal_diff_free(RAnalDiff *diff) {
	if (diff && diff->name) {
		free (diff->name);
		diff->name = NULL;
	}
	free (diff);
	return NULL;
}

/* 0-1 */
R_API void r_anal_diff_setup(RAnal *anal, int doops, double thbb, double thfcn) {
	if (doops>=0) anal->diff_ops = doops;
	anal->diff_thbb = (thbb>=0)? thbb: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn>=0)? thfcn: R_ANAL_THRESHOLDFCN;
}

/* 0-100 */
R_API void r_anal_diff_setup_i(RAnal *anal, int doops, int thbb, int thfcn) {
	if (doops>=0) anal->diff_ops = doops;
	anal->diff_thbb = (thbb>=0)? ((double)thbb)/100: R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = (thfcn>=0)? ((double)thfcn)/100: R_ANAL_THRESHOLDFCN;
}

// Fingerprint function basic block
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb) {
	RAnalOp *op;
	ut8 *buf;
	int oplen, idx = 0;

	if (!anal)
		return R_FALSE;
	if (anal->cur && anal->cur->fingerprint_bb)
		return (anal->cur->fingerprint_bb (anal, bb));

	if (!(bb->fingerprint = malloc (1+bb->size)))
		return R_FALSE;
	if (!(buf = malloc (1+bb->size))) {
		free (bb->fingerprint);
		return R_FALSE;
	}
	if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size) == bb->size) {
		memcpy (bb->fingerprint, buf, bb->size);
		if (anal->diff_ops) { // diff using only the opcode
			if (!(op = r_anal_op_new ())) {
				free (bb->fingerprint);
				free (buf);
				return R_FALSE;
			}
			while (idx < bb->size) {
				if ((oplen = r_anal_op (anal, op, 0, buf+idx, bb->size-idx)) <1)
					break;
				if (op->nopcode != 0)
					memset (bb->fingerprint+idx+op->nopcode, 0, oplen-op->nopcode);
				idx += oplen;
			}
			free (op);
		}
	}
	free (buf);
	return bb->size;
}

R_API int r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	int len = 0;

	if (anal && anal->cur && anal->cur->fingerprint_fcn)
		return (anal->cur->fingerprint_fcn (anal, fcn));

	fcn->fingerprint = NULL;
	r_list_foreach (fcn->bbs, iter, bb) {
		len += bb->size;
		fcn->fingerprint = realloc (fcn->fingerprint, len);
		if (!fcn->fingerprint)
			return 0;
		memcpy (fcn->fingerprint+len-bb->size, bb->fingerprint, bb->size);
	}
	return len;
}

R_API int r_anal_diff_bb(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2) {
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	double t, ot;

	if (!anal) return R_FALSE;
	if (anal->cur && anal->cur->diff_bb)
		return (anal->cur->diff_bb (anal, fcn, fcn2));

	fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->diff && bb->diff->type != R_ANAL_DIFF_TYPE_NULL)
			continue;
		ot = 0;
		mbb = mbb2 = NULL;
		r_list_foreach (fcn2->bbs, iter2, bb2) {
			if (bb2->diff && bb2->diff->type == R_ANAL_DIFF_TYPE_NULL) {
				r_diff_buffers_distance (NULL, bb->fingerprint, bb->size,
						bb2->fingerprint, bb2->size, NULL, &t);
#if 0
				eprintf ("BB: %llx - %llx => %lli - %lli => %f\n", bb->addr, bb2->addr,
						bb->size, bb->size, t);
#endif
				if (t > anal->diff_thbb && t > ot) {
					ot = t;
					mbb = bb;
					mbb2 = bb2;
					if (t == 1) break;
				}
}
		}
		if (mbb != NULL && mbb2 != NULL) {
			if (ot == 1 || t > anal->diff_thfcn )
				mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
			else mbb->diff->type = mbb2->diff->type = \
				fcn->diff->type = fcn2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
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
	RAnalFunction *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	ut64 maxsize, minsize;
	double t, ot;

	if (!anal)
		return R_FALSE;

	if (anal->cur && anal->cur->diff_fcn)
		return (anal->cur->diff_fcn (anal, fcns, fcns2));

	/* Compare functions with the same name */
	if (fcns)
	r_list_foreach (fcns, iter, fcn) {
		if (fcn->type != R_ANAL_FCN_TYPE_SYM || fcn->name == NULL)
			continue;
		r_list_foreach (fcns2, iter2, fcn2) {
			if (fcn2->type != R_ANAL_FCN_TYPE_SYM || fcn2->name == NULL ||
				strcmp (fcn->name, fcn2->name))
				continue;
			r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->size,
					fcn2->fingerprint, fcn2->size, NULL, &t);
#if 0
			eprintf ("FCN NAME (NAME): %s - %s => %lli - %lli => %f\n", fcn->name, fcn2->name,
					fcn->size, fcn2->size, t);
#endif
			/* Set flag in matched functions */
			fcn->diff->type = fcn2->diff->type = (t==1)?
				R_ANAL_DIFF_TYPE_MATCH: R_ANAL_DIFF_TYPE_UNMATCH;
			fcn->diff->dist = fcn2->diff->dist = t;
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
	r_list_foreach (fcns, iter, fcn) {
		if ((fcn->type != R_ANAL_FCN_TYPE_FCN && fcn->type != R_ANAL_FCN_TYPE_SYM) ||
			fcn->diff->type != R_ANAL_DIFF_TYPE_NULL)
			continue;
		ot = 0;
		mfcn = mfcn2 = NULL;
		r_list_foreach (fcns2, iter2, fcn2) {
			if (fcn->size > fcn2->size) {
				maxsize = fcn->size;
				minsize = fcn2->size;
			} else {
				maxsize = fcn2->size;
				minsize = fcn->size;
			}
			if ((fcn2->type != R_ANAL_FCN_TYPE_FCN && fcn2->type != R_ANAL_FCN_TYPE_SYM) ||
				fcn2->diff->type != R_ANAL_DIFF_TYPE_NULL || (maxsize * anal->diff_thfcn > minsize))
				continue;
			r_diff_buffers_distance (NULL, fcn->fingerprint, fcn->size,
					fcn2->fingerprint, fcn2->size, NULL, &t);
			fcn->diff->dist = fcn2->diff->dist = t;
#if 0
			int i;
			eprintf ("FP0 ");
			for (i=0;i<fcn->size;i++)
				eprintf ("%02x", fcn->fingerprint[i]);
			eprintf ("\n");

			eprintf ("FP1 ");
			for (i=0;i<fcn2->size;i++)
				eprintf ("%02x", fcn2->fingerprint[i]);
			eprintf ("\n");
			eprintf ("FCN: %s - %s => %lli - %lli => %f\n", fcn->name, fcn2->name,
					fcn->size, fcn2->size, t);
#endif
			if (t > anal->diff_thfcn && t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
				if (t == 1) break;
			}
		}
		if (mfcn && mfcn2) {
#if 0
			eprintf ("Match => %s - %s\n", mfcn->name, mfcn2->name);
#endif
			/* Set flag in matched functions */
			mfcn->diff->type = mfcn2->diff->type = (ot==1)?
				R_ANAL_DIFF_TYPE_MATCH: R_ANAL_DIFF_TYPE_UNMATCH;
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
	return R_TRUE; // XXX: shouldnt this be false?
}
