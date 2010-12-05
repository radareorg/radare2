/* radare - LGPL - Copyright 2010 - nibble<develsec.org> */

#include <stdio.h>
#include <string.h>
#include <r_anal.h>
#include <r_diff.h>
#include <r_list.h>
#include <r_util.h>
#include <r_core.h>

#define THRESHOLDFCN 0.7F
#define THRESHOLDBB 0.7F

static ut8* gdiff_fingerprint(RAnal *a, ut8* buf, int len) {
	RAnalOp *aop;
	ut8 *ret = NULL;
	int oplen, idx = 0;

	if (!(ret = malloc (len)))
		return NULL;
	memcpy (ret, buf, len);
	if (!(aop = r_anal_aop_new ())) {
		free (ret);
		return NULL;
	}
	while (idx < len) {
		if ((oplen = r_anal_aop (a, aop, 0, buf+idx, len-idx)) == 0)
			break;
		if (aop->nopcode != 0)
			memset (ret+idx+aop->nopcode, 0, oplen-aop->nopcode);
		idx += oplen;
	}
	free (aop);
	return ret;
}

static void gdiff_diff_bb(RAnalFcn *mfcn, RAnalFcn *mfcn2, RList *bbs, RList *bbs2) {
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	ut32 d;
	double t, ot;

	iter = r_list_iterator (bbs);
	while (r_list_iter_next (iter)) {
		bb = r_list_iter_get (iter);
		if (bb->diff->type != R_ANAL_DIFF_TYPE_NULL)
			continue;
		if (bb->addr >= mfcn->addr && bb->addr < mfcn->addr + mfcn->size) {
			ot = 0;
			mbb = mbb2 = NULL;
			iter2 = r_list_iterator (bbs2);
			while (r_list_iter_next (iter2)) {
				bb2 = r_list_iter_get (iter2);
				if (bb2->diff->type == R_ANAL_DIFF_TYPE_NULL &&
						bb2->addr >= mfcn2->addr && bb2->addr < mfcn2->addr + mfcn2->size) {
					r_diff_buffers_distance(NULL, bb->fingerprint, bb->size,
							bb2->fingerprint, bb2->size, &d, &t);
#if 0 
					eprintf ("BB: %llx - %llx => %i - %i - %i => %f\n", bb->addr, bb2->addr,
							bb->ninstr, bb2->ninstr, p, t);
#endif 
					if (t > THRESHOLDBB && t > ot) {
						ot = t;
						mbb = bb;
						mbb2 = bb2;
					}
				}
			}
			if (mbb != NULL && mbb2 != NULL) {
				if (ot == 1)
					mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_MATCH;
				else
					mbb->diff->type = mbb2->diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				mbb->diff->addr = mbb2->addr;
				R_FREE (mbb->fingerprint);
				R_FREE (mbb2->fingerprint);
			}
		}
	}
}

static void gdiff_diff_fcn(RList *fcns, RList *fcns2, RList *bbs, RList *bbs2) {
	RAnalFcn *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	ut32 d;
	double t, ot;

	iter = r_list_iterator (fcns);
	while (r_list_iter_next (iter)) {
		fcn = r_list_iter_get (iter);
		if (fcn->type != R_ANAL_FCN_TYPE_FCN)
			continue;
		ot = 0;
		mfcn = mfcn2 = NULL;
		iter2 = r_list_iterator (fcns2);
		while (r_list_iter_next (iter2)) {
			fcn2 = r_list_iter_get (iter2);
			if (fcn2->type != R_ANAL_FCN_TYPE_FCN || fcn2->diff->type != R_ANAL_DIFF_TYPE_NULL)
				continue;
			r_diff_buffers_distance(NULL, fcn->fingerprint, fcn->size,
					fcn2->fingerprint, fcn2->size, &d, &t);
#if 0
			eprintf ("FCN: %s - %s => %lli - %lli => %f\n", fcn->name, fcn2->name,
					fcn->size, fcn2->size, t);
#endif 
			if (t > THRESHOLDFCN && t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
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
			if (mfcn2->name)
				mfcn->diff->name = strdup (mfcn2->name);
			gdiff_diff_bb (mfcn, mfcn2, bbs, bbs2);
		}
	}
}

R_API int r_core_gdiff(RCore *c, const char *file1, const char *file2, int va) {
	RCore *core2;
	RAnalFcn *fcn;
	RAnalBlock *bb;
	RList *fcns[2], *bbs[2];
	RListIter *iter;
	ut8 *buf;
	const char *files[2] = {file1, file2};
	int i;

	/* Init resources  */
	core2 = r_core_new ();

	for (i = 0; i < 2; i++) {
		/* Load and analyze bin*/
		r_config_set_i (core2->config, "io.va", va);
		if (!r_core_file_open (core2, files[i], 0)) {
			eprintf ("Cannot open file '%s'\n", files[i]);
			return R_FALSE;
		}
		r_config_set_i (core2->config, "anal.split", 0);
		r_core_cmd0 (core2, "aa");
		/* Copy fcn's */
		fcns[i] = r_list_new ();
		fcns[i]->free = &r_anal_fcn_free;
		iter = r_list_iterator (core2->anal->fcns);
		while (r_list_iter_next (iter)) {
			fcn = r_list_iter_get (iter);
			/* Fingerprint fcn */
			if ((buf = malloc (fcn->size))) {
				if (r_io_read_at (core2->io, fcn->addr, buf, fcn->size) == fcn->size)
					fcn->fingerprint = gdiff_fingerprint (core2->anal, buf, fcn->size);
				free (buf);
			}
			r_list_split (core2->anal->fcns, fcn);
			r_list_append (fcns[i], fcn);
		}
		/* Copy bb's */
		bbs[i] = r_list_new ();
		bbs[i]->free = &r_anal_bb_free;
		iter = r_list_iterator (core2->anal->bbs);
		while (r_list_iter_next (iter)) {
			bb = r_list_iter_get (iter);
			/* Fingerprint bb */
			if ((buf = malloc (bb->size))) {
				if (r_io_read_at (core2->io, bb->addr, buf, bb->size) == bb->size)
					bb->fingerprint = gdiff_fingerprint (core2->anal, buf, bb->size);
				free (buf);
			}
			r_list_split (core2->anal->bbs, bb);
			r_list_append (bbs[i], bb);
		}
		/* Remove flags and analysis info */
		r_core_cmd0 (core2, "af-");
		r_core_cmd0 (core2, "ab-");
		r_core_cmd0 (core2, "f-*");
	}

	/* Diff functions */
	gdiff_diff_fcn (fcns[0], fcns[1], bbs[0], bbs[1]);

	/* Fill analysis info in core */
	r_list_foreach (bbs[0], iter, bb)
		r_anal_bb_add (c->anal, bb->addr, bb->size, bb->jump, bb->fail, bb->type, bb->diff);
	r_list_foreach (fcns[0], iter, fcn)
		r_anal_fcn_add (c->anal, fcn->addr, fcn->size, fcn->name, fcn->type, fcn->diff);

	/* Free resources */
	r_core_free (core2);
	for (i=0;i<2;i++) {
		r_list_free (bbs[i]);
		r_list_free (fcns[i]);
	}

	return R_TRUE;
}
