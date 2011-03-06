/* radare - LGPL - Copyright 2010 - nibble<develsec.org> */

#include <stdio.h>
#include <string.h>
#include <r_anal.h>
#include <r_list.h>
#include <r_util.h>
#include <r_core.h>

R_API int r_core_gdiff(RCore *c, RCore *c2) {
	RCore *cores[2] = {c, c2};
	RAnalFcn *fcn;
	RAnalBlock *bb;
	RListIter *iter, *iter2;
	ut8 *buf;
	int i;

	for (i = 0; i < 2; i++) {
		r_core_anal_all (cores[i]);
		/* Fingerprint fcn bbs */
		iter = r_list_iterator (cores[i]->anal->fcns);
		while (r_list_iter_next (iter)) {
			fcn = r_list_iter_get (iter);
			iter2 = r_list_iterator (fcn->bbs);
			while (r_list_iter_next (iter2)) {
				bb = r_list_iter_get (iter2);
				r_anal_diff_fingerprint_bb (cores[i]->anal, bb);
			}
		}
		/* Fingerprint fcn */
		iter = r_list_iterator (cores[i]->anal->fcns);
		while (r_list_iter_next (iter)) {
			fcn = r_list_iter_get (iter);
			fcn->size = r_anal_diff_fingerprint_fcn (cores[i]->anal, fcn);
		}
	}
	/* Diff functions */
	r_anal_diff_fcn (cores[0]->anal, cores[0]->anal->fcns, cores[1]->anal->fcns);

	return R_TRUE;
}
