/* radare - LGPL - Copyright 2010 - nibble<develsec.org> */

#include <stdio.h>
#include <string.h>
#include <r_anal.h>
#include <r_list.h>
#include <r_util.h>
#include <r_core.h>
#include "gdiff.h"

/* XXX NEED A HASH ALGO */
static ut32 gdiff_get_prime(char* mnemonic) {
	int i;

	for (i=0; i < 442; i++)
		if (!strcmp (mnemonic, mnemonics[i]))
			return primes[i];
	return 1;
#if 0 
	ut64 index = 0;
	char *ch;
	
	ch = (char *)mnemonic + strlen (mnemonic)-1;
	do {
		index = index*32 + (*ch-0x60) & 0xff;
	} while (ch-- > (char*)mnemonic);
	return primes[index % sizeof (primes)];
#endif 
}

static void gdiff_fingerprint_bb(RAnalBlock *bb) {
	RAnalOp *op;
	RListIter *iter;

	r_big_set_str (bb->fingerprint, "1");
	r_list_foreach (bb->aops, iter, op)
		r_big_mul_ut (bb->fingerprint, bb->fingerprint, gdiff_get_prime (op->mnemonic));
}

static void gdiff_fingerprint_fcn(RList *bbs, RAnalFcn *fcn) {
	RAnalBlock *bb;
	RListIter *iter;

	r_big_set_str (fcn->fingerprint, "1");
	r_list_foreach (bbs, iter, bb)
		if (bb->addr >= fcn->addr && bb->addr < fcn->addr + fcn->size)
			r_big_mul (fcn->fingerprint, fcn->fingerprint, bb->fingerprint);
}

static void gdiff_diff_bb(RAnalFcn *mfcn, RAnalFcn *mfcn2, RList *bbs, RList *bbs2) {
	RAnalBlock *bb, *bb2, *mbb, *mbb2;
	RListIter *iter, *iter2;
	RNumBig *fingerprint, *fingerprint2;
	float t, ot;
	int i, p;

	fingerprint = r_big_new (NULL);
	fingerprint2 = r_big_new (NULL);

	iter = r_list_iterator (bbs);
	while (r_list_iter_next (iter)) {
		bb = r_list_iter_get (iter);
		if (bb->diff == R_ANAL_DIFF_NULL &&
				bb->addr >= mfcn->addr && bb->addr < mfcn->addr + mfcn->size) {
			ot = 0;
			mbb = mbb2 = NULL;
			iter2 = r_list_iterator (bbs2);
			while (r_list_iter_next (iter2)) {
				bb2 = r_list_iter_get (iter2);
				if (bb2->diff == R_ANAL_DIFF_NULL &&
						bb2->addr >= mfcn2->addr && bb2->addr < mfcn2->addr + mfcn2->size) {
					p = 0;
					t = 0;
					if (r_big_cmp (bb->fingerprint, bb2->fingerprint) != 0) {
						r_big_set (fingerprint, bb->fingerprint);
						r_big_set (fingerprint2, bb2->fingerprint);
						while ( r_big_cmp_st (fingerprint, 1) != 0 && 
								r_big_cmp_st (fingerprint2, 1) != 0) {
							for (i = 0; i < NPRIMES; i++)
								if (r_big_divisible_ut (fingerprint, primes[i]) &&
									r_big_divisible_ut (fingerprint2, primes[i])) {
									r_big_div_ut (fingerprint, fingerprint, primes[i]);
									r_big_div_ut (fingerprint2, fingerprint2, primes[i]);
									p++;
									break;
								}
							if (i == NPRIMES)
								break;
						}
					} else {
						if (bb->ninstr > bb2->ninstr)
							p = bb->ninstr;
						else p = bb2->ninstr;
					}
					if (bb->ninstr > bb2->ninstr)
						t = (float)1-(float)(bb->ninstr-p)/bb->ninstr;
					else t = (float)1-(float)(bb2->ninstr-p)/bb2->ninstr;
#if 0 
					printf ("BB: %llx - %llx => %i - %i - %i => %f\n", bb->addr, bb2->addr,
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
					mbb->diff = mbb2->diff = R_ANAL_DIFF_MATCH;
				else
					mbb->diff = mbb2->diff = R_ANAL_DIFF_UNMATCH;
			}
		}
	}

	r_big_free (fingerprint);
	r_big_free (fingerprint2);
}

static void gdiff_diff_fcn(RList *fcns, RList *fcns2, RList *bbs, RList *bbs2) {
	RAnalFcn *fcn, *fcn2, *mfcn, *mfcn2;
	RListIter *iter, *iter2;
	RNumBig *fingerprint, *fingerprint2;
	float t, ot;
	int i, p;

	fingerprint = r_big_new (NULL);
	fingerprint2 = r_big_new (NULL);

	iter = r_list_iterator (fcns);
	while (r_list_iter_next (iter)) {
		fcn = r_list_iter_get (iter);
		ot = 0;
		mfcn = mfcn2 = NULL;
		iter2 = r_list_iterator (fcns2);
		while (r_list_iter_next (iter2)) {
			fcn2 = r_list_iter_get (iter2);
			p = 0;
			t = 0;
			if (r_big_cmp (fcn->fingerprint, fcn2->fingerprint) != 0) {
				r_big_set (fingerprint, fcn->fingerprint);
				r_big_set (fingerprint2, fcn2->fingerprint);
				while ( r_big_cmp_st (fingerprint, 1) != 0 && 
						r_big_cmp_st (fingerprint2, 1) != 0) {
					for (i = 0; i < NPRIMES; i++)
						if (r_big_divisible_ut (fingerprint, primes[i]) &&
							r_big_divisible_ut (fingerprint2, primes[i])) {
							r_big_div_ut (fingerprint, fingerprint, primes[i]);
							r_big_div_ut (fingerprint2, fingerprint2, primes[i]);
							p++;
							break;
						}
					if (i == NPRIMES)
						break;
				}
			} else {
				if (fcn->ninstr > fcn2->ninstr)
					p = fcn->ninstr;
				else p = fcn2->ninstr;
			}
			if (fcn->ninstr > fcn2->ninstr)
				t = (float)1-(float)(fcn->ninstr-p)/fcn->ninstr;
			else t = (float)1-(float)(fcn2->ninstr-p)/fcn2->ninstr;
#if 0
			printf ("FCN: %s - %s => %i - %i - %i => %f\n", fcn->name, fcn2->name,
					fcn->ninstr, fcn2->ninstr, p, t);
#endif 
			if (t > THRESHOLDFCN && t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
			}
		}
		if (mfcn != NULL && mfcn2 != NULL) {
			/* Diff basic blocks and remove matched functions */
#if 0
			printf ("Match => %s - %s\n", mfcn->name, mfcn2->name);
#endif
			if (ot == 1)
				mfcn->diff = mfcn2->diff = R_ANAL_DIFF_MATCH;
			else
				mfcn->diff = mfcn2->diff = R_ANAL_DIFF_UNMATCH;
			gdiff_diff_bb (mfcn, mfcn2, bbs, bbs2);
		}
	}

	r_big_free (fingerprint);
	r_big_free (fingerprint2);
}

R_API int r_core_gdiff(RCore *core, char *file1, char *file2, int va) {
	RCore *core2;
	RAnalFcn *fcn;
	RAnalBlock *bb;
	RList *fcns[2], *bbs[2];
	RListIter *iter;
	char cmd[1024], *files[2] = {file1, file2};
	int i;

	/* Init resources  */
	core2 = r_core_new ();

	for (i = 0; i < 2; i++) {
		/* Load and analyze bin*/
		if (!r_core_file_open (core2, files[i], 0)) {
			fprintf (stderr, "Cannot open file '%s'\n", files[i]);
			return R_FALSE;
		}
		r_config_set_i (core2->config, "io.va", va);
		sprintf (cmd, ".!rabin2 -rSIeMis%s %s", va?"v":"", files[i]);
		r_core_cmd0 (core2, cmd);
		/* XXX Select correct analysis plugin */
		r_core_cmd0 (core2, "ah x86_x86im");
		r_core_cmd0 (core2, "fs *");
		r_core_cmd0 (core2, "af @ entry0");
		r_core_cmd0 (core2, "af @ main");
		r_core_cmd0 (core2, "af @@ fcn.");
		r_core_cmd0 (core2, "ab @@ fcn.");
		/* Copy bb's and fcn's */
		bbs[i] = r_list_new ();
		bbs[i]->free = &r_anal_bb_free;
		iter = r_list_iterator (core2->anal->bbs);
		while (r_list_iter_next (iter)) {
			bb = r_list_iter_get (iter);
			r_list_split (core2->anal->bbs, bb);
			r_list_append (bbs[i], bb);
		}
		fcns[i] = r_list_new ();
		fcns[i]->free = &r_anal_fcn_free;
		iter = r_list_iterator (core2->anal->fcns);
		while (r_list_iter_next (iter)) {
			fcn = r_list_iter_get (iter);
			r_list_split (core2->anal->fcns, fcn);
			r_list_append (fcns[i], fcn);
		}
		/* Fingerprint bb's and fcn's */
		r_list_foreach (bbs[i], iter, bb)
			gdiff_fingerprint_bb (bb);
		r_list_foreach (fcns[i], iter, fcn)
			gdiff_fingerprint_fcn (bbs[i], fcn);
		/* Remove flags and analysis info */
		r_core_cmd0 (core2, "af-");
		r_core_cmd0 (core2, "ab-");
		r_core_cmd0 (core2, "f-*");
	}

	/* Diff functions */
	/* XXX Avoid dupped code diffing bb's directly? */
	gdiff_diff_fcn (fcns[0], fcns[1], bbs[0], bbs[1]);

	/* Fill analysis info in core */
	iter = r_list_iterator (bbs[0]);
	while (r_list_iter_next (iter)) {
		bb = r_list_iter_get (iter);
		r_anal_bb_add (core->anal, bb->addr, bb->size, bb->jump, bb->fail, bb->type, bb->diff);
	}
	iter = r_list_iterator (fcns[0]);
	while (r_list_iter_next (iter)) {
		fcn = r_list_iter_get (iter);
		r_anal_fcn_add (core->anal, fcn->addr, fcn->size, fcn->name, fcn->diff);
	}

	/* Free resources */
	r_core_free (core2);
	for (i=0;i<2;i++) {
		r_list_free (bbs[i]);
		r_list_free (fcns[i]);
	}

	return R_TRUE;
}
