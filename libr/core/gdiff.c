/* radare - LGPL - Copyright 2010-2022 - nibble, pancake */

#include <r_core.h>

R_API int r_core_gdiff_fcn(RCore *c, ut64 addr, ut64 addr2) {
	RAnalFunction *fa = r_anal_get_function_at (c->anal, addr);
	RAnalFunction *fb = r_anal_get_function_at (c->anal, addr2);
	if (!fa || !fb) {
		return false;
	}
	RAnalBlock *bb;
	RListIter *iter;
	r_list_foreach (fa->bbs, iter, bb) {
		r_anal_diff_fingerprint_bb (c->anal, bb);
	}
	r_list_foreach (fb->bbs, iter, bb) {
		r_anal_diff_fingerprint_bb (c->anal, bb);
	}
#if 0
	RList *la = r_list_new ();
	r_list_append (la, fa);
	r_anal_diff_fcn (c->anal, la, la);
	r_list_free (la);
#else
	RList *la = r_list_new ();
	r_list_append (la, fa);
	RList *lb = r_list_new ();
	r_list_append (lb, fb);
	r_anal_diff_fcn (c->anal, la, lb);
	r_list_free (la);
	r_list_free (lb);
#endif
	return true;
}

/* Fingerprint functions and blocks, then diff. */
R_API bool r_core_gdiff(RCore *c, RCore *c2) {
	RCore *cores[2] = {c, c2};
	RAnalFunction *fcn;
	RAnalBlock *bb;
	RListIter *iter, *iter2;
	int i;

	if (!c || !c2) {
		return false;
	}
	if (c == c2) {
		eprintf ("sama\n");
		return false;
	}
	for (i = 0; i < 2; i++) {
		/* remove strings */
		r_list_foreach_safe (cores[i]->anal->fcns, iter, iter2, fcn) {
			if (r_str_startswith (fcn->name, "str.")) {
				r_anal_function_delete (fcn);
			}
		}
		/* Fingerprint fcn bbs (functions basic-blocks) */
		r_list_foreach (cores[i]->anal->fcns, iter, fcn) {
			r_list_foreach (fcn->bbs, iter2, bb) {
				r_anal_diff_fingerprint_bb (cores[i]->anal, bb);
			}
		}
		/* Fingerprint fcn */
		r_list_foreach (cores[i]->anal->fcns, iter, fcn) {
			r_anal_diff_fingerprint_fcn (cores[i]->anal, fcn);
		}
	}
	/* Diff functions */
	r_anal_diff_fcn (cores[0]->anal, cores[0]->anal->fcns, cores[1]->anal->fcns);

	return true;
}

/* copypasta from radiff2 */
/// XXX use cb_printf and pass instance
static void diffrow(ut64 addr, const char *name, ut32 size, int maxnamelen,
		int digits, ut64 addr2, const char *name2, ut32 size2,
		const char *match, double dist, int bare) {
	if (bare) {
		if (addr2 == UT64_MAX || !name2) {
			printf ("0x%016"PFMT64x" |%8s  (%f)\n", addr, match, dist);
		} else {
			printf ("0x%016"PFMT64x" |%8s  (%f) | 0x%016"PFMT64x"\n", addr, match, dist, addr2);
		}
	} else {
		if (addr2 == UT64_MAX || !name2) {
			printf ("%*s %*d 0x%"PFMT64x" |%8s  (%f)\n",
				maxnamelen, name, digits, size, addr, match, dist);
		} else {
			printf ("%*s %*d 0x%"PFMT64x" |%8s  (%f) | 0x%"PFMT64x"  %*d %s\n",
				maxnamelen, name, digits, size, addr, match, dist, addr2,
				digits, size2, name2);
		}
	}
}

R_API void r_core_diff_show(RCore *c, RCore *c2) {
	bool bare = r_config_get_i (c->config, "diff.bare") || r_config_get_i (c2->config, "diff.bare");
	RList *fcns = r_anal_get_fcns (c->anal);
	const char *match;
	RListIter *iter;
	RAnalFunction *f;
	int maxnamelen = 0;
	ut64 maxsize = 0;
	int digits = 1;
	int len;

	r_list_foreach (fcns, iter, f) {
		if (f->name && (len = strlen (f->name)) > maxnamelen) {
			maxnamelen = len;
		}
		if (r_anal_function_linear_size (f) > maxsize) {
			maxsize = r_anal_function_linear_size (f);
		}
	}
	fcns = r_anal_get_fcns (c2->anal);
	r_list_foreach (fcns, iter, f) {
		if (f->name && (len = strlen (f->name)) > maxnamelen) {
			maxnamelen = len;
		}
		if (r_anal_function_linear_size (f) > maxsize) {
			maxsize = r_anal_function_linear_size (f);
		}
	}
	while (maxsize > 9) {
		maxsize /= 10;
		digits++;
	}

	fcns = r_anal_get_fcns (c->anal);
	if (r_list_empty (fcns)) {
		R_LOG_ERROR ("No functions found, try running with -A or load a project");
		return;
	}
	r_list_sort (fcns, c->anal->columnSort);

	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			switch (f->diff->type) {
			case R_ANAL_DIFF_TYPE_MATCH:
				match = "MATCH";
				break;
			case R_ANAL_DIFF_TYPE_UNMATCH:
				match = "UNMATCH";
				break;
			default:
				match = "NEW";
				f->diff->dist = 0;
			}
			diffrow (f->addr, f->name, r_anal_function_linear_size (f), maxnamelen, digits,
							f->diff->addr, f->diff->name, f->diff->size,
							match, f->diff->dist, bare);
			break;
		}
	}
	fcns = r_anal_get_fcns (c2->anal);
	r_list_sort (fcns, c2->anal->columnSort);
	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			if (f->diff->type == R_ANAL_DIFF_TYPE_NULL) {
				diffrow (f->addr, f->name, r_anal_function_linear_size (f), maxnamelen,
									digits, f->diff->addr, f->diff->name, f->diff->size,
									"NEW", 0, bare); //f->diff->dist, bare);
			}
			break;
		}
	}
}

/* Iterate available diffs and print json output */
R_API void r_core_diff_show_json(RCore *c, RCore *c2) {
	const char *match;
	RListIter *iter;
	RAnalFunction *f;

	RList *fcns = r_anal_get_fcns (c->anal);
	if (r_list_empty (fcns)) {
		R_LOG_ERROR ("No functions found, try running with -A or load a project");
		return;
	}
	PJ *pj = r_core_pj_new (c);
	if (!pj) {
		return;
	}
	pj_a (pj);

	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			switch (f->diff->type) {
			case R_ANAL_DIFF_TYPE_MATCH:
				match = "MATCH";
				break;
			case R_ANAL_DIFF_TYPE_UNMATCH:
				match = "UNMATCH";
				break;
			default:
				match = "NEW";
				f->diff->dist = 0;
			}

			pj_o (pj);
			pj_kn (pj, "addr", f->addr);
			pj_ks (pj, "name", f->name? f->name: "");
			pj_kn (pj, "size", r_anal_function_linear_size (f));
			pj_kn (pj, "diff_addr", f->diff->addr);
			pj_ks (pj, "diff_name", f->diff->name? f->diff->name: "");
			pj_kn (pj, "diff_size", f->diff->size);
			pj_ks (pj, "match", match);
			pj_kd (pj, "dist", f->diff->dist);
			pj_end (pj);
			break;
		}
	}

	fcns = r_anal_get_fcns (c2->anal);
	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			if (f->diff->type == R_ANAL_DIFF_TYPE_NULL) {
				pj_o (pj);
				pj_kn (pj, "addr", f->addr);
				pj_ks (pj, "name", f->name? f->name: "");
				pj_kn (pj, "size", r_anal_function_linear_size (f));
				pj_ks (pj, "match", "NEW");
				pj_kd (pj, "dist", 0);
				pj_end (pj);
			}
			break;
		}
	}

	pj_end (pj);

	char *s = pj_drain (pj);
	printf ("%s\n", s);
	free (s);
}
