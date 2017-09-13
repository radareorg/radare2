/* radare - LGPL - Copyright 2009-2017 - pancake, nikolai */

#include <r_diff.h>

R_API RDiff *r_diff_new_from(ut64 off_a, ut64 off_b) {
	RDiff *d = R_NEW0 (RDiff);
	if (d) {
		d->delta = 1;
		d->user = NULL;
		d->off_a = off_a;
		d->off_b = off_b;
	}
	return d;
}

R_API RDiff *r_diff_new() {
	return r_diff_new_from (0, 0);
}

R_API RDiff *r_diff_free(RDiff *d) {
	free (d);
	return NULL;
}

R_API int r_diff_set_callback(RDiff *d, RDiffCallback callback, void *user) {
	d->callback = callback;
	d->user = user;
	return 1;
}

R_API int r_diff_set_delta(RDiff *d, int delta) {
	d->delta = delta;
	return 1;
}

R_API int r_diff_buffers_static(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	int i, len;
	int hit = 0;
	la = R_ABS (la);
	lb = R_ABS (lb);
	if (la != lb) {
	 	len = R_MIN(la, lb);
		eprintf ("Buffer truncated to %d bytes (%d not compared)\n", len, R_ABS(lb-la));
	} else {
		len = la;
	}
	for (i = 0; i < len; i++) {
		if (a[i] != b[i]) {
			hit++;
		} else {
			if (hit > 0) {
				int ra = la - (i - hit);
				int rb = lb - (i - hit);
				struct r_diff_op_t o = {
					.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = R_MIN (hit, ra),
					.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = R_MIN (hit, rb)
				};
				d->callback (d, d->user, &o);
				hit = 0;
			}
		}
	}
	if (hit > 0) {
		int ra = la - (i - hit);
		int rb = lb - (i - hit);
		struct r_diff_op_t o = {
			.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = R_MIN (hit, ra),
			.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = R_MIN (hit, rb)
		};
		d->callback (d, d->user, &o);
		hit = 0;
	}
	return 0;
}

// XXX: temporary files are
R_API int r_diff_buffers_unified(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	if (r_mem_is_printable (a, R_MIN (5, la))) {
		r_file_dump (".a", a, la, 0);
		r_file_dump (".b", b, lb, 0);
	} else {
		r_file_hexdump (".a", a, la, 0);
		r_file_hexdump (".b", b, lb, 0);
	}
	r_sys_cmd ("diff -ru .a .b");
	r_file_rm (".a");
	r_file_rm (".b");
	return 0;
}

R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb) {
	if (d->delta) {
		return r_diff_buffers_delta (d, a, la, b, lb);
	}
	return r_diff_buffers_static (d, a, la, b, lb);
}

// Eugene W. Myers' O(ND) diff algorithm
// Returns edit distance with costs: insertion=1, deletion=1, no substitution
R_API bool r_diff_buffers_distance_myers(RDiff *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	const bool verbose = diff ? diff->verbose: false;
	if (!a || !b) {
		return false;
	}
	const ut32 length = la + lb;
	const ut8 *ea = a + la, *eb = b + lb;
	// Strip prefix
	for (; a < ea && b < eb && *a == *b; a++, b++) {}
	// Strip suffix
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {}
	la = ea - a;
	lb = eb - b;
	ut32 *v0, *v;
	st64 m = (st64)la + lb, di = 0, low, high, i, x, y;
	if (m + 2 > SIZE_MAX / sizeof (st64) || !(v0 = malloc ((m + 2) * sizeof (ut32)))) {
		return false;
	}
	v = v0 + lb;
	v[1] = 0;
	for (di = 0; di <= m; di++) {
		low = -di + 2 * R_MAX (0, di - (st64)lb);
		high = di - 2 * R_MAX (0, di - (st64)la);
		for (i = low; i <= high; i += 2) {
			x = i == -di || (i != di && v[i-1] < v[i+1]) ? v[i+1] : v[i-1] + 1;
			y = x - i;
			while (x < la && y < lb && a[x] == b[y]) {
				x++;
				y++;
			}
			v[i] = x;
			if (x == la && y == lb) {
				goto out;
			}
		}
		if (verbose && di % 10000 == 0) {
			eprintf ("\rProcessing dist %" PFMT64d " of max %" PFMT64d "\r", di, m);
		}
	}

out:
	if (verbose) {
		eprintf ("\n");
	}
	free (v0);
	//Clean up output on loop exit (purely aesthetic)
	if (distance) {
		*distance = di;
	}
	if (similarity) {
		*similarity = length ? 1.0 - (double)di / length : 1.0;
	}
	return true;
}

R_API bool r_diff_buffers_distance_original(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	int i, j, tmin, **m;
	ut64 totalsz = 0;

	if (!a || !b || la < 1 || lb < 1)
		return false;

	if (la == lb && !memcmp (a, b, la)) {
		if (distance != NULL)
			*distance = 0;
		if (similarity != NULL)
			*similarity = 1.0;
		return true;
	}
	totalsz = sizeof(int*) * (lb+1);
	for(i = 0; i <= la; i++) {
		totalsz += ((lb+1) * sizeof(int));
	}
	if (totalsz >= 1024 * 1024 * 1024) { // 1 GB of ram
		char *szstr = r_num_units (NULL, totalsz);
		eprintf ("Too much memory required (%s) to run distance diff, Use -c.\n", szstr);
		free (szstr);
		return false;
	}
	if ((m = malloc ((la+1) * sizeof(int*))) == NULL)
		return false;
	for(i = 0; i <= la; i++) {
		if ((m[i] = malloc ((lb+1) * sizeof(int))) == NULL) {
			eprintf ("Allocation failed\n");
			while (i--)
				free (m[i]);
			free (m);
			return false;
		}
	}

	for (i = 0; i <= la; i++)
		m[i][0] = i;
	for (j = 0; j <= lb; j++)
		m[0][j] = j;

	for (i = 1; i <= la; i++) {
		for (j = 1; j <= lb; j++) {
			int cost = (a[i-1] != b[j-1])? 1: 0;
			tmin = R_MIN (m[i-1][j] + 1, m[i][j-1] + 1);
			m[i][j] = R_MIN (tmin, m[i-1][j-1] + cost);
		}
	}

	if (distance) {
		*distance = m[la][lb];
	}
	if (similarity) {
		*similarity = (double)1 - (double)(m[la][lb])/(double)(R_MAX(la, lb));
	}

	for(i = 0; i <= la; i++) {
		free (m[i]);
	}
	free (m);

	return true;
}

R_API bool r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	if (d && d->levenstein) {
		return r_diff_buffers_distance_original (d, a, la, b, lb, distance, similarity);
	}
	return r_diff_buffers_distance_myers (d, a, la, b, lb, distance, similarity);
}
