/* radare - LGPL - Copyright 2009-2020 - pancake, nikolai */

#include <r_diff.h>

// the non-system-diff doesnt work well
#define USE_SYSTEM_DIFF 1


R_API RDiff *r_diff_new_from(ut64 off_a, ut64 off_b) {
	RDiff *d = R_NEW0 (RDiff);
	if (d) {
		d->delta = 1;
		d->user = NULL;
		d->off_a = off_a;
		d->off_b = off_b;
		d->diff_cmd = "diff -u";
	}
	return d;
}

R_API RDiff *r_diff_new(void) {
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

typedef struct {
	RDiff *d;
	char *str;
} RDiffUser;

#if USE_SYSTEM_DIFF
R_API char *r_diff_buffers_to_string(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	return r_diff_buffers_unified (d, a, la, b, lb);
}

#else
// XXX buffers_static doesnt constructs the correct string in this callback
static int tostring(RDiff *d, void *user, RDiffOp *op) {
	RDiffUser *u = (RDiffUser*)user;
	if (op->a_len > 0) {
		char *a_str = r_str_ndup ((const char *)op->a_buf + op->a_off, op->a_len);
		u->str = r_str_appendf (u->str, "+(%s)", a_str);
#if 0
		char *bufasm = r_str_prefix_all (a_str, "- ");
		u->str = r_str_appendf (u->str, "-(%s)", bufasm);
		free (bufasm);
#endif
		free (a_str);
	}
	if (op->b_len > 0) {
		char *b_str = r_str_ndup ((const char *)op->b_buf + op->b_off, op->b_len);
		u->str = r_str_appendf (u->str, "+(%s)", b_str);
#if 0
		char *bufasm = r_str_prefix_all (b_str, "+ ");
		u->str = r_str_appendf (u->str, "+(%s)", bufasm);
		free (bufasm);
#endif
		free (b_str);
	}
	if (op->a_len == op->b_len) {
		char *b_str = r_str_ndup ((const char *)op->a_buf + op->a_off, op->a_len);
		// char *bufasm = r_str_prefix_all (b_str, "  ");
		u->str = r_str_appendf (u->str, "%s", b_str);
		// free (bufasm);
		free (b_str);
	}
	return 1;
}

R_API char *r_diff_buffers_to_string(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	// XXX buffers_static doesnt constructs the correct string in this callback
	void *c = d->callback;
	void *u = d->user;
	RDiffUser du = {d, strdup ("")};
	d->callback = &tostring;
	d->user = &du;
	r_diff_buffers_static (d, a, la, b, lb);
	d->callback = c;
	d->user = u;
	return du.str;
}
#endif

#define diffHit(void) {\
	const size_t i_hit = i - hit;\
	int ra = la - i_hit;\
	int rb = lb - i_hit;\
	struct r_diff_op_t o = {\
		.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = R_MIN (hit, ra),\
		.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = R_MIN (hit, rb)\
	};\
	d->callback (d, d->user, &o);\
}

R_API int r_diff_buffers_static(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	int i, len;
	int hit = 0;
	la = R_ABS (la);
	lb = R_ABS (lb);
	if (la != lb) {
	 	len = R_MIN (la, lb);
		eprintf ("Buffer truncated to %d byte(s) (%d not compared)\n", len, R_ABS(lb-la));
	} else {
		len = la;
	}
	for (i = 0; i < len; i++) {
		if (a[i] != b[i]) {
			hit++;
		} else {
			if (hit > 0) {
				diffHit ();
				hit = 0;
			}
		}
	}
	if (hit > 0) {
		diffHit ();
	}
	return 0;
}

// XXX: temporary files are
R_API char *r_diff_buffers_unified(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	r_file_dump (".a", a, la, 0);
	r_file_dump (".b", b, lb, 0);
#if 0
	if (r_mem_is_printable (a, R_MIN (5, la))) {
		r_file_dump (".a", a, la, 0);
		r_file_dump (".b", b, lb, 0);
	} else {
		r_file_hexdump (".a", a, la, 0);
		r_file_hexdump (".b", b, lb, 0);
	}
#endif
	char* err = NULL;
	char* out = NULL;
	int out_len;
	char* diff_cmdline = r_str_newf ("%s .a .b", d->diff_cmd);
	if (diff_cmdline) {
		(void)r_sys_cmd_str_full (diff_cmdline, NULL, &out, &out_len, &err);
		free (diff_cmdline);
	}
	r_file_rm (".a");
	r_file_rm (".b");
	free (err);
	return out;
}

R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb) {
	return d->delta
		? r_diff_buffers_delta (d, a, la, b, lb)
		: r_diff_buffers_static (d, a, la, b, lb);
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

R_API bool r_diff_buffers_distance_levenshtein(RDiff *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	if (!a || !b) {
		return false;
	}

	const bool verbose = diff ? diff->verbose : false;
	const ut32 length = R_MAX (la, lb);
	const ut8 *ea = a + la, *eb = b + lb, *t;
	ut32 *d, i, j;
	// Strip prefix
	for (; a < ea && b < eb && *a == *b; a++, b++) {}
	// Strip suffix
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {}
	la = ea - a;
	lb = eb - b;
	if (la < lb) {
		i = la;
		la = lb;
		lb = i;
		t = a;
		a = b;
		b = t;
	}

	if (sizeof (ut32) > SIZE_MAX / (lb + 1) || !(d = malloc ((lb + 1) * sizeof (ut32)))) {
		return false;
	}
	for (i = 0; i <= lb; i++) {
		d[i] = i;
	}
	for (i = 0; i < la; i++) {
		ut32 ul = d[0];
		d[0] = i + 1;
		for (j = 0; j < lb; j++) {
			ut32 u = d[j + 1];
			d[j + 1] = a[i] == b[j] ? ul : R_MIN (ul, R_MIN (d[j], u)) + 1;
			ul = u;
		}
		if (verbose && i % 10000 == 0) {
			eprintf ("\rProcessing %" PFMT32u " of %" PFMT32u "\r", i, la);
		}
	}

	if (verbose) {
		eprintf ("\n");
	}
	if (distance) {
		*distance = d[lb];
	}
	if (similarity) {
		*similarity = length ? 1.0 - (double)d[lb] / length : 1.0;
	}
	free (d);
	return true;
}

R_API bool r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	if (d) {
		switch (d->type) {
		case 'm':
			return r_diff_buffers_distance_myers (d, a, la, b, lb, distance, similarity);
		case 'l':
		default:
			break;
		}
	}
	return r_diff_buffers_distance_levenshtein (d, a, la, b, lb, distance, similarity);
}

// Use Needleman–Wunsch to diffchar.
// This is an O(mn) algo in both space and time.
// Note that 64KB * 64KB * 2 = 8GB.
// TODO Discard common prefix and suffix
R_API RDiffChar *r_diffchar_new(const ut8 *a, const ut8 *b) {
	r_return_val_if_fail (a && b, NULL);
	RDiffChar *diffchar = R_NEW0 (RDiffChar);
	if (!diffchar) {
		return NULL;
	}

	const size_t len_a = strlen ((const char *)a);
	const size_t len_b = strlen ((const char *)b);
	const size_t len_long = len_a > len_b ? len_a : len_b;
	const size_t dim = len_long + 1;
	char *dup_a = malloc (len_long);
	char *dup_b = malloc (len_long);
	st16 *align_table = malloc (dim * dim * sizeof (st16));
	ut8 *align_a = malloc (2 * len_long);
	ut8 *align_b = malloc (2 * len_long);
	if (!(dup_a && dup_b && align_table && align_a && align_b)) {
		free (dup_a);
		free (dup_b);
		free (align_table);
		free (align_a);
		free (align_b);
		free (diffchar);
		return NULL;
	}

	snprintf (dup_a, len_long, "%s", a);
	a = (const ut8*)dup_a;
	snprintf (dup_b, len_long, "%s", b);
	b = (const ut8*)dup_b;

	// Fill table
	size_t row, col;
	*align_table = 0;
	for (row = 1; row < dim; row++) {
		// TODO Clamping [ST16_MIN + 1, .]
		*(align_table + row) = *(align_table + row * dim) = -(st16)row;
	}
	const st16 match = 1;
	const st16 match_nl = 2;
	const st16 mismatch = -2;
	const st16 gap = -1;
	for (row = 1; row < dim; row++) {
		for (col = 1; col < dim; col++) {
			// TODO Clamping [ST16_MIN + 1, ST16_MAX]
			const ut8 a_ch = a[col - 1];
			const ut8 b_ch = b[row - 1];
			const st16 tl_score = *(align_table + (row - 1) * dim + col - 1)
			                    + (a_ch == b_ch ?
			                       (a_ch == '\n' ? match_nl : match) :
			                       mismatch);
			const st16 t_score = *(align_table + (row - 1) * dim + col) + gap;
			const st16 l_score = *(align_table + row * dim + col - 1) + gap;
			st16 score;
			if (tl_score >= t_score && tl_score >= l_score) {
				score = tl_score;
			} else if (t_score >= tl_score && t_score >= l_score) {
				score = t_score;
			} else {
				score = l_score;
			}
			*(align_table + row * dim + col) = score;
		}
	}

#if 0
	// Print table (Debug)
	char char_str[3] = { ' ' };
	printf ("%4s ", char_str);
	for (col = 0; col < dim; col++) {
		if (col && a[col - 1] == '\n') {
			char_str[0] = '\\';
			char_str[1] = 'n';
		} else {
			char_str[0] = col ? a[col - 1] : ' ';
			char_str[1] = 0;
		}
		printf ("%4s ", char_str);
	}
	printf ("\n");
	for (row = 0; row < dim; row++) {
		if (row && b[row - 1] == '\n') {
			char_str[0] = '\\';
			char_str[1] = 'n';
		} else {
			char_str[0] = row ? b[row - 1] : ' ';
			char_str[1] = 0;
		}
		printf ("%4s ", char_str);
		for (col = 0; col < dim; col++) {
			printf ("%4d ", *(align_table + row * dim + col));
		}
		printf ("\n");
	}
#endif

	// Do alignment
	size_t idx_a = len_long - 1;
	size_t idx_b = len_long - 1;
	size_t idx_align = 2 * len_long - 1;
	size_t pos_row = dim - 1;
	size_t pos_col = dim - 1;
	while (pos_row || pos_col) {
		const st16 tl_score = (pos_row > 0 && pos_col > 0) ?
				*(align_table + (pos_row - 1) * dim + pos_col - 1) :
				ST16_MIN;
		const st16 t_score = pos_row > 0 ?
				*(align_table + (pos_row - 1) * dim + pos_col) :
				ST16_MIN;
		const st16 l_score = pos_col > 0 ?
				*(align_table + pos_row * dim + pos_col - 1) :
				ST16_MIN;
		const bool match = a[idx_a] == b[idx_b];
		if (t_score >= l_score && (!match || t_score >= tl_score)) {
			align_a[idx_align] = 0;
			align_b[idx_align] = b[idx_b--];
			idx_align--;
			pos_row--;
		} else if (l_score >= t_score && (!match || l_score >= tl_score)) {
			align_a[idx_align] = a[idx_a--];
			align_b[idx_align] = 0;
			idx_align--;
			pos_col--;
		} else {
			align_a[idx_align] = a[idx_a--];
			align_b[idx_align] = b[idx_b--];
			idx_align--;
			pos_row--;
			pos_col--;
		}
	}
	idx_align++;
	const size_t start_align = idx_align;

#if 0
	// Print alignment (Debug)
	for (; idx_align < 2 * len_long; idx_align++) {
		const ut8 ch = align_a[idx_align];
		if (align_b[idx_align] == '\n' && ch != '\n') {
			printf (ch ? " " : "-");
		}
		if (ch == 0) {
			printf ("-");
		} else if (ch == '\n') {
			printf ("\\n");
		} else {
			printf ("%c", ch);
		}
	}
	printf ("\n");
	for (idx_align = start_align; idx_align < 2 * len_long; idx_align++) {
		const ut8 ch = align_b[idx_align];
		if (align_a[idx_align] == '\n' && ch != '\n') {
			printf (ch ? " " : "-");
		}
		if (ch == 0) {
			printf ("-");
		} else if (ch == '\n') {
			printf ("\\n");
		} else {
			printf ("%c", ch);
		}
	}
	printf ("\n");
#endif

	diffchar->align_a = align_a;
	diffchar->align_b = align_b;
	diffchar->len_buf = len_long;
	diffchar->start_align = start_align;
	free (dup_a);
	free (dup_b);
	free (align_table);
	return diffchar;
}

typedef enum {
	R2R_ALIGN_MATCH, R2R_ALIGN_MISMATCH, R2R_ALIGN_TOP_GAP, R2R_ALIGN_BOTTOM_GAP
} R2RCharAlignment;

typedef enum {
	R2R_DIFF_MATCH, R2R_DIFF_DELETE, R2R_DIFF_INSERT
} R2RPrintDiffMode;

R_API void r_diffchar_print(RDiffChar *diffchar) {
	r_return_if_fail (diffchar);
	R2RPrintDiffMode cur_mode = R2R_DIFF_MATCH;
	R2RCharAlignment cur_align;
	size_t idx_align = diffchar->start_align;
	while (idx_align < 2 * diffchar->len_buf) {
		const ut8 a_ch = diffchar->align_a[idx_align];
		const ut8 b_ch = diffchar->align_b[idx_align];
		if (a_ch && !b_ch) {
			cur_align = R2R_ALIGN_BOTTOM_GAP;
		} else if (!a_ch && b_ch) {
			cur_align = R2R_ALIGN_TOP_GAP;
		} else if (a_ch != b_ch) {
			eprintf ("Internal error: mismatch detected!\n");
			cur_align = R2R_ALIGN_MISMATCH;
		} else {
			cur_align = R2R_ALIGN_MATCH;
		}
		if (cur_mode == R2R_DIFF_MATCH) {
			if (cur_align == R2R_ALIGN_MATCH) {
				if (a_ch) {
					printf ("%c", a_ch);
				}
			} else if (cur_align == R2R_ALIGN_BOTTOM_GAP) {
				printf (a_ch == '\n' ?
				        "%c"Color_HLDELETE :
				        Color_HLDELETE"%c", a_ch);
				cur_mode = R2R_DIFF_DELETE;
			} else if (cur_align == R2R_ALIGN_TOP_GAP) {
				printf (b_ch == '\n' ?
				        "%c"Color_HLINSERT :
				        Color_HLINSERT"%c", b_ch);
				cur_mode = R2R_DIFF_INSERT;
			}
		} else if (cur_mode == R2R_DIFF_DELETE) {
			if (cur_align == R2R_ALIGN_MATCH) {
				printf (Color_RESET);
				if (a_ch) {
					printf ("%c", a_ch);
				}
				cur_mode = R2R_DIFF_MATCH;
			} else if (cur_align == R2R_ALIGN_BOTTOM_GAP) {
				printf (a_ch == '\n' ?
				        Color_RESET"%c"Color_HLDELETE :
				        "%c", a_ch);
			} else if (cur_align == R2R_ALIGN_TOP_GAP) {
				printf (b_ch == '\n' ?
				        Color_RESET"%c"Color_HLINSERT :
				        Color_HLINSERT"%c", b_ch);
				cur_mode = R2R_DIFF_INSERT;
			}
		} else if (cur_mode == R2R_DIFF_INSERT) {
			if (cur_align == R2R_ALIGN_MATCH) {
				printf (Color_RESET);
				if (a_ch) {
					printf ("%c", a_ch);
				}
				cur_mode = R2R_DIFF_MATCH;
			} else if (cur_align == R2R_ALIGN_BOTTOM_GAP) {
				printf (a_ch == '\n' ?
				        Color_RESET"%c"Color_HLDELETE :
				        Color_HLDELETE"%c", a_ch);
				cur_mode = R2R_DIFF_DELETE;
			} else if (cur_align == R2R_ALIGN_TOP_GAP) {
				printf (b_ch == '\n' ?
				        Color_RESET"%c"Color_HLINSERT :
				        "%c", b_ch);
			}
		}
		idx_align++;
	}
	printf (Color_RESET"\n");
}

R_API void r_diffchar_free(RDiffChar *diffchar) {
	if (diffchar) {
		free ((ut8 *)diffchar->align_a);
		free ((ut8 *)diffchar->align_b);
		free (diffchar);
	}
}
