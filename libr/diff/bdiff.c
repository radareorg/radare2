/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */
/* Adapted code from:

 bdiff.c - efficient binary diff extension for Mercurial

 Copyright 2005, 2006 Matt Mackall <mpm@selenic.com>

 This software may be used and distributed according to the terms of
 the GNU General Public License, incorporated herein by reference.

 Based roughly on Python difflib
*/

#include <r_util.h>
#include <r_diff.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct line {
	int h, len, n, e;
	const char *l;
};

struct pos {
	int pos, len;
};

struct hunk {
	int a1, a2, b1, b2;
};

struct hunklist {
	struct hunk *base, *head;
};

static int splitlines(const char *a, int len, struct line **lr) {
	int h, i;
	const char *p, *b = a;
	const char * const plast = a + len - 1;
	struct line *l;

	if (a == NULL) {
		eprintf ("null pointer received\n");
		return 0;
	}

	/* count the lines */
	i = 1; /* extra line for sentinel */
	for (p = a; p < a + len; p++)
		if (*p == '\n' || p == plast)
			i++;

	*lr = l = (struct line *)malloc(sizeof(struct line) * i);
	if (!l)
		return -1;

	/* build the line array and calculate hashes */
	h = 0;
	for (p = a; p < a + len; p++) {
		/* Leonid Yuriev's hash */
		h = (h * 1664525) + *p + 1013904223;

		if (*p == '\n' || p == plast) {
			l->h = h;
			h = 0;
			l->len = p - b + 1;
			l->l = b;
			l->n = INT_MAX;
			l++;
			b = p + 1;
		}
	}

	/* set up a sentinel */
	l->h = l->len = 0;
	l->l = a + len;
	return i - 1;
}

static int inline cmp(struct line *a, struct line *b) {
	return a->h != b->h || a->len != b->len || memcmp(a->l, b->l, a->len);
}

static int equatelines(struct line *a, int an, struct line *b, int bn) {
	int i, j, buckets = 1, t, scale;
	struct pos *h = NULL;

	/* build a hash table of the next highest power of 2 */
	while (buckets < bn + 1)
		buckets *= 2;

	/* try to allocate a large hash table to avoid collisions */
	for (scale = 4; scale; scale /= 2) {
		h = (struct pos *)malloc(scale * buckets * sizeof(struct pos));
		if (h)
			break;
	}

	if (!h)
		return 0;

	buckets = buckets * scale - 1;

	/* clear the hash table */
	for (i = 0; i <= buckets; i++) {
		h[i].pos = INT_MAX;
		h[i].len = 0;
	}

	/* add lines to the hash table chains */
	for (i = bn - 1; i >= 0; i--) {
		/* find the equivalence class */
		for (j = b[i].h & buckets; h[j].pos != INT_MAX;
		     j = (j + 1) & buckets)
			if (!cmp(b + i, b + h[j].pos))
				break;

		/* add to the head of the equivalence class */
		b[i].n = h[j].pos;
		b[i].e = j;
		h[j].pos = i;
		h[j].len++; /* keep track of popularity */
	}

	/* compute popularity threshold */
	t = (bn >= 4000) ? bn / 1000 : bn + 1;

	/* match items in a to their equivalence class in b */
	for (i = 0; i < an; i++) {
		/* find the equivalence class */
		for (j = a[i].h & buckets; h[j].pos != INT_MAX;
		     j = (j + 1) & buckets)
			if (!cmp(a + i, b + h[j].pos))
				break;

		a[i].e = j; /* use equivalence class for quick compare */
		if (h[j].len <= t)
			a[i].n = h[j].pos; /* point to head of match list */
		else
			a[i].n = INT_MAX; /* too popular */
	}

	/* discard hash tables */
	free(h);
	return 1;
}

static int longest_match(struct line *a, struct line *b, struct pos *pos,
			 int a1, int a2, int b1, int b2, int *omi, int *omj)
{
	int mi = a1, mj = b1, mk = 0, mb = 0, i, j, k;

	for (i = a1; i < a2; i++) {
		/* skip things before the current block */
		for (j = a[i].n; j < b1; j = b[j].n)
			;

		/* loop through all lines match a[i] in b */
		for (; j < b2; j = b[j].n) {
			/* does this extend an earlier match? */
			if (i > a1 && j > b1 && pos[j - 1].pos == i - 1)
				k = pos[j - 1].len + 1;
			else
				k = 1;
			pos[j].pos = i;
			pos[j].len = k;

			/* best match so far? */
			if (k > mk) {
				mi = i;
				mj = j;
				mk = k;
			}
		}
	}

	if (mk) {
		mi = mi - mk + 1;
		mj = mj - mk + 1;
	}

	/* expand match to include neighboring popular lines */
	while (mi - mb > a1 && mj - mb > b1 &&
	       a[mi - mb - 1].e == b[mj - mb - 1].e)
		mb++;
	while (mi + mk < a2 && mj + mk < b2 &&
	       a[mi + mk].e == b[mj + mk].e)
		mk++;

	*omi = mi - mb;
	*omj = mj - mb;

	return mk + mb;
}

static void recurse(struct line *a, struct line *b, struct pos *pos,
		    int a1, int a2, int b1, int b2, struct hunklist *l)
{
	int i, j, k;

	/* find the longest match in this chunk */
	k = longest_match(a, b, pos, a1, a2, b1, b2, &i, &j);
	if (!k)
		return;

	/* and recurse on the remaining chunks on either side */
	recurse(a, b, pos, a1, i, b1, j, l);
	l->head->a1 = i;
	l->head->a2 = i + k;
	l->head->b1 = j;
	l->head->b2 = j + k;
	l->head++;
	recurse(a, b, pos, i + k, a2, j + k, b2, l);
}

static struct hunklist diff(struct line *a, int an, struct line *b, int bn)
{
	struct hunklist l;
	struct hunk *curr;
	struct pos *pos;
	int t;

	/* allocate and fill arrays */
	t = equatelines(a, an, b, bn);
	pos = (struct pos *)calloc(bn ? bn : 1, sizeof(struct pos));
	/* we can't have more matches than lines in the shorter file */
	l.head = l.base = (struct hunk *)malloc(sizeof(struct hunk) *
	                                        ((an<bn ? an:bn) + 1));

	if (pos && l.base && t) {
		/* generate the matching block list */
		recurse(a, b, pos, 0, an, 0, bn, &l);
		l.head->a1 = l.head->a2 = an;
		l.head->b1 = l.head->b2 = bn;
		l.head++;
	}

	free(pos);

	/* normalize the hunk list, try to push each hunk towards the end */
	for (curr = l.base; curr != l.head; curr++) {
		struct hunk *next = curr+1;
		int shift = 0;

		if (next == l.head)
			break;

		if (curr->a2 == next->a1)
			while (curr->a2+shift < an && curr->b2+shift < bn
			       && !cmp(a+curr->a2+shift, b+curr->b2+shift))
				shift++;
		else if (curr->b2 == next->b1)
			while (curr->b2+shift < bn && curr->a2+shift < an
			       && !cmp(b+curr->b2+shift, a+curr->a2+shift))
				shift++;
		if (!shift)
			continue;
		curr->b2 += shift;
		next->b1 += shift;
		curr->a2 += shift;
		next->a1 += shift;
	}

	return l;
}

//--
// TODO: implement the r_diff_lines // we need to implement r_file_line_at (file, off);
R_API int r_diff_buffers_delta(RDiff *d, const ut8 *sa, int la, const ut8 *sb, int lb) {
	RDiffOp dop;
	struct line *al = NULL;
	struct line *bl = NULL;
	struct hunklist l = { NULL, NULL };
	struct hunk *h;
	int an, bn, offa, rlen, offb, len = 0;
	int hits = -1;

	an = splitlines ((const char *)sa, la, &al);
	if (an<0) {
		free (al);
		return -1;
	}
	bn = splitlines ((const char *)sb, lb, &bl);
	if (bn<0) {
		free (al);
		free (bl);
		return -1;
	}
	if (!al || !bl) {
		eprintf ("bindiff_buffers: Out of memory.\n");
		goto beach;
	}

	l = diff (al, an, bl, bn);
	if (!l.head) {
		eprintf ("bindiff_buffers: Out of memory.\n");
		goto beach;
	}

	hits = la = lb = 0;
	for (h = l.base; h != l.head; h++) {
		if (h->a1 != la || h->b1 != lb) {
			len = bl[h->b1].l - bl[lb].l;
			offa = al[la].l - al->l;
			offb = al[h->a1].l - al->l;
			rlen = offb-offa;

			if (d->callback) {
				/* source file */
				dop.a_off = offa;
				dop.a_buf = (ut8 *)al[la].l;
				dop.a_len = rlen;

				/* destination file */
				dop.b_off = offa; // XXX offb not used??
				dop.b_buf = (ut8 *)bl[lb].l;
				dop.b_len = len;
				if (!d->callback (d, d->user, &dop))
					break;
			}
#if 0	
			if (rlen > 0) {
				//printf ("Remove %d bytes at %d\n", rlen, offa);
				printf ("r-%d @ 0x%"PFMT64x"\n", rlen, (ut64)offa);
			}
			printf ("e file.write=true\n"); // XXX
			printf ("wx ");
			for(i=0;i<len;i++)
				printf ("%02x", bl[lb].l[i]);
			printf (" @ 0x%"PFMT64x"\n", (ut64)offa);
			rb += 12 + len;
#endif
		}
		la = h->a2;
		lb = h->b2;
	}
	beach:
	free (al);
	free (bl);
	free (l.base);

	return hits;
}
