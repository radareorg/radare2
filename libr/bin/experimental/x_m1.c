#include <experimental/x_m1.h>
#include <experimental/x_m1_private.h>

R_API void x_m1_init (RBinObject *o) {
	if (!(o && o->sections)) {
		return;
	}

	r_bin_x_f1 (o);
}

R_API void x_m1_fini (RBinObject *o) {
	if (!(o && o->sections && o->x_d1)) {
		return;
	}

	r_bin_x_f5 (o);
}

// section {
// 	int from, to;
// }

// event {
// 	int off;
// 	bool is_start;
// 	int s_id;
// }

// segment_event {
// 	int off;
// 	bool is_start;
// 	list<int> s_ids;
// }

// vector<event> b;
//
// vector<section> a;
//
// list<segment_event> c;

// void func() {
// 	vector<section> a;
//
//	for (s in a) {
//		b.push({a.from, true, &a})
//		b.push({a.to, false, &a})
//	}
//
// 	sort(b, [x, y] {
// 		return x.off < y.off ||
// 		       x.off == y.off && x.start && y.start && x.s_id < y.s_id ||
// 		       x.off == y.off && !x.start && !y.start && x.s_id > y.s_id ||
// 		       x.off == y.off && x.start && !y.start;
// 	})
//
// }

// The procedure generates a sequence per addressing scheme (either virtual or
// physical). The list is sorted, all segments are disjoint. Each segment
// has a list of associated sections. The sections are in the order
// of the initial sections list.

static int r_bin_x_cmp1 (RBinXS1 const *x, RBinXS1 const *y) {
	return x->off < y->off ||
	       x->off == y->off && x->start && y->start && x->s_id < y->s_id ||
	       x->off == y->off && !x->start && !y->start && x->s_id > y->s_id ||
	       x->off == y->off && x->start && !y->start;
}

static int r_bin_x_cmp2_less (RBinXS1 const *x, RBinXS1 const *y) {
	if (r_bin_x_cmp1 (x, y)) {
		return -1;
	} else if (r_bin_x_cmp1 (y, x)) {
		return 1;
	} else {
		return 0;
	}
}

static void r_bin_x_f2 (RBinXS1 *b, int n, RBinXS3 **out, int *out_len) {
	int m = _r_bin_x_f2 (b, n, true, NULL, 0);

	_r_bin_x_f2 (b, n, false, out, m);

	if (out_len) {
		*out_len = m;
	}
}

static int _r_bin_x_f2 (RBinXS1 *b, int n, int dry, RBinXS3 **out, int out_len) {
	RBinXS3 prev, cur, tmp;

	int res_len = 0;

	prev.s = NULL;
	cur.s = NULL;
	tmp.s = NULL;
	prev.l = 0;
	cur.l = 0;
	tmp.l = 0;

	if (!dry) {
		*out = R_NEWS (RBinXS3, out_len);
	}

	for (int i = 0; i < 2 * n; ++i) {
		int x, o = 0, c = 0, w = i;

		for (x = i; x < 2 * n || b[x].off != b[i].off; ++x) {
			if (b[x].start) {
				++o;
			} else {
				w = x;
				++c;
			}
		}

		prev = cur;

		tmp.s = R_NEWS (int, prev.l + o);
		tmp.l = prev.l + o;

		cur.off = b[i].off;
		cur.s = R_NEWS (int, prev.l + o - c);
		cur.l = prev.l + o - c;

		for (int p1 = i, p2 = 0, p3 = 0; p1 < w || p2 < tmp.l;) {
			if (p1 < w && p2 < tmp.l) {
				if (b[p1].s_id <= prev.s[p2]) {
					tmp.s[p3++] = b[p1++].s_id;
				} else {
					tmp.s[p3++] = prev.s[p2++];
				}
			} else if (p1 < w) {
				tmp.s[p3++] = b[p1++].s_id;
			} else { //if (p2 < tmp.l)
				tmp.s[p3++] = prev.s[p2++];
			}
		}

		for (int p1 = x - 1, p2 = tmp.l - 1, p3 = 0; p1 >= w || p2 >= 0;) {
			if (p1 >= w && p2 >= 0) {
				if (b[p1].s_id != tmp.s[p2]) {
					cur.s[p3++] = tmp.s[p2++];
				} else {
					++p1;
					++p2;
				}
			} else if (p1 >= w) {
				++p1;
			} else { // if (p2 >= 0)
				cur.s[p3++] = tmp.s[p2++];
			}
		}

		R_FREE (tmp.s);
		R_FREE (prev.s);
		tmp.l = 0;
		prev.l = 0;

		if (!dry) {
			(*out)[res_len].off = cur.off;
			(*out)[res_len].l = cur.l;
			(*out)[res_len].s = R_NEWS (int, cur.l);
			memcpy ((*out)[res_len].s, cur.s, sizeof (int) * cur.l);
		}

		++res_len;
	}

	R_FREE (cur.s);
	cur.l = 0;

	return res_len;
}

static int r_bin_x_f3 (RBinXS3 *c, int m, RBinXS4 **out) {
	RBinXS4 *d = NULL;
	int u = -1;

	if (!out) {
		goto error;
	}

	if (m == 0 || m == 1) {
		goto error;
	}

	d = R_NEWS (RBinXS4, m - 1);

	for (int i = 0; i < m - 1; ++i) {
		d[i].from = c[i].off;
		d[i].to = c[i + 1].off;
		d[i].l = c[i].l;
		d[i].s = R_NEWS (int, c[i].l);
		memcpy (d[i].s, c[i].s, sizeof (int) * c[i].l);
	}

	u = m - 1;

	(*out) = d;
error:

	return u;
}

R_API ut64 r_bin_section_get_from_addr (RBinObject *o, RBinSection *s, int va) {
	return va ? r_bin_object_a2b (o, s->vaddr) : s->paddr;
}

R_API ut64 r_bin_section_get_to_addr (RBinObject *o, RBinSection *s, int va) {
	return va ? (r_bin_object_a2b (o, s->vaddr) + s->vsize) : (s->paddr + s->size);
}

static void r_bin_x_f1 (RBinObject *o) {
	RListIter *iter;
	RBinSection *section;

	if (!o) {
		return;
	}

	o->x_d1 = R_NEWS (RBinXS5, 2);

	for (int va = 0; va <= 1; ++va) {
		int n = o->sections->length;

		RBinXS2 *a = R_NEWS (RBinXS2, n);

		int i = 0;
		r_list_foreach (o->sections, iter, section) {
			a[i].from = r_bin_section_get_from_addr (o, section, va);
			a[i].to = r_bin_section_get_to_addr (o, section, va);
			a[i].s_id = i;
			++i;
		}

		RBinXS1 *b = R_NEWS (RBinXS1, 2 * n);

		for (int i = 0; i < n; ++i) {
			b[2 * i].off = a[i].from;
			b[2 * i].start = true;
			b[2 * i].s_id = a[i].s_id;

			b[2 * i + 1].off = a[i].to;
			b[2 * i + 1].start = false;
			b[2 * i + 1].s_id = a[i].s_id;
		}

		// TODO(nartes): might be replaced with a quick sort, or
		// any RList sort we already have.
		for (int i = 1; i < 2 * n; ++i) {
			for (int j = i; j < 2 * n; ++j) {
				if (r_bin_x_cmp2_less (&b[j], &b[j - 1]) > 0) {
					RBinXS1 tmp;
					memcpy (&tmp, &b[j], sizeof (tmp));
					memcpy (&b[j], &b[j - 1], sizeof (tmp));
					memcpy (&b[j - 1], &tmp, sizeof (tmp));
				}
			}
		}

		int m;
		RBinXS3 *c = NULL;
		r_bin_x_f2 (b, n, &c, &m);

		RBinXS4 *d = NULL;
		int u = r_bin_x_f3 (c, m, &d);

		((RBinXS5 *)o->x_d1)[va].d = d;
		((RBinXS5 *)o->x_d1)[va].u = u;

		R_FREE (a);
		R_FREE (b);
		for (int k = 0; k < m; ++k) {
			R_FREE (c[k].s);
		}
		R_FREE (c);
	}
}

static void r_bin_x_f6_bt (RBinObject *o, ut64 off, int va) {
	RBinXS5 * e = o->x_d1;
	RBinXS4 * d = e[va].d;
	int u = e[va].u;

	e[va].sections = NULL;

	for (int k = 0; k < u; ++k) {
		if (d[k].from <= off && off < d[k].to) {
			e[va].sections = &d[k];
		}
	}
}

static RBinSection *r_bin_x_f7_get_first (RBinObject *o, int va) {
	RBinXS5 * e = o->x_d1;
	RBinXS4 * d = e[va].sections;

	if (!d) {
		return NULL;
	}

	return r_list_get_n(o->sections, d->s[0]);
}

// TODO: Move into section.c and rename it to r_io_section_get_at ()
R_API RBinSection *r_bin_get_section_at (RBinObject *o, ut64 off, int va) {
	RBinSection *res = NULL;

	if (o) {
		r_bin_x_f6_bt(o, off, va);

		res = r_bin_x_f7_get_first (o, va);
	}

	return res;
}

static void r_bin_x_f5 (RBinObject *o) {
	RBinXS5 **e = &o->x_d1;

	for (int va = 0; va <= 1; ++va) {
		RBinXS4 **d = &(*e)[va].d;
		for (int k = 0; k < (*e)[va].u; ++k) {
			R_FREE ((*d)[k].s);
		}
		R_FREE ((*d));
	}

	R_FREE (o->x_d1);
}
