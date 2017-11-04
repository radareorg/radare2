#include <experimental/x_m1.h>
#include <experimental/x_m1_private.h>

R_API void x_m1_init (RBinObject *o) {
	if (!(o && o->sections)) {
		return;
	}

	r_bin_x_f1 (o);
}

R_API void x_m1_fini (RBinObject *o) {
	if (!x_m1_status (o)) {
		return;
	}

	r_bin_x_f5 (o);
}

TEST_STATIC int x_m1_status (RBinObject *o) {
	if (o && o->sections && o->x_d1) {
		return true;
	}

	return false;
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

TEST_STATIC int r_bin_x_cmp1_less (RBinXS1 const *x, RBinXS1 const *y) {
	return x->off < y->off ||
	       x->off == y->off && x->start && y->start && x->s_id < y->s_id ||
	       x->off == y->off && !x->start && !y->start && x->s_id > y->s_id ||
	       x->off == y->off && x->start && !y->start;
}

TEST_STATIC int r_bin_x_cmp2 (RBinXS1 const *x, RBinXS1 const *y) {
	if (r_bin_x_cmp1_less (x, y)) {
		return -1;
	} else if (r_bin_x_cmp1_less (y, x)) {
		return 1;
	} else {
		return 0;
	}
}

TEST_STATIC void r_bin_x_f2 (RBinXS1 *b, int n, RBinXS3 **out, int *out_len) {
	int m = _r_bin_x_f2 (b, n, true, NULL, 0);

	_r_bin_x_f2 (b, n, false, out, m);

	if (out_len) {
		*out_len = m;
	}
}

TEST_STATIC int _r_bin_x_f2 (RBinXS1 *b, int n, int dry, RBinXS3 **out, int out_len) {
	RBinXS3 prev, cur, tmp;

	int res_len = 0;
	int i, o, c, w, x;
	int p1, p2, p3;

	prev.s = NULL;
	cur.s = NULL;
	tmp.s = NULL;
	prev.l = 0;
	cur.l = 0;
	tmp.l = 0;

	if (!dry) {
		*out = R_NEWS (RBinXS3, out_len);
	}

	for (i = 0; i < 2 * n; i = x) {
		o = 0;
		c = 0;
		w = -1;

		for (x = i; x < 2 * n && b[x].off == b[i].off; ++x) {
			if (b[x].start) {
				++o;
			} else {
				if (w == -1) {
					w = x;
				}

				++c;
			}
		}

		if (w == -1) {
			w = x;
		}

		prev = cur;

		tmp.l = prev.l + o;
		if (tmp.l != 0) {
			tmp.s = R_NEWS (int, tmp.l);
		}

		cur.off = b[i].off;
		cur.l = prev.l + o - c;
		if (cur.l != 0) {
			cur.s = R_NEWS (int, cur.l);
		} else {
			cur.s = NULL;
		}

		for (p1 = i, p2 = 0, p3 = 0; p1 < w || p2 < prev.l;) {
			if (p1 < w && p2 < prev.l) {
				if (b[p1].s_id <= prev.s[p2]) {
					tmp.s[p3] = b[p1].s_id;
					++p3;
					++p1;
				} else {
					tmp.s[p3] = prev.s[p2];
					++p3;
					++p2;
				}
			} else if (p1 < w) {
				tmp.s[p3] = b[p1].s_id;
				++p3;
				++p1;
			} else { //if (p2 < prev.l)
				tmp.s[p3] = prev.s[p2];
				++p3;
				++p2;
			}
		}

		for (p1 = w, p2 = tmp.l - 1, p3 = cur.l - 1; p1 < x || p2 >= 0;) {
			if (p1 < x && p2 >= 0) {
				if (b[p1].s_id != tmp.s[p2]) {
					cur.s[p3] = tmp.s[p2];
					--p3;
					--p2;
				} else {
					++p1;
					--p2;
				}
			} else if (p1 < x) {
				++p1;
			} else { // if (p2 >= 0)
				cur.s[p3] = tmp.s[p2];
				--p3;
				--p2;
			}
		}

		R_FREE (tmp.s);
		R_FREE (prev.s);
		tmp.l = 0;
		prev.l = 0;

		if (!dry) {
			(*out)[res_len].off = cur.off;
			(*out)[res_len].l = cur.l;
			if (cur.l) {
				(*out)[res_len].s = R_NEWS (int, cur.l);
				memcpy ((*out)[res_len].s, cur.s, sizeof (int) * cur.l);
			} else {
				(*out)[res_len].s = NULL;
			}
		}

		++res_len;
	}

	R_FREE (cur.s);
	cur.l = 0;

	return res_len;
}

TEST_STATIC int r_bin_x_f3 (RBinXS3 *c, int m, RBinXS4 **out) {
	RBinXS4 *d = NULL;
	int u = -1;
	int i;

	if (!out) {
		goto error;
	}

	if (m == 0 || m == 1) {
		goto error;
	}

	d = R_NEWS (RBinXS4, m - 1);

	for (i = 0; i < m - 1; ++i) {
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
	if (!(x_m1_status (o))) {
		return -1;
	}

	return va ? r_bin_object_a2b (o, s->vaddr) : s->paddr;
}

R_API ut64 r_bin_section_get_to_addr (RBinObject *o, RBinSection *s, int va) {
	if (!(x_m1_status (o))) {
		return -1;
	}

	return va ? (r_bin_object_a2b (o, s->vaddr) + s->vsize) : (s->paddr + s->size);
}

TEST_STATIC void r_bin_x_sort1_asc (void *b, void *e, int t_s, RBinXComp c) {
	int n = (e - b) / t_s;

	void *tmp = malloc (t_s);
	void *i, *j;

	for (i = e; i > b; i -= t_s) {
		for (j = b + t_s; j < i; j += t_s) {
			if (c (j, j - t_s) < 0) {
				memcpy (tmp, j, t_s);
				memcpy (j, j - t_s, t_s);
				memcpy (j - t_s, tmp, t_s);
			}
		}
	}

	R_FREE (tmp);
}

TEST_STATIC int r_bin_x_binary_search (void *b, void *e, int t_s, RBinXComp c, void *g) {
	int n = (e - b) / t_s;
	void *m;
	void *_b = b;
	void *_e = e;

	while (b + t_s < e) {
		m = b + ((e - b) / t_s / 2) * t_s;

		if (c (m, g) > 0) {
			e = m;
		} else {
			b = m;
		}
	}

	if (b + t_s == e && c (b, g) == 0) {
		return (b - _b) / t_s;
	}

	return -1;
}

TEST_STATIC void r_bin_x_f1 (RBinObject *o) {
	RListIter *iter;
	RBinSection *section;
	int va, n, i, m, u, k;
	RBinXS2 *a = NULL;
	RBinXS1 *b = NULL;
	RBinXS3 *c = NULL;
	RBinXS4 *d = NULL;

	if (!o) {
		return;
	}

	o->x_d1 = R_NEWS (RBinXS5, 2);

	for (va = 0; va <= 1; ++va) {
		n = o->sections->length;

		a = R_NEWS (RBinXS2, n);

		i = 0;
		r_list_foreach (o->sections, iter, section) {
			a[i].from = r_bin_section_get_from_addr (o, section, va);
			a[i].to = r_bin_section_get_to_addr (o, section, va);
			if (a[i].from > a[i].to) {
				a[i].from = a[i].to = -0x1;
			}
			a[i].s_id = i;
			++i;
		}

		b = R_NEWS (RBinXS1, 2 * n);

		for (i = 0; i < n; ++i) {
			b[2 * i].off = a[i].from;
			b[2 * i].start = true;
			b[2 * i].s_id = a[i].s_id;

			b[2 * i + 1].off = a[i].to;
			b[2 * i + 1].start = false;
			b[2 * i + 1].s_id = a[i].s_id;
		}

		// TODO(nartes): might be replaced with a quick sort, or
		// any RList sort we already have.
		r_bin_x_sort1_asc (b, b + 2 * n, sizeof (RBinXS1), (RBinXComp)r_bin_x_cmp2);

		c = NULL;
		r_bin_x_f2 (b, n, &c, &m);

		d = NULL;
		u = r_bin_x_f3 (c, m, &d);

		((RBinXS5 *)o->x_d1)[va].d = d;
		((RBinXS5 *)o->x_d1)[va].u = u;
		((RBinXS5 *)o->x_d1)[va].sections = NULL;
		((RBinXS5 *)o->x_d1)[va].lru = -1;

		R_FREE (a);
		R_FREE (b);
		for (k = 0; k < m; ++k) {
			R_FREE (c[k].s);
		}
		R_FREE (c);
	}
}

#ifdef TEST_STATIC
R_API int r_bin_x_cmp3_count;
#endif TEST_STATIC

TEST_STATIC int r_bin_x_cmp3 (RBinXS4 const *d, ut64 const *off) {
#ifdef TEST_STATIC
	++r_bin_x_cmp3_count;
#endif TEST_STATIC

	if (d->to <= *off) {
		return -1;
	} else if (d->from <= *off && *off < d->to) {
		return 0;
	} else { // if (*off < d->from)
		return 1;
	}
}

TEST_STATIC void r_bin_x_f6_bt (RBinXS5 *e, ut64 off, int va) {
	RBinXS4 *d = e[va].d;
	int u = e[va].u;
	int lru = e[va].lru;

#ifdef TEST_STATIC
	r_bin_x_cmp3_count = 0;
#endif TEST_STATIC

	if (lru != -1) {
		if (0 <= lru && lru < u && r_bin_x_cmp3 (&d[lru], &off) == 0) {
			// do nothing
		} else if (0 <= lru + 1 && lru + 1 < u && r_bin_x_cmp3 (&d[lru + 1], &off) == 0) {
			++lru;
		} else if (0 <= lru - 1 && lru - 1 < u && r_bin_x_cmp3 (&d[lru - 1], &off) == 0) {
			--lru;
		} else {
			lru = -1;
		}
	}

	if (lru == -1) {
		lru = r_bin_x_binary_search(d, d + u, sizeof(RBinXS4), r_bin_x_cmp3, &off);
	}

	if (lru != -1) {
		e[va].sections = &d[lru];
		e[va].lru = lru;
	} else {
		e[va].sections = NULL;
		e[va].lru = -1;
	}
}

TEST_STATIC RBinXS4 *r_bin_x_f8_get_all (RBinXS5 *e, int va) {
	return e[va].sections;
}

TEST_STATIC RBinSection *r_bin_x_f7_get_first (RBinObject *o, int va) {
	RBinXS5 *e = o->x_d1;
	RBinXS4 *d = r_bin_x_f8_get_all(e, va);

	if (d && d->l > 0) {
		return r_list_get_n (o->sections, d->s[0]);
	}

	return NULL;

}

// TODO: Move into section.c and rename it to r_io_section_get_at ()
R_API RBinSection *r_bin_get_section_at (RBinObject *o, ut64 off, int va) {
	RBinSection *res = NULL;

	if (x_m1_status (o)) {
		r_bin_x_f6_bt (o->x_d1, off, va);

		res = r_bin_x_f7_get_first (o, va);
	}

	return res;
}

TEST_STATIC void r_bin_x_f5 (RBinObject *o) {
	RBinXS5 **e = &o->x_d1;

	int va, k;

	for (va = 0; va <= 1; ++va) {
		RBinXS4 **d = &(*e)[va].d;
		for (k = 0; k < (*e)[va].u; ++k) {
			R_FREE ((*d)[k].s);
		}
		R_FREE ((*d));
	}

	R_FREE (o->x_d1);
}
