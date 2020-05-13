/* radare - LGPL - Copyright 2009-2020 - pancake, nibble */

#include <r_core.h>
#include <r_util.h>
#include <r_cons.h>

#define mid_down_refline(a, r) ((r)->from > (r)->to && (a) < (r)->from && (a) > (r)->to)
#define mid_up_refline(a, r) ((r)->from < (r)->to && (a) > (r)->from && (a) < (r)->to)
#define mid_refline(a, r) (mid_down_refline (a, r) || mid_up_refline (a, r))
#define in_refline(a, r) (mid_refline (a, r) || (a) == (r)->from || (a) == (r)->to)

typedef struct refline_end {
	int val;
	bool is_from;
	RAnalRefline *r;
} ReflineEnd;

static int cmp_asc(const struct refline_end *a, const struct refline_end *b) {
	return a->val > b->val;
}

static int cmp_by_ref_lvl(const RAnalRefline *a, const RAnalRefline *b) {
	return a->level < b->level;
}

static ReflineEnd *refline_end_new(ut64 val, bool is_from, RAnalRefline *ref) {
	ReflineEnd *re = R_NEW0 (struct refline_end);
	if (!re) {
		return NULL;
	}
	re->val = val;
	re->is_from = is_from;
	re->r = ref;
	return re;
}

static bool add_refline(RList *list, RList *sten, ut64 addr, ut64 to, int *idx) {
	ReflineEnd *re1, *re2;
	RAnalRefline *item = R_NEW0 (RAnalRefline);
	if (!item) {
		return false;
	}
	item->from = addr;
	item->to = to;
	item->index = *idx;
	item->level = -1;
	item->direction = (to > addr)? 1: -1;
	*idx += 1;
	r_list_append (list, item);

	re1 = refline_end_new (item->from, true, item);
	if (!re1) {
		free (item);
		return false;
	}
	r_list_add_sorted (sten, re1, (RListComparator)cmp_asc);

	re2 = refline_end_new (item->to, false, item);
	if (!re2) {
		free (re1);
		free (item);
		return false;
	}
	r_list_add_sorted (sten, re2, (RListComparator)cmp_asc);
	return true;
}

R_API void r_anal_reflines_free (RAnalRefline *rl) {
	free (rl);
}

/* returns a list of RAnalRefline for the code present in the buffer buf, of
 * length len. A RAnalRefline exists from address A to address B if a jmp,
 * conditional jmp or call instruction exists at address A and it targets
 * address B.
 *
 * nlines - max number of lines of code to consider
 * linesout - true if you want to display lines that go outside of the scope [addr;addr+len)
 * linescall - true if you want to display call lines */
R_API RList *r_anal_reflines_get(RAnal *anal, ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall) {
	RList *list, *sten;
	RListIter *iter;
	RAnalOp op;
	struct refline_end *el;
	const ut8 *ptr = buf;
	const ut8 *end = buf + len;
	ut8 *free_levels;
	int res, sz = 0, count = 0;
	ut64 opc = addr;

	memset (&op, 0, sizeof (op));
	/*
	 * 1) find all reflines
	 * 2) sort "from"s and "to"s in a list
	 * 3) traverse the list to find the minimum available level for each refline
	 *      * create a sorted list with available levels.
	 *      * when we encounter a previously unseen "from" or "to" of a
	 *        refline, we occupy the lowest level available for it.
	 *      * when we encounter the "from" or "to" of an already seen
	 *        refline, we free that level.
	 */

	list = r_list_newf (free);
	if (!list) {
		return NULL;
	}
	sten = r_list_newf ((RListFree)free);
	if (!sten) {
		goto list_err;
	}
	r_cons_break_push (NULL, NULL);
	/* analyze code block */
	while (ptr < end && !r_cons_is_breaked ()) {
		if (nlines != -1) {
			if (!nlines) {
				break;
			}
			nlines--;
		}
		if (anal->maxreflines && count > anal->maxreflines) {
			break;
		}
		addr += sz;
		{
			RPVector *metas = r_meta_get_all_at (anal, addr);
			if (metas) {
				void **it;
				ut64 skip = 0;
				r_pvector_foreach (metas, it) {
					RIntervalNode *node = *it;
					RAnalMetaItem *meta = node->data;
					switch (meta->type) {
					case R_META_TYPE_DATA:
					case R_META_TYPE_STRING:
					case R_META_TYPE_HIDE:
					case R_META_TYPE_FORMAT:
					case R_META_TYPE_MAGIC:
						skip = r_meta_node_size (node);
						goto do_skip;
					default:
						break;
					}
				}
do_skip:
				r_pvector_free (metas);
				if (skip) {
					ptr += skip;
					addr += skip;
					goto __next;
				}
			}
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, addr, 1)) {
			const int size = 4;
			ptr += size;
			addr += size;
			goto __next;
		}

		// This can segfault if opcode length and buffer check fails
		r_anal_op_fini (&op);
		sz = r_anal_op (anal, &op, addr, ptr, (int)(end - ptr), R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		sz = op.size;
		if (sz <= 0) {
			sz = 1;
			goto __next;
		}

		/* store data */
		switch (op.type) {
		case R_ANAL_OP_TYPE_CALL:
			if (!linescall) {
				break;
			}
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
			if ((!linesout && (op.jump > opc + len || op.jump < opc)) || !op.jump) {
				break;
			}
			if (!(res = add_refline (list, sten, addr, op.jump, &count))) {
				r_anal_op_fini (&op);
				goto sten_err;
			}
			// add false branch in case its set and its not a call, useful for bf, maybe others
			if (!op.delay && op.fail != UT64_MAX && op.fail != addr + op.size) {
				if (!(res = add_refline (list, sten, addr, op.fail, &count))) {
					r_anal_op_fini (&op);
					goto sten_err;
				}
			}
			break;
		case R_ANAL_OP_TYPE_SWITCH:
		{
			RAnalCaseOp *caseop;
			RListIter *iter;

			// add caseops
			if (!op.switch_op) {
				break;
			}
			r_list_foreach (op.switch_op->cases, iter, caseop) {
				if (!linesout && (op.jump > opc + len || op.jump < opc)) {
					goto __next;
				}
				if (!(res = add_refline (list, sten, op.switch_op->addr, caseop->jump, &count))) {
					r_anal_op_fini (&op);
					goto sten_err;
				}
			}
			break;
		}
		}
	__next:
		ptr += sz;
	}
	r_anal_op_fini (&op);
	r_cons_break_pop ();

	free_levels = R_NEWS0 (ut8, r_list_length (list) + 1);
	if (!free_levels) {
		goto sten_err;
	}
	int min = 0;

	r_list_foreach (sten, iter, el) {
		if ((el->is_from && el->r->level == -1) || (!el->is_from && el->r->level == -1)) {
			el->r->level = min + 1;
			free_levels[min] = 1;
			if (min < 0) {
				min = 0;
			}
			while (free_levels[++min] == 1) {
				;
			}
		} else {
			free_levels[el->r->level - 1] = 0;
			if (min > el->r->level - 1) {
				min = el->r->level - 1;
			}
		}
	}

	/* XXX: the algorithm can be improved. We can calculate the set of
	 * reflines used in each interval of addresses and store them.
	 * Considering r_anal_reflines_str is always called with increasing
	 * addresses, we can just traverse linearly the list of intervals to
	 * know which reflines need to be drawn for each address. In this way,
	 * we don't need to traverse again and again the reflines for each call
	 * to r_anal_reflines_str, but we can reuse the data already
	 * calculated. Those data will be quickly available because the
	 * intervals will be sorted and the addresses to consider are always
	 * increasing. */
	free (free_levels);
	r_list_free (sten);
	return list;

sten_err:
list_err:
	r_list_free (sten);
	r_list_free (list);
	return NULL;
}

R_API int r_anal_reflines_middle(RAnal *a, RList* /*<RAnalRefline>*/ list, ut64 addr, int len) {
	if (a && list) {
		RAnalRefline *ref;
		RListIter *iter;
		r_list_foreach (list, iter, ref) {
			if ((ref->to > addr) && (ref->to < addr + len)) {
				return true;
			}
		}
	}
	return false;
}

static const char* get_corner_char(RAnalRefline *ref, ut64 addr, bool is_middle_before) {
	if (ref->from == ref->to) {
		return "@";
	}
	if (addr == ref->to) {
		if (is_middle_before) {
			return (ref->from > ref->to) ? " " : "|";
		}
		return (ref->from > ref->to) ? "." : "`";
	}
	if (addr == ref->from) {
		if (is_middle_before) {
			return (ref->from > ref->to) ? "|" : " ";
		}
		return (ref->from > ref->to) ? "`" : ",";
	}
	return "";
}

static void add_spaces(RBuffer *b, int level, int pos, bool wide) {
	if (pos != -1) {
		if (wide) {
			pos *= 2;
			level *= 2;
		}
		if (pos > level + 1) {
			const char *pd = r_str_pad (' ', pos - level - 1);
			r_buf_append_string (b, pd);
		}
	}
}

static void fill_level(RBuffer *b, int pos, char ch, RAnalRefline *r, bool wide) {
	int sz = r->level;
	if (wide) {
		sz *= 2;
	}
	const char *pd = r_str_pad (ch, sz - 1);
	if (pos == -1) {
		r_buf_append_string (b, pd);
	} else {
		int pdlen = strlen (pd);
		if (pdlen > 0) {
			r_buf_write_at (b, pos, (const ut8 *)pd, pdlen);
		}
	}
}

static inline bool refline_kept(RAnalRefline *ref, bool middle_after, ut64 addr) {
	if (middle_after) {
		if (ref->direction < 0) {
			if (ref->from == addr) {
				return false;
			}
		} else {
			if (ref->to == addr) {
				return false;
			}
		}
	}
	return true;
}

// TODO: move into another file
// TODO: this is TOO SLOW. do not iterate over all reflines or gtfo
R_API RAnalRefStr *r_anal_reflines_str(void *_core, ut64 addr, int opts) {
	RCore *core = _core;
	RCons *cons = core->cons;
	RAnal *anal = core->anal;
	RBuffer *b;
	RBuffer *c;
	RListIter *iter;
	RAnalRefline *ref;
	int l;
	bool wide = opts & R_ANAL_REFLINE_TYPE_WIDE;
	int dir = 0, pos = -1, max_level = -1;
	bool middle_before = opts & R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE;
	bool middle_after = opts & R_ANAL_REFLINE_TYPE_MIDDLE_AFTER;
	char *str = NULL;
	char *col_str = NULL;

	r_return_val_if_fail (cons && anal && anal->reflines, NULL);

	RList *lvls = r_list_new ();
	if (!lvls) {
		return NULL;
	}
	r_list_foreach (anal->reflines, iter, ref) {
		if (core->cons && core->cons->context->breaked) {
			r_list_free (lvls);
			return NULL;
		}
		if (in_refline (addr, ref) && refline_kept (ref, middle_after, addr)) {
			r_list_add_sorted (lvls, (void *)ref, (RListComparator)cmp_by_ref_lvl);
		}
	}
	b = r_buf_new ();
	c = r_buf_new ();
	r_buf_append_string (c, " ");
	r_buf_append_string (b, " ");
	r_list_foreach (lvls, iter, ref) {
		if (core->cons && core->cons->context->breaked) {
			r_list_free (lvls);
			r_buf_free (b);
			r_buf_free (c);
			return NULL;
		}
		if ((ref->from == addr || ref->to == addr) && !middle_after) {
			const char *corner = get_corner_char (ref, addr, middle_before);
			const char ch = ref->from == addr ? '=' : '-';
			const char ch_col = ref->from >= ref->to ? 't': 'd';
			const char *col = (ref->from >= ref->to) ? "t" : "d";
			if (!pos) {
				int ch_pos = max_level + 1 - ref->level;
				if (wide) {
					ch_pos = ch_pos * 2 - 1;
				}
				r_buf_write_at (b, ch_pos, (ut8 *)corner, 1);
				r_buf_write_at (c, ch_pos, (ut8 *)col, 1);
				fill_level (b, ch_pos + 1, ch, ref, wide);
				fill_level (c, ch_pos + 1, ch_col, ref, wide);
			} else {
				add_spaces (b, ref->level, pos, wide);
				add_spaces (c, ref->level, pos, wide);
				r_buf_append_string (b, corner);
				r_buf_append_string (c, col);
				if (!middle_before) {
					fill_level (b, -1, ch, ref, wide);
					fill_level (c, -1, ch_col, ref, wide);
				}
			}
			if (!middle_before) {
				dir = ref->to == addr ? 1 : 2;
			}
			pos = middle_before ? ref->level : 0;
		} else {
			if (!pos) {
				continue;
			}
			add_spaces (b, ref->level, pos, wide);
			add_spaces (c, ref->level, pos, wide);
			if (ref->from >= ref->to) {
				r_buf_append_string (b, ":");
				r_buf_append_string (c, "t");
			} else {
				r_buf_append_string (b, "|");
				r_buf_append_string (c, "d");
			}
			pos = ref->level;
		}
		if (max_level == -1) {
			max_level = ref->level;
		}
	}
	add_spaces (c, 0, pos, wide);
	add_spaces (b, 0, pos, wide);
	str = r_buf_to_string (b);
	col_str = r_buf_to_string (c);
	r_buf_free (b);
	r_buf_free (c);
	b = NULL;
	c = NULL;
	if (!str || !col_str) {
		r_list_free (lvls);
		//r_buf_free_to_string already free b and if that is the case
		//b will be NULL and r_buf_free will return but if there was
		//an error we free b here so in other words is safe
		r_buf_free (b);
		r_buf_free (c);
		return NULL;
	}
	if (core->anal->lineswidth > 0) {
		int lw = core->anal->lineswidth;
		l = strlen (str);
		if (l > lw) {
			r_str_cpy (str, str + l - lw);
			r_str_cpy (col_str, col_str + l - lw);
		} else {
			char pfx[128];
			lw -= l;
			memset (pfx, ' ', sizeof (pfx));
			if (lw >= sizeof (pfx)) {
				lw = sizeof (pfx)-1;
			}
			if (lw > 0) {
				pfx[lw] = 0;
				str = r_str_prepend (str, pfx);
				col_str = r_str_prepend (col_str, pfx);
			}
		}
	}
	const char prev_col = col_str[strlen (col_str) - 1];
	const char *arr_col = prev_col == 't' ? "tt ": "dd ";
	str = r_str_append (str, (dir == 1) ? "-> "
		: (dir == 2) ? "=< " : "   ");
	col_str = r_str_append (col_str, arr_col);

	r_list_free (lvls);
	RAnalRefStr *out = R_NEW0 (RAnalRefStr);
	out->str = str;
	out->cols = col_str;
	return out;
}

R_API void r_anal_reflines_str_free(RAnalRefStr *refstr) {
	free (refstr->str);
	free (refstr->cols);
	free (refstr);
}
