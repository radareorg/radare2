/* radare - LGPL - Copyright 2009-2016 - pancake, nibble */

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

	list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = free;
	sten = r_list_new ();
	if (!sten) {
		goto list_err;
	}
	sten->free = (RListFree)free;

	/* analyze code block */
	while (ptr < end) {
		if (nlines != -1) {
			if (!nlines) {
				break;
			}
			nlines--;
		}
		{
			const RAnalMetaItem *mi = r_meta_find (anal, addr, R_META_TYPE_ANY, 0);
			if (mi) {
				ptr += mi->size;
				addr += mi->size;
				continue;
			}
		}
		if (anal->maxreflines && count > anal->maxreflines) {
			break;
		}

		addr += sz;
		// This can segfault if opcode length and buffer check fails
		r_anal_op_fini (&op);
		sz = r_anal_op (anal, &op, addr, ptr, (int)(end - ptr));
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
					continue;
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
			while (free_levels[++min] == 1);
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

R_API RList*r_anal_reflines_fcn_get(RAnal *anal, RAnalFunction *fcn, int nlines, int linesout, int linescall) {
	RList *list;
	RAnalRefline *item;
	RAnalBlock *bb;
	RListIter *bb_iter;

	int index = 0;
	ut32 len;

	list = r_list_new ();
	if (!list) return NULL;

	/* analyze code block */
	r_list_foreach (fcn->bbs, bb_iter, bb) {
		if (!bb || !bb->size) {
			continue;
		}
		if (nlines != -1 && !--nlines) {
			break;
		}
		len = bb->size;
		/* store data */
		ut64 control_type = bb->type;
		control_type &= R_ANAL_BB_TYPE_SWITCH | R_ANAL_BB_TYPE_JMP | R_ANAL_BB_TYPE_COND | R_ANAL_BB_TYPE_CALL;

		// handle call
		if (!linescall) {
			if ((control_type & R_ANAL_BB_TYPE_CALL) == R_ANAL_BB_TYPE_CALL) {
				continue;
			}
		}
		// Handles conditonal + unconditional jump
		if ( (control_type & R_ANAL_BB_TYPE_CJMP) == R_ANAL_BB_TYPE_CJMP) {
			// dont need to continue here is opc+len exceed function scope
			if (linesout && bb->fail > 0LL && bb->fail != bb->addr + len) {
				item = R_NEW0 (RAnalRefline);
				if (!item) {
					r_list_free (list);
					return NULL;
				}
				item->from = bb->addr;
				item->to = bb->fail;
				item->index = index++;
				r_list_append (list, item);
			}
		}
		if ((control_type & R_ANAL_BB_TYPE_JMP) == R_ANAL_BB_TYPE_JMP) {
			if (!linesout || !bb->jump || bb->jump == bb->addr + len) {
				continue;
			}
			item = R_NEW0 (RAnalRefline);
			if (!item) {
				r_list_free (list);
				return NULL;
			}
			item->from = bb->addr;
			item->to = bb->jump;
			item->index = index++;
			r_list_append (list, item);
			continue;
		}

		// XXX - Todo test handle swith op
		if (control_type & R_ANAL_BB_TYPE_SWITCH) {
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					if (caseop) {
						if (!linesout) {// && (op.jump > opc+len || op.jump < pc)) 
							continue;
						}
						item = R_NEW0 (RAnalRefline);
						if (!item){
							r_list_free (list);
							return NULL;
						}
						item->from = bb->switch_op->addr;
						item->to = caseop->jump;
						item->index = index++;
						r_list_append (list, item);
					}
				}
			}
		}
	}
	return list;
}

R_API int r_anal_reflines_middle(RAnal *a, RList* /*<RAnalRefline>*/ list, ut64 addr, int len) {
	if (a && list) {
		RAnalRefline *ref;
		RListIter *iter;
		r_list_foreach (list, iter, ref) {
			if ((ref->to > addr) && (ref->to < addr+len))
				return true;
		}
	}
	return false;
}

static const char* get_corner_char(RAnalRefline *ref, ut64 addr, int is_middle) {
	if (addr == ref->to) {
		if (is_middle) {
			return (ref->from > ref->to) ? " " : "|";
		}
		return (ref->from > ref->to) ? "." : "`";
	} else if (addr == ref->from) {
		if (is_middle) {
			return (ref->from > ref->to) ? "|" : " ";
		}
		return (ref->from > ref->to) ? "`" : ",";
	}

	return "";
}

static void add_spaces(RBuffer *b, int level, int pos, int wide) {
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

static void fill_level(RBuffer *b, int pos, char ch, RAnalRefline *r, int wide) {
	const char *pd;
	int sz = r->level;
	if (wide) {
		sz *= 2;
	}
	pd = r_str_pad (ch, sz - 1);
	if (pos == -1) {
		r_buf_append_string (b, pd);
	} else {
		r_buf_write_at (b, pos, (ut8 *)pd, strlen (pd));
	}
}

// TODO: move into another file
// TODO: this is TOO SLOW. do not iterate over all reflines or gtfo
R_API char* r_anal_reflines_str(void *_core, ut64 addr, int opts) {
	RCore *core = _core;
	RCons *c = core->cons;
	RAnal *anal = core->anal;
	RBuffer *b;
	RListIter *iter;
	RAnalRefline *ref;
	int l;
	int dir = 0, wide = opts & R_ANAL_REFLINE_TYPE_WIDE;
	int pos = -1, max_level = -1;
	int middle = opts & R_ANAL_REFLINE_TYPE_MIDDLE;
	char *str = NULL;

	if (!c || !anal || !anal->reflines) {
		return NULL;
	}

	RList *lvls = r_list_new ();
	if (!lvls) {
		return NULL;
	}
	r_list_foreach (anal->reflines, iter, ref) {
		if (core->cons && core->cons->breaked) {
			r_list_free (lvls);
			return NULL;
		}
		if (in_refline (addr, ref)) {
			r_list_add_sorted (lvls, (void *)ref, (RListComparator)cmp_by_ref_lvl);
		}
	}
	b = r_buf_new ();
	r_buf_append_string (b, " ");
	r_list_foreach (lvls, iter, ref) {
		if (core->cons && core->cons->breaked) {
			r_list_free (lvls);
			r_buf_free (b);
			return NULL;
		}
		if (ref->from == addr || ref->to == addr) {
			const char *corner = get_corner_char (ref, addr, middle);
			const char ch = ref->from == addr ? '=' : '-';

			if (!pos) {
				int ch_pos = max_level + 1 - ref->level;
				if (wide) {
					ch_pos = ch_pos * 2 - 1;
				}
				r_buf_write_at (b, ch_pos, (ut8 *)corner, 1);
				fill_level (b, ch_pos + 1, ch, ref, wide);
			} else {
				add_spaces (b, ref->level, pos, wide);
				r_buf_append_string (b, corner);
				if (!middle) {
					fill_level (b, -1, ch, ref, wide);
				}
			}
			if (!middle) {
				dir = ref->to == addr ? 1 : 2;
			}
			pos = middle ? ref->level : 0;
		} else {
			if (!pos) {
				continue;
			}
			add_spaces (b, ref->level, pos, wide);
			r_buf_append_string (b, "|");
			pos = ref->level;
		}
		if (max_level == -1) {
			max_level = ref->level;
		}
	}
	add_spaces (b, 0, pos, wide);
	str = r_buf_free_to_string (b);
	if (!str) {
		r_list_free (lvls);
		//r_buf_free_to_string already free b and if that is the case
		//b will be NULL and r_buf_free will return but if there was 
		//an error we free b here 
		r_buf_free (b);
		return NULL;
	}
	if (core->anal->lineswidth > 0) {
		int lw = core->anal->lineswidth;
		l = strlen (str);
		if (l > lw) {
			r_str_cpy (str, str + l - lw);
		} else {
			char pfx[128];
			lw -= l;
			memset (pfx, ' ', sizeof (pfx));
			if (lw >= sizeof (pfx)) {
				lw = sizeof (pfx)-1;
			}
			if (lw > 0) {
				pfx[lw] = 0;
				str = r_str_prefix (str, pfx);
			}
		}
	}
	str = r_str_concat (str, (dir == 1) ? "-> "
		: (dir == 2) ? "=< " : "   ");

	if (core->cons->use_utf8 || opts & R_ANAL_REFLINE_TYPE_UTF8) {
		str = r_str_replace (str, "<", c->vline[ARROW_LEFT], 1);
		str = r_str_replace (str, ">", c->vline[ARROW_RIGHT], 1);
		str = r_str_replace (str, "!", c->vline[LINE_UP], 1);
		str = r_str_replace (str, "|", c->vline[LINE_VERT], 1);
		str = r_str_replace (str, "=", c->vline[LINE_HORIZ], 1);
		str = r_str_replace (str, "-", c->vline[LINE_HORIZ], 1);
		str = r_str_replace (str, ",", c->vline[CORNER_TL], 1);
		str = r_str_replace (str, ".", c->vline[CORNER_TR], 1);
		str = r_str_replace (str, "`", c->vline[CORNER_BL], 1);
	}
	r_list_free (lvls);
	return str;
}
