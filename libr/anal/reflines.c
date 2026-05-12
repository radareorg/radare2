/* radare - LGPL - Copyright 2009-2025 - pancake, nibble */

#include <r_core.h>

#define mid_down_refline(a, r) ((r)->from > (r)->to && (a) < (r)->from && (a) > (r)->to)
#define mid_up_refline(a, r) ((r)->from < (r)->to && (a) > (r)->from && (a) < (r)->to)
#define mid_refline(a, r) (mid_down_refline (a, r) || mid_up_refline (a, r))
#define in_refline(a, r) (mid_refline (a, r) || (a) == (r)->from || (a) == (r)->to)

typedef struct refline_end {
	ut64 val;
	size_t order;
	bool is_from;
	RAnalRefline *r;
} ReflineEnd;

typedef struct refline_event_t {
	ut64 addr;
	RAnalRefline *r;
} ReflineEvent;

R_VEC_TYPE (RVecReflineEnd, ReflineEnd);
R_VEC_TYPE (RVecReflineEvent, ReflineEvent);
R_VEC_TYPE (RVecAnalReflinePtr, RAnalRefline *);

typedef struct refline_cache_t {
	RVecReflineEvent starts;
	RVecReflineEvent ends;
	RVecAnalReflinePtr active;
	size_t next_start;
	size_t next_end;
	ut64 last_addr;
	int refs;
	bool active_valid;
} ReflineCache;

typedef struct refline_item_t {
	RAnalRefline ref;
	ReflineCache *cache;
} ReflineItem;

static int cmp_asc(const struct refline_end *a, const struct refline_end *b) {
	int cmp = (a->val > b->val) - (a->val < b->val);
	if (cmp) {
		return cmp;
	}
	return (a->order < b->order) - (a->order > b->order);
}

static int cmp_by_ref_lvl(const RAnalRefline *a, const RAnalRefline *b) {
	return (a->level < b->level) - (a->level > b->level);
}

static int cmp_refline_event(const ReflineEvent *a, const ReflineEvent *b) {
	int cmp = (a->addr > b->addr) - (a->addr < b->addr);
	if (cmp) {
		return cmp;
	}
	return (a->r->index > b->r->index) - (a->r->index < b->r->index);
}

static int cmp_refline_event_addr(const ReflineEvent *a, const ReflineEvent *b) {
	return (a->addr > b->addr) - (a->addr < b->addr);
}

static int cmp_ref_ptr_level(RAnalRefline * const *a, RAnalRefline * const *b) {
	int cmp = cmp_by_ref_lvl (*a, *b);
	if (cmp) {
		return cmp;
	}
	return ((*a)->index > (*b)->index) - ((*a)->index < (*b)->index);
}

static int cmp_ref_ptr_find_level(RAnalRefline * const *a, const void *b) {
	RAnalRefline *ref = (RAnalRefline *)b;
	int cmp = cmp_by_ref_lvl (*a, ref);
	if (cmp) {
		return cmp;
	}
	return ((*a)->index > ref->index) - ((*a)->index < ref->index);
}

static inline ut64 refline_start(const RAnalRefline *ref) {
	return R_MIN (ref->from, ref->to);
}

static inline ut64 refline_end(const RAnalRefline *ref) {
	return R_MAX (ref->from, ref->to);
}

static ReflineCache *refline_cache_new(void) {
	ReflineCache *cache = R_NEW0 (ReflineCache);
	RVecReflineEvent_init (&cache->starts);
	RVecReflineEvent_init (&cache->ends);
	RVecAnalReflinePtr_init (&cache->active);
	cache->last_addr = UT64_MAX;
	return cache;
}

static void refline_cache_free(ReflineCache *cache) {
	if (cache) {
		RVecReflineEvent_fini (&cache->starts);
		RVecReflineEvent_fini (&cache->ends);
		RVecAnalReflinePtr_fini (&cache->active);
		free (cache);
	}
}

static void refline_item_free(void *p) {
	ReflineItem *item = p;
	if (item && item->cache && --item->cache->refs < 1) {
		refline_cache_free (item->cache);
	}
	free (item);
}

static bool refline_vec_insert_sorted(RVecAnalReflinePtr *vec, RAnalRefline *ref) {
	RAnalRefline *refp = ref;
	size_t index = RVecAnalReflinePtr_lower_bound (vec, &refp, cmp_ref_ptr_level);
	RAnalRefline **slot = RVecAnalReflinePtr_emplace_back (vec);
	RAnalRefline **dst = R_VEC_START_ITER (vec) + index;
	memmove (dst + 1, dst, (slot - dst) * sizeof (RAnalRefline *));
	*dst = ref;
	return true;
}

static bool refline_active_insert(ReflineCache *cache, RAnalRefline *ref) {
	return refline_vec_insert_sorted (&cache->active, ref);
}

static void refline_active_remove(ReflineCache *cache, RAnalRefline *ref) {
	size_t index = RVecAnalReflinePtr_find_sorted_index (&cache->active, ref, cmp_ref_ptr_find_level);
	if (index != SZT_MAX) {
		RVecAnalReflinePtr_remove (&cache->active, index);
	}
}

static bool refline_cache_build(ReflineCache *cache, RList *list) {
	RAnalRefline *ref;
	RListIter *iter;

	if (!RVecReflineEvent_reserve (&cache->starts, r_list_length (list)) ||
		!RVecReflineEvent_reserve (&cache->ends, r_list_length (list))) {
		return false;
	}
	r_list_foreach (list, iter, ref) {
		ReflineEvent *start = RVecReflineEvent_emplace_back (&cache->starts);
		ReflineEvent *end = RVecReflineEvent_emplace_back (&cache->ends);
		start->addr = refline_start (ref);
		start->r = ref;
		end->addr = refline_end (ref);
		end->r = ref;
	}
	RVecReflineEvent_sort (&cache->starts, cmp_refline_event);
	RVecReflineEvent_sort (&cache->ends, cmp_refline_event);
	return true;
}

static ReflineCache *refline_cache_from_list(RList *list) {
	if (r_list_empty (list)) {
		return NULL;
	}
	ReflineItem *item = list->head->data;
	return item? item->cache: NULL;
}

static void refline_list_set_cache(RList *list, ReflineCache *cache) {
	ReflineItem *item;
	RListIter *iter;

	r_list_foreach (list, iter, item) {
		item->cache = cache;
	}
}

static RVecAnalReflinePtr *refline_cache_refs_at(ReflineCache *cache, ut64 addr) {
	ReflineEvent event = {
		.addr = addr
	};
	size_t i;

	if (!cache->active_valid || addr < cache->last_addr) {
		RVecAnalReflinePtr_clear (&cache->active);
		cache->next_start = RVecReflineEvent_upper_bound (&cache->starts, &event, cmp_refline_event_addr);
		cache->next_end = RVecReflineEvent_lower_bound (&cache->ends, &event, cmp_refline_event_addr);
		for (i = 0; i < cache->next_start; i++) {
			ReflineEvent *start = RVecReflineEvent_at (&cache->starts, i);
			if (refline_end (start->r) >= addr && !refline_active_insert (cache, start->r)) {
				return NULL;
			}
		}
		cache->active_valid = true;
	} else if (addr > cache->last_addr) {
		while (cache->next_end < RVecReflineEvent_length (&cache->ends)) {
			ReflineEvent *end = RVecReflineEvent_at (&cache->ends, cache->next_end);
			if (end->addr >= addr) {
				break;
			}
			refline_active_remove (cache, end->r);
			cache->next_end++;
		}
		while (cache->next_start < RVecReflineEvent_length (&cache->starts)) {
			ReflineEvent *start = RVecReflineEvent_at (&cache->starts, cache->next_start);
			if (start->addr > addr) {
				break;
			}
			if (refline_end (start->r) >= addr && !refline_active_insert (cache, start->r)) {
				return NULL;
			}
			cache->next_start++;
		}
	}
	cache->last_addr = addr;
	return &cache->active;
}

static bool add_refline(RList *list, RVecReflineEnd *sten, ReflineCache *cache, ut64 addr, ut64 to, int *idx, int type, int splitmode) {
	if (splitmode) {
		if (splitmode > 0) {
			if (addr > to) {
				return true;
			}
		} else {
			if (addr < to) {
				return true;
			}
		}
	}
	ReflineItem *item = R_NEW0 (ReflineItem);
	RAnalRefline *ref = &item->ref;
	ref->from = addr;
	ref->to = to;
	ref->index = *idx;
	ref->level = -1;
	ref->type = type;
	ref->direction = (to > addr)? 1: -1;
	item->cache = cache;

	ReflineEnd *re1 = RVecReflineEnd_emplace_back (sten);
	re1->val = ref->from;
	re1->order = RVecReflineEnd_length (sten) - 1;
	re1->is_from = true;
	re1->r = ref;

	ReflineEnd *re2 = RVecReflineEnd_emplace_back (sten);
	re2->val = ref->to;
	re2->order = RVecReflineEnd_length (sten) - 1;
	re2->is_from = false;
	re2->r = ref;

	*idx += 1;
	r_list_append (list, item);
	cache->refs++;
	return true;
}

R_API void r_anal_reflines_free(RAnalRefline *rl) {
	free (rl);
}

/* returns a list of RAnalRefline for the code present in the buffer buf, of
 * length len. A RAnalRefline exists from address A to address B if a jmp,
 * conditional jmp or call instruction exists at address A and it targets
 * address B.
 *
 * nlines - max number of lines of code to consider
 * linesout - true if you want to display lines that go outside of the scope [addr;addr+len)
 * linescall - true if you want to display call lines
 * splitmode - 0, -1, 1 */
R_API RList *r_anal_reflines_get(RAnal *anal, ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall, int splitmode) {
	RAnalOp op = { 0 };
	struct refline_end *el;
	const ut8 *ptr = buf;
	const ut8 *end = buf + len;
	ut8 *free_levels;
	int sz = 0, count = 0;
	ut64 opc = addr;
	RCore *core = anal->coreb.core;
	RCons *cons = core->cons;

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

	RList *list = r_list_newf (refline_item_free);
	if (!list) {
		return NULL;
	}
	ReflineCache *cache = refline_cache_new ();
	RVecReflineEnd sten;
	RVecReflineEnd_init (&sten);
	r_cons_break_push (cons, NULL, NULL);
	/* analyze code block */
	while (ptr < end && !r_cons_is_breaked (cons)) {
		if (nlines != -1) {
			if (!nlines) {
				break;
			}
			nlines--;
		}
		if (anal->maxreflines && count > anal->maxreflines) {
			break;
		}
		ut64 skip = 0;
		ut64 bind_addr = 0;
		addr += sz;
		{
			RVecIntervalNodePtr *metas = r_meta_get_all_at (anal, addr);
			if (metas) {
				RIntervalNode **it;
				R_VEC_FOREACH (metas, it) {
					RIntervalNode *node = *it;
					RAnalMetaItem *meta = node->data;
					switch (meta->type) {
					case R_META_TYPE_BIND:
						bind_addr = r_num_math (NULL, meta->str);
						break;
					case R_META_TYPE_DATA:
					case R_META_TYPE_STRING:
					case R_META_TYPE_HIDE:
					case R_META_TYPE_FORMAT:
					case R_META_TYPE_MAGIC:
						skip = r_meta_node_size (node);
						// goto doskip;
						break;
					default:
						break;
					}
				}
				// doskip:
				RVecIntervalNodePtr_free (metas);
				if (skip) {
					ptr += skip;
					addr += skip;
					goto __next;
				}
			}
		}
		if (bind_addr != 0 && bind_addr != UT64_MAX) {
			if (!add_refline (list, &sten, cache, addr, bind_addr, &count, 'b', splitmode)) {
				r_anal_op_fini (&op);
				goto sten_err;
			}
			bind_addr = UT64_MAX;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, addr, 1)) {
			const int size = 4;
			ptr += size;
			addr += size;
			goto __next;
		}

		// This can segfault if opcode length and buffer check fails
		r_anal_op_fini (&op);
		int rc = r_anal_op (anal, &op, addr, ptr, (int) (end - ptr), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
		if (rc <= 0) {
			sz = 1;
			goto __next;
		}
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
			if (op.jump == UT64_MAX) {
				break;
			}
			if ((!linesout && (op.jump > opc + len || op.jump < opc)) || !op.jump) {
				break;
			}
			if (!add_refline (list, &sten, cache, addr, op.jump, &count, 'j', splitmode)) {
				r_anal_op_fini (&op);
				goto sten_err;
			}
			// add false branch in case its set and its not a call, useful for bf, maybe others
			if (!op.delay && op.fail != UT64_MAX && op.fail != addr + op.size) {
				if (!add_refline (list, &sten, cache, addr, op.fail, &count, 'f', splitmode)) {
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
					if (!add_refline (list, &sten, cache, op.switch_op->addr, caseop->jump, &count, 'j', splitmode)) {
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
	r_cons_break_pop (cons);

	free_levels = R_NEWS0 (ut8, r_list_length (list) + 1);
	int min = 0;

	RVecReflineEnd_sort (&sten, cmp_asc);
	R_VEC_FOREACH (&sten, el) {
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

	if (r_list_empty (list)) {
		refline_cache_free (cache);
	} else if (!refline_cache_build (cache, list)) {
		refline_list_set_cache (list, NULL);
		refline_cache_free (cache);
	}
	free (free_levels);
	RVecReflineEnd_fini (&sten);
	return list;

sten_err:
	r_anal_op_fini (&op);
	r_cons_break_pop (cons);
	RVecReflineEnd_fini (&sten);
	if (cache->refs < 1) {
		refline_cache_free (cache);
	}
	r_list_free (list);
	return NULL;
}

R_API int r_anal_reflines_middle(RAnal *a, RList * /*<RAnalRefline>*/ list, ut64 addr, int len) {
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

static inline const char *colchar(RAnalRefline *ref) {
	return (ref->type == 'b')? "!": "|";
}

static const char *get_corner_char(RAnalRefline *ref, ut64 addr, bool is_middle_before) {
	if (ref->from == ref->to) {
		return "@";
	}
	if (addr == ref->to) {
		if (is_middle_before) {
			return (ref->from > ref->to)? " ": colchar (ref);
		}
		return (ref->from > ref->to)? ".": "`";
	}
	if (addr == ref->from) {
		if (is_middle_before) {
			return (ref->from > ref->to)? colchar (ref): " ";
		}
		return (ref->from > ref->to)? "`": ",";
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
			int count = R_MIN (pos - level - 1, 255);
			char padbuf[256];
			r_str_pad (padbuf, sizeof (padbuf), ' ', count);
			r_buf_append_bytes (b, (ut8 *)padbuf, count);
		}
	}
}

static void fill_level(RBuffer *b, int pos, char ch, RAnalRefline *r, bool wide) {
	int sz = r->level;
	if (wide) {
		sz *= 2;
	}
	int count = R_MAX (0, R_MIN (sz - 1, 255));
	if (count > 0) {
		char padbuf[256];
		r_str_pad (padbuf, sizeof (padbuf), ch, count);
		if (pos == -1) {
			r_buf_append_bytes (b, (ut8 *)padbuf, count);
		} else {
			r_buf_write_at (b, pos, (ut8 *)padbuf, count);
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

static const char *arrowbydir(int dir) {
	return (dir == 1)? "-> ": (dir == 2)? "=< "
					: "   ";
}

R_API RAnalRefStr *r_anal_reflines_str(void *_core, ut64 addr, int opts) {
	RCore *core = _core;
	R_RETURN_VAL_IF_FAIL (core && core->anal, NULL);
	RConsContext *ctx = core->cons->context;
	RAnal *anal = core->anal;
	RListIter *iter;
	RAnalRefline *ref;
	RAnalRefline **refp;
	int l;
	bool wide = opts & R_ANAL_REFLINE_TYPE_WIDE;
	int dir = 0, pos = -1, max_level = -1;
	bool middle_before = opts & R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE;
	bool middle_after = opts & R_ANAL_REFLINE_TYPE_MIDDLE_AFTER;
	bool split_mode = opts & R_ANAL_REFLINE_TYPE_SPLIT;
	char *str = NULL;
	char *col_str = NULL;
#if 0
	if (!anal->reflines) {
		return NULL;
	}
#endif
	RList *reflines = split_mode? anal->reflines2: anal->reflines;
	RVecAnalReflinePtr tmp_lvls;
	RVecAnalReflinePtr *lvls = NULL;
	bool free_lvls = false;
	ReflineCache *cache = refline_cache_from_list (reflines);

	if (cache) {
		lvls = refline_cache_refs_at (cache, addr);
		if (!lvls) {
			return NULL;
		}
	} else {
		RVecAnalReflinePtr_init (&tmp_lvls);
		free_lvls = true;
		r_list_foreach (reflines, iter, ref) {
			if (ctx->breaked) {
				RVecAnalReflinePtr_fini (&tmp_lvls);
				return NULL;
			}
			if (in_refline (addr, ref)) {
				if (!refline_vec_insert_sorted (&tmp_lvls, ref)) {
					RVecAnalReflinePtr_fini (&tmp_lvls);
					return NULL;
				}
			}
		}
		lvls = &tmp_lvls;
	}
	RBuffer *b = r_buf_new ();
	RBuffer *c = r_buf_new ();
	r_buf_append_string (c, " ");
	r_buf_append_string (b, " ");
	R_VEC_FOREACH (lvls, refp) {
		ref = *refp;
		if (ctx->breaked) {
			if (free_lvls) {
				RVecAnalReflinePtr_fini (&tmp_lvls);
			}
			r_unref (b);
			r_unref (c);
			return NULL;
		}
		if (!refline_kept (ref, middle_after, addr)) {
			continue;
		}
		if ((ref->from == addr || ref->to == addr) && !middle_after) {
			const char *corner = get_corner_char (ref, addr, middle_before);
			const char ch = ref->from == addr? '=': '-';
			const char ch_col = ref->from >= ref->to? 't': 'd';
			const char *col = (ref->from >= ref->to)? "t": "d";
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
				dir = ref->to == addr? 1: 2;
			}
			pos = middle_before? ref->level: 0;
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
				r_buf_append_string (b, colchar (ref));
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
	str = r_buf_tostring (b);
	col_str = r_buf_tostring (c);
	r_unref (b);
	r_unref (c);
	b = NULL;
	c = NULL;
	if (!str || !col_str) {
		if (free_lvls) {
			RVecAnalReflinePtr_fini (&tmp_lvls);
		}
		// r_unref_tostring already free b and if that is the case
		// b will be NULL and r_unref will return but if there was
		// an error we free b here so in other words is safe
		r_unref (b);
		r_unref (c);
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
				lw = sizeof (pfx) - 1;
			}
			if (lw > 0) {
				pfx[lw] = 0;
				str = r_str_prepend (str, pfx);
				col_str = r_str_prepend (col_str, pfx);
			}
		}
	}
	const char prev_col = col_str[strlen (col_str) - 1];
	const char *arr_col = prev_col == 't'? "tt ": "dd ";
	str = r_str_append (str, arrowbydir (dir));
	col_str = r_str_append (col_str, arr_col);

	if (free_lvls) {
		RVecAnalReflinePtr_fini (&tmp_lvls);
	}
	RAnalRefStr *out = R_NEW0 (RAnalRefStr);
	out->str = str;
	out->cols = col_str;
	return out;
}

R_API void r_anal_reflines_str_free(RAnalRefStr *refstr) {
	if (refstr) {
		free (refstr->str);
		free (refstr->cols);
		free (refstr);
	}
}
