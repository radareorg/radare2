/* radare - LGPL - Copyright 2008-2014 - nibble, pancake */

// TODO: Use SDB

#include <r_anal.h>
#include <r_print.h>

R_API void r_meta_init(RAnal *a) {
	a->meta = r_list_new ();
	a->meta->free = r_meta_item_free;
}

R_API void r_meta_fini(RAnal *a) {
	r_list_free (a->meta);
}

R_API int r_meta_count(RAnal *m, int type, ut64 from, ut64 to) {
	RAnalMetaItem *d;
	RListIter *iter;
	int count = 0;

	r_list_foreach (m->meta, iter, d) {
		if (d->type == type || type == R_META_TYPE_ANY)
			if (from >= d->from && d->to < to)
				count++;
	}
	return count;
}

R_API int r_meta_set_string(RAnal *m, int type, ut64 addr, const char *s) {
	RAnalMetaItem *mi = r_meta_find (m, addr, type, R_META_WHERE_HERE);
	if (mi) {
		free (mi->str);
		mi->str = strdup (s);
		return R_TRUE;
	}
	r_meta_add (m, type, addr, addr+1, s);
	return R_FALSE;
}

R_API char *r_meta_get_string(RAnal *m, int type, ut64 addr) {
	char *str = NULL;
	RListIter *iter;
	RAnalMetaItem *d;

	switch (type) {
	case R_META_TYPE_COMMENT:
	case R_META_TYPE_HIDE:
	case R_META_TYPE_ANY:
		break;
	case R_META_TYPE_CODE:
	case R_META_TYPE_DATA:
	case R_META_TYPE_STRING:
	case R_META_TYPE_FORMAT:
	case R_META_TYPE_MAGIC:
		/* we should remove overlapped types and so on.. */
		return "(Unsupported meta type)";
	default:
		eprintf ("r_meta_get_string: unhandled meta type\n");
		return "(Unhandled meta type)";
	}
	r_list_foreach (m->meta, iter, d) {
		if (d->type == type || type == R_META_TYPE_ANY) {
			if (d->from == addr)
			switch (d->type) {
			case R_META_TYPE_COMMENT:
				str = r_str_concatf (str, "%s\n", d->str);
				break;
			}
		}
	}
	return str;
}

R_API int r_meta_del(RAnal *a, int type, ut64 from, ut64 size, const char *str) {
	int ret = 0;
	RListIter *iter, *iter_tmp;
	RAnalMetaItem *d;

	r_list_foreach_safe (a->meta, iter, iter_tmp, d) {
		if (d->type == type || type == R_META_TYPE_ANY) {
			if (str && d->str && !strstr (d->str, str))
				continue;
			if (size==UT64_MAX || (from+size >= d->from && from <= d->to-size)) {
				free (d->str);
				r_list_delete (a->meta, iter);
				ret++;
			}
		}
	}
	return ret;
}

R_API int r_meta_cleanup(RAnal *a, ut64 from, ut64 to) {
	RAnalMetaItem *d;
	RListIter *iter, next;
	int ret = R_FALSE;

	if (from == 0LL && to == UT64_MAX) {
		RList *m2 = a->meta;
		r_meta_init (a);
		if (!a->meta) {
			a->meta = m2;
			return R_FALSE;
		}
		r_list_free (m2);
		free (m2);
		return R_TRUE;
	}
	/* No _safe loop necessary because we break immediately after the delete. */
	if (a)
	r_list_foreach (a->meta, iter, d) {
		next.n = iter->n;
		switch (d->type) {
		case R_META_TYPE_CODE:
		case R_META_TYPE_DATA:
		case R_META_TYPE_STRING:
		case R_META_TYPE_FORMAT:
#if 0
			   |__| |__|  |___|  |_|
			 |__|     |_|  |_|  |___|
			 ====== ===== ===== =====
#endif
			if (to>d->from && to<d->to) {
				d->from = to;
				ret = R_TRUE;
			} else
			if (from>d->from && from<d->to &&to>d->to) {
				d->to = from;
				ret = R_TRUE;
			} else
			if (from>d->from&&from<d->to&&to<d->to) {
				// XXX split!
				d->to = from;
				ret = R_TRUE;
			} else
			if (from>d->from&&to<d->to) {
				r_list_delete (a->meta, iter);
				ret = R_TRUE;
			}
			break;
		}
		iter = &next;
	}
	return ret;
}

R_API void r_meta_item_free(void *_item) {
	RAnalMetaItem *item = _item;
	free (item);
}

R_API RAnalMetaItem *r_meta_item_new(int type) {
	RAnalMetaItem *mi = R_NEW (RAnalMetaItem);
	memset (mi, 0, sizeof (RAnalMetaItem));
	mi->type = type;
	return mi;
}

// TODO: This is ultraslow. must accelerate with hashtables
R_API int r_meta_comment_check (RAnal *m, const char *s, ut64 addr) {
	RAnalMetaItem *d;
	RListIter *iter;

	r_list_foreach (m->meta, iter, d) {
		if (d->type == R_META_TYPE_COMMENT)
			if (d->from == addr)
				if (!strcmp (s, d->str))
					return R_TRUE;
	}

	return R_FALSE;
}

R_API int r_meta_add(RAnal *m, int type, ut64 from, ut64 to, const char *str) {
	RAnalMetaItem *mi;
	if (to<from)
		to = from+to;

	switch (type) {
	case R_META_TYPE_COMMENT:
		if (r_meta_comment_check (m, str, from))
			return R_FALSE;
	case R_META_TYPE_HIDE:
	case R_META_TYPE_CODE:
	case R_META_TYPE_DATA:
	case R_META_TYPE_STRING:
	case R_META_TYPE_FORMAT:
		//r_meta_cleanup (m, from, to); /* remove overlapped stuff? */
		mi = r_meta_item_new (type);
		if (!mi) return R_FALSE;
		mi->size = to-from;
		mi->type = type;
		mi->from = from;
		mi->to = to;
		if (str && *str) {
			if (strnlen (str, 80)>78) {
				mi->str = malloc (80);
				memcpy (mi->str, str, 78);
				mi->str[78] = 0;
			} else {
				mi->str = strdup (str);
			}
		} else mi->str = NULL;
		r_list_append (m->meta, mi);
		break;
	default:
		eprintf ("r_meta_add: Unsupported type '%c'\n", type);
		return R_FALSE;
	}
	if (mi && mi->type == R_META_TYPE_FORMAT)
		mi->size = r_print_format_length (mi->str);
	return R_TRUE;
}

/* snippet from data.c */
R_API RAnalMetaItem *r_meta_find(RAnal *m, ut64 off, int type, int where) {
	RAnalMetaItem *d, *it = NULL;
	RListIter *iter;
	r_list_foreach (m->meta, iter, d) {
		if (d->type == type || type == R_META_TYPE_ANY) {
			switch (where) {
			case R_META_WHERE_PREV:
				if (d->from < off)
					it = d;
				break;
			case R_META_WHERE_HERE:
				if (!off || ((off>=d->from) && (off<d->to)))
					it = d;
				break;
			case R_META_WHERE_NEXT:
				if (d->from > off)
					it = d;
				break;
			}
		}
	}
	return it;
}

#if 0
	/* not necessary */
//int data_get_fun_for(ut64 addr, ut64 *from, ut64 *to)
int r_meta_get_bounds(RAnal *m, ut64 addr, int type, ut64 *from, ut64 *to)
{
	struct list_head *pos;
	int n_functions = 0;
	int n_xrefs = 0;
	int n_dxrefs = 0;
	struct r_meta_item_t *rd = NULL;
	ut64 lastfrom = 0LL;

	list_for_each(pos, &m->meta) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		if (d->type == type) {
			if (d->from < addr && d->from > lastfrom)
				rd = d;
		}
	}
	if (rd) {
		*from = rd->from;
		*to = rd->to;
		return 1;
	}
	return 0;
}
#endif

R_API const char *r_meta_type_to_string(int type) {
	// XXX: use type as '%c'
	switch(type) {
	case R_META_TYPE_HIDE: return "Ch";
	case R_META_TYPE_CODE: return "Cc";
	case R_META_TYPE_DATA: return "Cd";
	case R_META_TYPE_STRING: return "Cs";
	case R_META_TYPE_FORMAT: return "Cf";
	case R_META_TYPE_MAGIC: return "Cm";
	case R_META_TYPE_COMMENT: return "CC";
	}
	return "(...)";
}

#if 0
#include <r_util.h>
struct r_range_t *r_meta_ranges(RAnal *m)
{
	struct r_range_t *r;
	struct list_head *pos;

	r = r_range_new();
	list_for_each(pos, &m->meta) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		r_range_add(r, d->from, d->to, 1); //d->type);
	}
	return r;
}
#endif

static void printmetaitem(RAnal *m, RAnalMetaItem *d, int rad) {
	char *pstr, *str = r_str_unscape (d->str);
	if (str) {
		if (d->type=='s' && !*str)
			return;
		if (d->type != 'C') {
			r_name_filter (str, 0);
			pstr = str;
		} else pstr = d->str;
//		r_str_sanitize (str);
		switch (rad) {
		case 'j':
			m->printf ("{\"offset\":%"PFMT64d", \"type\":\"%s\", \"name\":\"%s\"}",
				d->from, r_meta_type_to_string (d->type), str);
			break;
		case 0:
			m->printf ("0x%08"PFMT64x" %s\n",
				d->from, str);
		case 1:
		case '*':
		default:
			if (d->type == 'C') {
				m->printf ("\"%s %s\" @ 0x%08"PFMT64x"\n",
					r_meta_type_to_string (d->type), pstr, d->from);
			} else {
				m->printf ("%s %d 0x%08"PFMT64x" # %s\n",
					r_meta_type_to_string (d->type), d->size, d->from, pstr);
			}
			break;
		}
		free (str);
	}
}

// TODO: Deprecate
R_API int r_meta_list(RAnal *m, int type, int rad) {
	int count = 0;
	RListIter *iter;
	RAnalMetaItem *d;
	if (rad=='j') m->printf ("[");
	r_list_foreach (m->meta, iter, d) {
		if (d->type == type || type == R_META_TYPE_ANY) {
			printmetaitem (m, d, rad);
			count++;
			if (rad=='j' && iter->n) m->printf (",");
		}
	}
	if (rad=='j') m->printf ("]\n");
	return count;
}

R_API char *r_anal_meta_bar (RAnal *anal, ut64 from, ut64 to, int blocks) {
	int i, n, blocksize;
	char *res;
	ut64 f, t;

	if (blocks<1 || from > to)
		return NULL;
#if 0
	if (from == to && from == 0) {
		// autodetect min and max here
	//	from = 
	}
#endif
	blocksize = (to-from)/blocks;
	res = malloc (blocks*4); //blocksize*5);// use realloc here
	for (i=0; i< blocks; i++) {
		f = from + (blocksize*i);
		t = f+blocksize;
		n = r_anal_fcn_count (anal, f, t);
		if (n>0) res[i++] = 'f';
		res[i++] = ',';
	}
	return res;
}
