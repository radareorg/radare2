/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <r_meta.h>

R_API struct r_meta_t *r_meta_new() {
	RMeta *m = R_NEW (RMeta);
	if (m) INIT_LIST_HEAD (&m->data);
	return m;
}

R_API void r_meta_free(struct r_meta_t *m) {
	/* TODO: memory leak */
	free (m);
}

R_API int r_meta_count(struct r_meta_t *m, int type, ut64 from, ut64 to, struct r_meta_count_t *c) {
	struct list_head *pos;
	int count = 0;

	list_for_each(pos, &m->data) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		if (d->type == type || type == R_META_ANY) {
			if (from >= d->from && d->to < to) {
				if (c) {
					/* */
				}
				count++;
			}
		}
	}
	return count;
}

R_API char *r_meta_get_string(struct r_meta_t *m, int type, ut64 addr) {
	char *str = NULL;
	struct list_head *pos;

	switch(type) {
	case R_META_FUNCTION:
	case R_META_COMMENT:
	case R_META_FOLDER:
	case R_META_XREF_CODE:
	case R_META_XREF_DATA:
	case R_META_ANY:
		break;
	case R_META_CODE:
	case R_META_DATA:
	case R_META_STRING:
	case R_META_STRUCT:
		/* we should remove overlapped types and so on.. */
		return "(Unsupported meta type)";
		break;
	default:
		eprintf ("Unhandled\n");
		return "(Unhandled meta type)";
	}
	list_for_each (pos, &m->data) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		if (d->type == type || type == R_META_ANY) {
			if (d->from == addr)
			switch(d->type) {
			case R_META_FUNCTION:
				str = r_str_concatf(str, "; FUNCTION SIZE %"PFMT64d"\n", d->size);
				break;
			case R_META_COMMENT:
				str = r_str_concatf(str, "; %s\n", d->str);
				break;
			case R_META_FOLDER:
				str = r_str_concatf(str, "; FOLDER %"PFMT64d" bytes\n", d->size);
				break;
			case R_META_XREF_CODE:
				str = r_str_concatf(str, "; CODE XREF FROM 0x%08"PFMT64x"\n", d->to);
				break;
			case R_META_XREF_DATA:
				str = r_str_concatf(str, "; DATA XREF FROM 0x%08"PFMT64x"\n", d->to);
				break;
			}
		}
	}
	return str;
}

R_API int r_meta_del(RMeta *m, int type, ut64 from, ut64 size, const char *str) {
	int ret = R_FALSE;
	struct list_head *pos, *n;

	list_for_each_safe (pos, n, &m->data) {
		RMetaItem *d = (RMetaItem *) list_entry(pos, RMetaItem, list);
		if (d->type == type || type == R_META_ANY) {
			if (str != NULL && !strstr(d->str, str))
				continue;
			if (from >= d->from && from <= d->to) {
				free (d->str);
				list_del (&(d->list));
				ret = R_TRUE;
			}
		}
	}
	return ret;
}

R_API int r_meta_cleanup(struct r_meta_t *m, ut64 from, ut64 to) {
	struct list_head *pos, *n;
	int ret = R_FALSE;

	if (from == 0LL && to == UT64_MAX) {
		// XXX: memory leak
		INIT_LIST_HEAD (&m->data);
		return R_TRUE;
	}
	list_for_each_safe (pos, n, &m->data) {
		RMetaItem *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		switch (d->type) {
		case R_META_CODE:
		case R_META_DATA:
		case R_META_STRING:
		case R_META_STRUCT:
#if 0
			   |__| |__|  |___|  |_|
			 |__|     |_|  |_|  |___|
			 ====== ===== ===== =====
#endif
			if (to>d->from && to<d->to) {
				d->from = to;
				ret= R_TRUE;
			} else
			if (from>d->from && from<d->to &&to>d->to) {
				d->to = from;
				ret= R_TRUE;
			} else
			if (from>d->from&&from<d->to&&to<d->to) {
				// XXX split!
				d->to = from;
				ret= R_TRUE;
			} else
			if (from>d->from&&to<d->to) {
				list_del(&(d->list));
				ret= R_TRUE;
			}
			break;
		}
	}
	return ret;
}

R_API int r_meta_add(RMeta *m, int type, ut64 from, ut64 size, const char *str) {
	RMetaItem *mi;
	switch(type) {
	case R_META_CODE:
	case R_META_DATA:
	case R_META_STRING:
	case R_META_STRUCT:
		/* we should remove overlapped types and so on.. */
		r_meta_cleanup(m, from, from + size);
	case R_META_FUNCTION:
	case R_META_COMMENT:
	case R_META_FOLDER:
	case R_META_XREF_CODE:
	case R_META_XREF_DATA:
		mi = R_NEW (RMetaItem);
		mi->type = type;
		mi->from = from;
		mi->size = size;
		mi->to = from+size;
		if (str) mi->str = strdup (str);
		else mi->str = NULL;
		list_add (&(mi->list), &m->data);
		break;
	default:
		return R_FALSE;
	}
	return R_TRUE;
}

/* snippet from data.c */
/* XXX: we should add a 4th arg to define next or prev */
R_API RMetaItem *r_meta_find(RMeta *m, ut64 off, int type, int where) {
	RMetaItem *it = NULL;
	struct list_head *pos;
	if (off==0LL)
		return NULL;

	list_for_each(pos, &m->data) {
		RMetaItem *d = (RMetaItem*) list_entry(pos, RMetaItem, list);
		if (d->type == type || type == R_META_ANY) {
			switch(where) {
			case R_META_WHERE_PREV:
				if (d->from < off) {
					if (it && d->from > it->from)
						it = d;
					else it = d;
				}
				break;
			case R_META_WHERE_HERE:
				if (off>=d->from && off <d->to) {
					it = d;
				}
				break;
			case R_META_WHERE_NEXT:
				if (d->from > off) {
					if (it && d->from < it->from)
						it = d;
					else it = d;
				}
				break;
			}
		}
	}
	return it;
}

#if 0
	/* not necessary */
//int data_get_fun_for(ut64 addr, ut64 *from, ut64 *to)
int r_meta_get_bounds(struct r_meta_t *m, ut64 addr, int type, ut64 *from, ut64 *to)
{
	struct list_head *pos;
	int n_functions = 0;
	int n_xrefs = 0;
	int n_dxrefs = 0;
	struct r_meta_item_t *rd = NULL;
	ut64 lastfrom = 0LL;

	list_for_each(pos, &m->data) {
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
	case R_META_CODE: return "Cc";
	case R_META_DATA: return "Cd";
	case R_META_STRING: return "Cs";
	case R_META_STRUCT: return "Cm";
	case R_META_FUNCTION: return "CF";
	case R_META_COMMENT: return "CC";
	case R_META_FOLDER: return "CF";
	case R_META_XREF_CODE: return "Cx";
	case R_META_XREF_DATA: return "CX";
	}
	return "(...)";
}

#if 0
#include <r_util.h>
struct r_range_t *r_meta_ranges(struct r_meta_t *m)
{
	struct r_range_t *r;
	struct list_head *pos;

	r = r_range_new();
	list_for_each(pos, &m->data) {
		struct r_meta_item_t *d = (struct r_meta_item_t *)
			list_entry(pos, struct r_meta_item_t, list);
		r_range_add(r, d->from, d->to, 1); //d->type);
	}
	return r;
}
#endif

int r_meta_list(struct r_meta_t *m, int type) {
	int count = 0;
	struct list_head *pos;
	list_for_each (pos, &m->data) {
		RMetaItem *d = (RMetaItem*) list_entry(pos, RMetaItem, list);
		if (d->type == type || type == R_META_ANY) {
			char *str = r_str_unscape (d->str);
			printf ("%s 0x%08"PFMT64x" 0x%08"PFMT64x" %d \"%s\"\n",
				r_meta_type_to_string (d->type),
				d->from, d->to, (int)(d->to-d->from), str);
			count++;
			free (str);
		}
	}
	return count;
}
