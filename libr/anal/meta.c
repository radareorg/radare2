/* radare - LGPL - Copyright 2008-2014 - nibble, pancake */

// TODO: rename to r_anal_meta_get() ??
#if 0
    TODO
    ====
    - handle sync to synchronize all the data on disk.
    - actually listing only works in memory
    - array_add doesnt needs index, right?
    - remove unused arguments from r_meta_find (where ???)
    - implement r_meta_find
#endif

#define USE_ANAL_SDB 1
#include <r_anal.h>
#include <r_print.h>

#if USE_ANAL_SDB
#define META_RANGE_BASE(x) ((x)>>12)
#define META_RANGE_SIZE 0xfff

static char *meta_inrange_get (RAnal *a, ut64 addr, int size) {
#undef DB
#define DB a->sdb_meta
	char key[64];
	ut64 base, base2;
	base = META_RANGE_BASE (addr);
	base2 = META_RANGE_BASE (addr+size);
	// return string array of all the offsets where there are stuff
	for (; base<base2; base += META_RANGE_SIZE) {
		snprintf (key, sizeof (key)-1, "range.0x%"PFMT64x, base);
		sdb_array_get (DB, key, 0, 0);
	}
	return NULL;
}

static int meta_inrange_add (RAnal *a, ut64 addr, int size) {
	int set = 0;
	char key[64];
	ut64 base, base2;
	base = META_RANGE_BASE (addr);
	base2 = META_RANGE_BASE (addr+size);
	for (; base<base2; base += META_RANGE_SIZE) {
		snprintf (key, sizeof (key)-1, "range.0x%"PFMT64x, base);
		if (sdb_array_add_num (DB, key, -1, addr, 0))
			set = 1;
	}
	return set;
}

static int meta_inrange_del (RAnal *a, ut64 addr, int size) {
	int set = 0;
	char key[64];
	ut64 base, base2;
	base = META_RANGE_BASE (addr);
	base2 = META_RANGE_BASE (addr+size);
// TODO: optimize this thing?
	for (; base<base2; base += META_RANGE_SIZE) {
		snprintf (key, sizeof (key)-1, "range.0x%"PFMT64x, base);
		if (sdb_array_del_num (DB, key, addr, 0))
			set = 1;
	}
	//sdb_array_del (DB);
	return set;
}
#endif

R_API void r_meta_init(RAnal *a) {
#if USE_ANAL_SDB
	a->meta = NULL;
#else
	a->meta = r_list_new ();
	a->meta->free = r_meta_item_free;
#endif
}

R_API void r_meta_fini(RAnal *a) {
#if !USE_ANAL_SDB
	r_list_free (a->meta);
#endif
}

// TODO: Add APIs to resize meta? nope, just del and add
R_API int r_meta_set_string(RAnal *m, int type, ut64 addr, const char *s) {
#if USE_ANAL_SDB
#undef DB
#define DB m->sdb_meta
	char key[100], val[2048], *e_str;
	int ret;
	ut64 size;
	snprintf (key, sizeof (key)-1, "meta.%c", type);
	sdb_array_add_num (DB, key, -1, addr, 0);

	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, addr);
	size = sdb_array_get_num (DB, key, 0, 0);
	if (!size) {
		size = strlen (s);
		meta_inrange_add (m, addr, size);
		ret = R_TRUE;
	} else ret = R_FALSE;
	e_str = sdb_encode ((const void*)s, 0);
	snprintf (val, sizeof (val)-1, "%d,%s", (int)size, e_str);
	sdb_set (DB, key, val, 0);
	free ((void*)e_str);
	return ret;
#else
	RAnalMetaItem *mi = r_meta_find (m, addr, type, R_META_WHERE_HERE);
	if (mi) {
		free (mi->str);
		mi->str = strdup (s);
		return R_TRUE;
	}
	r_meta_add (m, type, addr, addr+1, s);
	return R_FALSE;
#endif
}

R_API char *r_meta_get_string(RAnal *m, int type, ut64 addr) {
#if USE_ANAL_SDB
#undef DB
#define DB m->sdb_meta
	char key[100];
	const char *k, *p;
	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, 'C', addr);
	k = sdb_const_get (DB, key, NULL);
	if (!k) return NULL;
	p = strchr (k, SDB_RS);
	if (!p) return NULL;
	k = p+1;
// TODO : comment append has been deprecated
	return (char *)sdb_decode (k, NULL);
#else
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
#endif
}

R_API int r_meta_del(RAnal *a, int type, ut64 addr, ut64 size, const char *str) {
#if USE_ANAL_SDB
#undef DB
#define DB a->sdb_meta
	int i, nxt;
	char key[100], key2[100], *dtr, *s, *p;
	const char *ptr;
	if (size == UT64_MAX) {
		// FULL CLEANUP
		// XXX: this thing ignores the type
		if (type == R_META_TYPE_ANY) {
			sdb_reset (DB);
		} else {
			snprintf (key, sizeof (key)-1, "meta.%c", type);
			dtr = sdb_get (DB, key, 0);
			for (p = dtr; p; p=sdb_array_next (s)) {
				s = sdb_array_string (p, &nxt);
				snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x,
					type, sdb_atoi (s));
				eprintf ("--> %s\n", key);
				sdb_unset (DB, key, 0);
				if (!nxt) break;
			}
			free (dtr);
		}
		return R_FALSE;
	}
	meta_inrange_del (a, addr, size);
	snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, addr);
	ptr = sdb_const_get (DB, key, 0);
	for (i=0; ptr[i]; i++) {
		if (ptr[i] != SDB_RS) {
			snprintf (key2, sizeof (key2)-1, "meta.%c.0x%"PFMT64x, ptr[i], addr);
			sdb_unset (DB, key2, 0);
		}
	}
	sdb_unset (DB, key, 0);
	return R_FALSE;
#else
	int ret = 0;
	RListIter *iter, *iter_tmp;
	RAnalMetaItem *d;

	r_list_foreach_safe (a->meta, iter, iter_tmp, d) {
		if (d->type == type || type == R_META_TYPE_ANY) {
			if (str && d->str && !strstr (d->str, str))
				continue;
			if (size==UT64_MAX || (addr+size >= d->from && addr <= d->to-size)) {
				free (d->str);
				r_list_delete (a->meta, iter);
				ret++;
			}
		}
	}
	return ret;
#endif
}

R_API int r_meta_cleanup(RAnal *a, ut64 from, ut64 to) {
#if USE_ANAL_SDB
	r_meta_del (a, R_META_TYPE_ANY, from, (to-from), NULL);
#else
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
#endif
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

#if USE_ANAL_SDB
// DEPRECATED FUNCTIONS FTW
#else

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
#endif

R_API int r_meta_add(RAnal *m, int type, ut64 from, ut64 to, const char *str) {
#if USE_ANAL_SDB
#define DB m->sdb_meta
	char *e_str, key[100], val[2048];
	if (from>to)
		return R_FALSE;
	if (from == to)
		to = from+1;
	/* set entry */
	e_str = sdb_encode ((const void*)str, 0);
	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, from);
	snprintf (val, sizeof (val)-1, "%d,%s", (int)(to-from), e_str);
	sdb_set (DB, key, val, 0);
	free (e_str);

	/* set type index */
	snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, from);
	snprintf (val, sizeof (val)-1, "%c", type);
	sdb_array_add (DB, key, -1, val, 0);

	/* set type index */
	snprintf (key, sizeof (key)-1, "meta.%c", type);
	sdb_array_add_num (DB, key, -1, from, 0);

	return R_TRUE;
#else
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
			if (r_str_nlen (str, 80)>78) {
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
#endif
}

R_API RAnalMetaItem *r_meta_find(RAnal *m, ut64 off, int type, int where) {
#if USE_ANAL_SDB
#define DB m->sdb_meta
	static RAnalMetaItem it = {0};
	// XXX: return allocated item? wtf
	if (where != R_META_WHERE_HERE) {
		eprintf ("THIS WAS NOT SUPOSED TO HAPPEN\n");
		return NULL;
	}
	//char *range = get_in_range (off);
	if (type == R_META_TYPE_ANY) {
		char key [100];
		snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, off);
sdb_const_get (DB, key, 0);
	} else {
	//	snprintf (key, sizeof (key)-1, "meta.
	}
	return &it;
#else
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
#endif
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

static void printmetaitem(RAnal *m, RAnalMetaItem *d, int rad) {
	char *pstr, *str = r_str_escape (d->str);
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

#if USE_ANAL_SDB
typedef struct {
	RAnal *anal;
	int type;
	int rad;
} RAnalMetaUserItem;

static int meta_print_item(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RAnalMetaItem it;
	if (strlen (k)<8)
		return R_FALSE;
	if (k[6]!='.')
		return R_FALSE;
	it.type = k[5];
	it.size = sdb_atoi (v);
	it.from = sdb_atoi (k+7);
	it.to = it.from + it.size;
	it.str = strchr (v, ',');
	if (it.str)
		it.str = (char *)sdb_decode ((const char*)it.str+1, 0);
	printmetaitem (ui->anal, &it, ui->rad);
	free (it.str);
	return R_TRUE;
}
#endif

// TODO: Deprecate
R_API int r_meta_list(RAnal *m, int type, int rad) {
#if USE_ANAL_SDB
#define DB m->sdb_meta
	RAnalMetaUserItem ui = { m, type, rad };
// XXX: doesnt works well on sync
	sdb_foreach (DB, meta_print_item, &ui);
	return 0;
#else
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
#endif
}

R_API char *r_anal_meta_bar (RAnal *anal, ut64 from, ut64 to, int blocks) {
	int i, n, blocksize;
	char *res;
	ut64 f, t;
	if (blocks<1 || from > to)
		return NULL;
	blocksize = (to-from)/blocks;
	res = malloc (blocks*4);
	for (i=0; i< blocks; i++) {
		f = from + (blocksize*i);
		t = f+blocksize;
		n = r_anal_fcn_count (anal, f, t);
		if (n>0) res[i++] = 'f';
		res[i++] = ',';
	}
	return res;
}
