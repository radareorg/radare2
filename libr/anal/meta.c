/* radare - LGPL - Copyright 2008-2014 - nibble, pancake */

// TODO: rename to r_anal_meta_get() ??
#if 0
    TODO
    ====
    - handle sync to synchronize all the data on disk.
    - actually listing only works in memory
    - array_add doesnt needs index, right?
    - remove unused arguments from r_meta_find (where ?)
    - implement r_meta_find
#endif
#if 0
  SDB SPECS

DatabaseName:
  'anal.meta'
Keys:
  'meta.<type>.count=<int>'     number of added metas where 'type' is a single char
  'meta.<type>.<last>=<array>'  splitted array, each block contains K elements
  'meta.<type>.<addr>=<string>' string representing extra information of the meta type at given address
  'range.<baddr>=<array>'       store valid addresses in a base range array
#endif

#include <r_anal.h>
#include <r_print.h>

#define META_RANGE_BASE(x) ((x)>>12)
#define META_RANGE_SIZE 0xfff
#undef DB
#define DB a->sdb_meta

#if 0
// Defined but not used. Shall we remove it?
static char *meta_inrange_get (RAnal *a, ut64 addr, int size) {
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
#endif

static int meta_inrange_add (RAnal *a, ut64 addr, int size) {
	int set = 0;
	char key[64];
	ut64 base, base2;
	base = META_RANGE_BASE (addr);
	base2 = META_RANGE_BASE (addr+size);
	for (; base<base2; base += META_RANGE_SIZE) {
		snprintf (key, sizeof (key)-1, "range.0x%"PFMT64x, base);
		if (sdb_array_add_num (DB, key, addr, 0))
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
		if (sdb_array_remove_num (DB, key, addr, 0))
			set = 1;
	}
	//sdb_array_del (DB);
	return set;
}

// 512 = 1.5s
// 256 = 1.3s
// 128 = 1.2s
// 64 = 1.14
// 32 = 1.12
// not storing any = 1
#define K 256

static int meta_type_add (RAnal *a, char type, ut64 addr) {
	char key[32];
	ut32 count, last;
	snprintf (key, sizeof (key)-1, "meta.%c.count", type);
	count = (ut32)sdb_num_inc (DB, key, 1, 0);
	last = count/K;

	snprintf (key, sizeof (key)-1, "meta.%c.%d", type, last);
	sdb_array_add_num (DB, key, addr, 0);
	return count;
}

// TODO: Add APIs to resize meta? nope, just del and add
R_API int r_meta_set_string(RAnal *a, int type, ut64 addr, const char *s) {
	char key[100], val[2048], *e_str;
	int ret;
	ut64 size;
	meta_type_add (a, type, addr);

	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, addr);
	size = sdb_array_get_num (DB, key, 0, 0);
	if (!size) {
		size = strlen (s);
		meta_inrange_add (a, addr, size);
		ret = R_TRUE;
	} else ret = R_FALSE;
	e_str = sdb_encode ((const void*)s, -1);
	snprintf (val, sizeof (val)-1, "%d,%s", (int)size, e_str);
	sdb_set (DB, key, val, 0);
	free ((void*)e_str);
	return ret;
}

R_API char *r_meta_get_string(RAnal *a, int type, ut64 addr) {
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
}

R_API int r_meta_del(RAnal *a, int type, ut64 addr, ut64 size, const char *str) {
	char key[100], key2[100], *dtr, *s, *p, *next;
	const char *ptr;
	int i;
	if (size == UT64_MAX) {
		// FULL CLEANUP
		// XXX: this thing ignores the type
		if (type == R_META_TYPE_ANY) {
			sdb_reset (DB);
		} else {
			snprintf (key, sizeof (key)-1, "meta.%c.count", type);
			int last = (ut64)sdb_num_get (DB, key, NULL)/K;
			for (i=0; i<last; i++) {
				snprintf (key, sizeof (key)-1, "meta.%c.%d", type, i);
				dtr = sdb_get (DB, key, 0);
				for (p = dtr; p; p = next) {
					s = sdb_anext (p, &next);
					snprintf (key, sizeof (key)-1,
						"meta.%c.0x%"PFMT64x,
						type, sdb_atoi (s));
					eprintf ("--> %s\n", key);
					sdb_unset (DB, key, 0);
					if (!next) break;
				}
				free (dtr);
			}
		}
		return R_FALSE;
	}
	meta_inrange_del (a, addr, size);
	snprintf (key, sizeof (key)-1, type==R_META_TYPE_COMMENT ?
		"meta.C.0x%"PFMT64x : "meta.0x%"PFMT64x, addr);
	ptr = sdb_const_get (DB, key, 0);
	if (ptr) {
		for (i=0; ptr[i]; i++) {
			if (ptr[i] != SDB_RS) {
				snprintf (key2, sizeof (key2)-1,
					"meta.%c.0x%"PFMT64x, ptr[i], addr);
				sdb_unset (DB, key2, 0);
			}
		}
	}
	sdb_unset (DB, key, 0);
	return R_FALSE;
}

R_API int r_meta_cleanup(RAnal *a, ut64 from, ut64 to) {
	return r_meta_del (a, R_META_TYPE_ANY, from, (to-from), NULL);
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

R_API int r_meta_add(RAnal *a, int type, ut64 from, ut64 to, const char *str) {
	int exists;
	char *e_str, key[100], val[2048];
	if (from>to)
		return R_FALSE;
	if (from == to)
		to = from+1;
	if (type == 100 && (to-from)<1) {
		return R_FALSE;
	}
	/* set entry */
	e_str = sdb_encode ((const void*)str, -1);
	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, from);
	snprintf (val, sizeof (val)-1, "%d,%s", (int)(to-from), e_str);
	exists = sdb_exists (DB, key);
	sdb_set (DB, key, val, 0);
	free (e_str);

	// XXX: This is totally inefficient, using array_add withuot
	// checking return value is wrong practice, also it may lead
	// to inconsistent DB, and pretty bad performance. We should
	// store this list in a different storage that doesnt have
	// those limits and it's O(1) instead of O(n)
	if (!exists) {
		//ut64 count;
		/* set type index */
		snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, from);
		snprintf (val, sizeof (val)-1, "%c", type);
		sdb_array_add (DB, key, val, 0);
		/* set type index */
		//count = meta_type_add (a, type, from);
	}

	return R_TRUE;
}

R_API RAnalMetaItem *r_meta_find(RAnal *a, ut64 off, int type, int where) {
	static RAnalMetaItem it = {0};
	// XXX: return allocated item? wtf
	if (where != R_META_WHERE_HERE) {
		eprintf ("THIS WAS NOT SUPOSED TO HAPPEN\n");
		return NULL;
	}
	//char *range = get_in_range (off);
	if (type == R_META_TYPE_ANY) {
		//const char *p;
		char key [100];
		snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, off);
		//p = sdb_const_get (DB, key, 0);
// XXX: TODO unimplemented. see core/disasm.c:1070
	} else {
	//	snprintf (key, sizeof (key)-1, "meta.
	}
	return &it;
}

R_API const char *r_meta_type_to_string(int type) {
	// XXX: use type as '%c'
	switch(type) {
	case R_META_TYPE_HIDE: return "Ch";
	case R_META_TYPE_CODE: return "Cc";
	case R_META_TYPE_DATA: return "Cd";
	case R_META_TYPE_STRING: return "Cs";
	case R_META_TYPE_FORMAT: return "Cf";
	case R_META_TYPE_MAGIC: return "Cm";
	case R_META_TYPE_COMMENT: return "CCu";
	}
	return "(...)";
}

static void printmetaitem(RAnal *a, RAnalMetaItem *d, int rad) {
	char *pstr, *str = r_str_escape (d->str);
	if (str || d->type == 'd') {
		if (d->type=='s' && !*str) {
			free (str);
			return;
		}
		if (!str)
			pstr = "";
		else if (d->type != 'C') {
			r_name_filter (str, 0);
			pstr = str;
		} else pstr = d->str;
//		r_str_sanitize (str);
		switch (rad) {
		case 'j':
			a->printf ("{\"offset\":%"PFMT64d", \"type\":\"%s\", \"name\":\"%s\"}",
				d->from, r_meta_type_to_string (d->type), str);
			break;
		case 0:
			a->printf ("0x%08"PFMT64x" %s\n",
				d->from, str);
		case 1:
		case '*':
		default:
			switch (d->type) {
			case 'C':
				a->printf ("\"%s %s\" @ 0x%08"PFMT64x"\n",
					r_meta_type_to_string (d->type), pstr, d->from);
				break;
			case 'h': /* hidden */
			case 's': /* string */
				a->printf ("%s %d @ 0x%08"PFMT64x" # %s\n",
					r_meta_type_to_string (d->type),
					d->size, d->from, pstr);
				break;
			case 'd': /* data */
				a->printf ("%s %d @ 0x%08"PFMT64x"\n",
					r_meta_type_to_string (d->type),
					d->size, d->from);
				break;
			case 'm': /* magic */
			case 'f': /* formatted */
				a->printf ("%s %d %s @ 0x%08"PFMT64x"\n",
					r_meta_type_to_string (d->type),
					d->size, pstr, d->from);
				break;
			default:
				a->printf ("%s %d 0x%08"PFMT64x" # %s\n",
					r_meta_type_to_string (d->type),
					d->size, d->from, pstr);
			}
			break;
		}
		if (str)
			free (str);
	}
}

typedef struct {
	RAnal *anal;
	int type;
	int rad;
} RAnalMetaUserItem;

static int meta_print_item(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RAnalMetaItem it;
	if (strlen (k)<8)
		return 1;
	if (memcmp (k+6, ".0x", 3))
		return 1;
	it.type = k[5];
	it.size = sdb_atoi (v);
	it.from = sdb_atoi (k+7);
	it.to = it.from + it.size;
	it.str = strchr (v, ',');
	if (it.str)
		it.str = (char *)sdb_decode ((const char*)it.str+1, 0);
	printmetaitem (ui->anal, &it, ui->rad);
	free (it.str);
	return 1;
}

// TODO: Deprecate
R_API int r_meta_list(RAnal *a, int type, int rad) {
	RAnalMetaUserItem ui = { a, type, rad };
	if (rad=='j') a->printf ("[");
	sdb_foreach (DB, meta_print_item, &ui);
	if (rad=='j') a->printf ("]\n");
	return 0;
}

#if 0
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
#endif
