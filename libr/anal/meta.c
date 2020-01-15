/* radare - LGPL - Copyright 2008-2018 - nibble, pancake */

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
  'meta.<type>.<last>=<array>'  split array, each block contains K elements
  'meta.<type>.<addr>=<string>' string representing extra information of the meta type at given address
  'range.<baddr>=<array>'       store valid addresses in a base range array
#endif

#include <r_anal.h>
#include <r_core.h>
#include <r_util.h>

#define META_RANGE_BASE(x) ((x)>>5)
#undef DB
#define DB a->sdb_meta

static char *meta_inrange_get (RAnal *a, ut64 addr, int size) {
	if (size <= 0) {
		return NULL;
	}
	ut64 base = META_RANGE_BASE (addr);
	ut64 base2 = META_RANGE_BASE (addr + size - 1);
	char *res = NULL;
	// return string array of all the offsets where there are stuff
	for (; base <= base2; base++) {
		const char *key = sdb_fmt ("range.0x%"PFMT64x, base);
		char *r = sdb_get (DB, key, 0);
		if (r) {
			if (res) {
				res = r_str_append (res, ",");
			}
			res = r_str_append (res, r);
			free (r);
		}
	}
	return res;
}

static bool meta_inrange_add (RAnal *a, ut64 addr, int size) {
	if (size <= 0) {
		return false;
	}
	bool set = false;
	ut64 base, base2;
	base = META_RANGE_BASE (addr);
	base2 = META_RANGE_BASE (addr + size - 1);
	for (; base <= base2; base++) {
		const char *key = sdb_fmt ("range.0x%"PFMT64x, base);
		if (sdb_array_add_num (DB, key, addr, 0)) {
			set = true;
		}
	}
	return set;
}

static bool meta_inrange_del (RAnal *a, ut64 addr, int size) {
	if (size <= 0) {
		return false;
	}
	bool set = false;
	ut64 base = META_RANGE_BASE (addr);
	ut64 base2 = META_RANGE_BASE (addr + size - 1);
	for (; base <= base2; base++) {
		const char *key = sdb_fmt ("range.0x%"PFMT64x, base);
		if (sdb_array_remove_num (DB, key, addr, 0)) {
			set = true;
		}
	}
	return set;
}

// 512 = 1.5s
// 256 = 1.3s
// 128 = 1.2s
// 64 = 1.14
// 32 = 1.12
// not storing any = 1
#define K 256

static int meta_type_add(RAnal *a, char type, ut64 addr) {
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
	const char *space = r_spaces_current_name (&a->meta_spaces);
	meta_type_add (a, type, addr);

	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, addr);
	size = sdb_array_get_num (DB, key, 0, 0);
	if (!size) {
		size = strlen (s);
		meta_inrange_add (a, addr, size);
		ret = true;
	} else {
		ret = false;
	}
	if (a->log) {
		char *msg = r_str_newf (":C%c %s @ 0x%"PFMT64x, type, s, addr);
		a->log (a, msg);
		free (msg);
	}
	e_str = sdb_encode ((const void*)s, -1);
	snprintf (val, sizeof (val)-1, "%d,%s,%s", (int)size, space, e_str);
	sdb_set (DB, key, val, 0);
	free ((void*)e_str);

	/* send event */
	REventMeta rems = {
		.type = type,
		.addr = addr,
		.string = s
	};
	r_event_send (a->ev, R_EVENT_META_SET, &rems);

	return ret;
}

R_API int r_meta_set_var_comment(RAnal *a, int type, ut64 idx, ut64 addr, const char *s) {
	char key[100], val[2048], *e_str;
	int ret;
	ut64 size;
	const char *space = r_spaces_current_name (&a->meta_spaces);
	meta_type_add (a, type, addr);

	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x".0x%"PFMT64x, type, addr, idx);
	size = sdb_array_get_num (DB, key, 0, 0);
	if (!size) {
		size = strlen (s);
		meta_inrange_add (a, addr, size);
		ret = true;
	} else {
		ret = false;
	}
	e_str = sdb_encode ((const void*)s, -1);
	snprintf (val, sizeof (val)-1, "%d,%s,%s", (int)size, space, e_str);
	sdb_set (DB, key, val, 0);
	free ((void*)e_str);
	return ret;
}

R_API char *r_meta_get_string(RAnal *a, int type, ut64 addr) {
	char key[100];
	const char *k, *p, *p2, *p3;
	snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, addr);
	k = sdb_const_get (DB, key, NULL);
	if (!k) {
		return NULL;
	}
	p = strchr (k, SDB_RS);
	if (!p) {
		return NULL;
	}
	k = p + 1;
	p2 = strchr (k, SDB_RS);
	if (!p2) {
		return (char *)sdb_decode (k, NULL);
	}
	k = p2 + 1;
	if (type == R_META_TYPE_STRING) {
		p3 = strchr (k, SDB_RS);
		if (p3) {
			return (char *)sdb_decode (p3 + 1, NULL);
		}
	}
	return (char *)sdb_decode (k, NULL);
}

R_API char *r_meta_get_var_comment (RAnal *a, int type, ut64 idx, ut64 addr) {
	char key[100];
	const char *k, *p, *p2;
	snprintf (key, sizeof (key) - 1, "meta.%c.0x%"PFMT64x".0x%"PFMT64x, type, addr, idx);
	k = sdb_const_get (DB, key, NULL);
	if (!k) {
		return NULL;
	}
	p = strchr (k, SDB_RS);
	if (!p) {
		return NULL;
	}
	k = p + 1;
	p2 = strchr (k, SDB_RS);
	if (!p2) {
		return (char *)sdb_decode (k, NULL);
	}
	return (char *)sdb_decode (p2+1, NULL);
}

static bool mustDeleteMetaEntry(RAnal *a, ut64 addr) {
	const char *tt = sdb_const_get (DB, sdb_fmt ("meta.t.0x%"PFMT64x, addr), NULL);
	const char *ss = sdb_const_get (DB, sdb_fmt ("meta.s.0x%"PFMT64x, addr), NULL);
	const char *dd = sdb_const_get (DB, sdb_fmt ("meta.d.0x%"PFMT64x, addr), NULL);
	const char *cc = sdb_const_get (DB, sdb_fmt ("meta.C.0x%"PFMT64x, addr), NULL);
	int count = 0;
	if (tt) count++;
	if (ss) count++;
	if (dd) count++;
	if (cc) count++;
	return (count == 0);
}

// delete all the metas of a specific type, addr is ignored,
static void r_meta_del_cb (RAnal *a, int type, int rad, SdbForeachCallback cb, void *user, ut64 addr) {
	SdbList *ls = sdb_foreach_list (DB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		if (type == R_META_TYPE_ANY || (strlen (sdbkv_key (kv)) > 5 && sdbkv_key (kv)[5] == type)) {
			sdb_set (DB, sdbkv_key (kv), NULL, 0);
		}
	}
	ls_free (ls);
}

R_API int r_meta_del(RAnal *a, int type, ut64 addr, ut64 size) {
	char key[100];
	const char *val;
	/* send event */
	REventMeta rems = {
		.type = type,
		.addr = addr,
		.string = NULL
	};
	r_event_send (a->ev, R_EVENT_META_DEL, &rems);
	if (size == UT64_MAX) {
		// FULL CLEANUP
		// XXX: this thing ignores the type
		if (type == R_META_TYPE_ANY) {
			sdb_reset (DB);
		} else {
			r_meta_del_cb (a, type, type, NULL, NULL, UT64_MAX);
		}
		return false;
	}
	if (type == R_META_TYPE_ANY) {
		/* special case */
		r_meta_del (a, R_META_TYPE_COMMENT, addr, size);
		r_meta_del (a, R_META_TYPE_VARTYPE, addr, size);
	}
	if (type == R_META_TYPE_COMMENT || type == R_META_TYPE_VARTYPE) {
		snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, type, addr);
	} else {
		snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, addr);
	}
	val = sdb_const_get (DB, key, 0);
	if (val) {
		if (type == R_META_TYPE_ANY) {
			char item_key[100];
			const char *ptr = val;
			while (*ptr) {
				snprintf (item_key, sizeof (item_key), "meta.%c.0x%" PFMT64x, *ptr, addr);
				sdb_unset (DB, item_key, 0);
				ptr++;
				if (*ptr) {
					ptr++;
				}
			}
			sdb_unset (DB, key, 0);
			return false;
		}
		if (strchr (val, ',')) {
			char type_fld[] = "##";
			if (val[0] == type) {
				type_fld[0] = type;
				type_fld[1] = ',';
			} else {
				type_fld[0] = ',';
				type_fld[1] = type;
			}
			sdb_uncat (DB, key, type_fld, 0);
		} else {
			sdb_unset (DB, key, 0);
		}
		snprintf (key, sizeof (key), "meta.%c.0x%" PFMT64x, type, addr);
		sdb_unset (DB, key, 0);
	}
	sdb_unset (DB, key, 0);
	if (mustDeleteMetaEntry (a, addr)) {
		meta_inrange_del (a, addr, size);
	}
	return false;
}


R_API int r_meta_var_comment_del(RAnal *a, int type, ut64 idx, ut64 addr) {
	char *key = r_str_newf ("meta.%c.0x%"PFMT64x"0x%"PFMT64x, type, addr, idx);
	sdb_unset (DB, key, 0);
	return 0;
}

R_API int r_meta_cleanup(RAnal *a, ut64 from, ut64 to) {
	return r_meta_del (a, R_META_TYPE_ANY, from, (to-from));
}

static void r_meta_item_fini(RAnalMetaItem *item) {
	free (item->str);
}

R_API void r_meta_item_free(void *_item) {
	if (_item) {
		RAnalMetaItem *item = _item;
		r_meta_item_fini (item);
		free (item);
	}
}

R_API RAnalMetaItem *r_meta_item_new(int type) {
	RAnalMetaItem *mi = R_NEW0 (RAnalMetaItem);
	if (mi) {
		mi->type = type;
	}
	return mi;
}

static void meta_serialize(RAnalMetaItem *it, char *k, size_t k_size, char *v, size_t v_size) {
	snprintf (k, k_size, "meta.%c.0x%" PFMT64x, it->type, it->from);
	const char *name = it->space? it->space->name: "*";
	if (it->subtype) {
		snprintf (v, v_size, "%d,%s,%c,%s", (int)it->size, name, it->subtype, it->str);
	} else {
		snprintf (v, v_size, "%d,%s,%s", (int)it->size, name, it->str);
	}
}

static bool meta_deserialize(RAnal *a, RAnalMetaItem *it, const char *k, const char *v) {
	if (strlen (k) < 8) {
		return false;
	}
	if (memcmp (k + 6, ".0x", 3)) {
		return false;
	}
	return r_meta_deserialize_val (a, it, k[5], sdb_atoi (k + 7), v);
}

R_API bool r_meta_deserialize_val(RAnal *a, RAnalMetaItem *it, int type, ut64 from, const char *v) {
	const char *v2;
	char *v3;
	it->type = type;
	it->subtype = 0;
	it->size = sdb_atoi (v);
	it->from = from;
	it->to = from + it->size;
	v2 = strchr (v, ',');
	if (!v2) {
		return false;
	}
	v3 = strchr (v2 + 1, ',');
	if (!v3) {
		return false;
	}
	char *tmp = r_str_ndup (v2 + 1, v3 - v2 - 1);
	it->space = r_spaces_add (&a->meta_spaces, tmp);
	free (tmp);
	it->str = strchr (v2 + 1, ',');
	if (it->str) {
		if (it->type == R_META_TYPE_STRING) {
			v3 = strchr (it->str + 1, ',');
			if (v3) {
				it->subtype = *(it->str + 1);
				it->str = v3;
			}
		}
		it->str = (char *)sdb_decode ((const char*)it->str + 1, 0);
	}
	return true;
}

static int meta_add(RAnal *a, int type, int subtype, ut64 from, ut64 to, const char *str) {
	const RSpace *space = r_spaces_current (&a->meta_spaces);
	char key[100], val[2048];
	if (from > to) {
		return false;
	}
	if (from == to) {
		to = from + 1;
	}
	if (type == 100 && (to - from) < 1) {
		return false;
	}
	/* set entry */
	char *e_str = sdb_encode ((const void*)str, -1);
	RAnalMetaItem mi = {from, to, (int)(to - from), type, subtype, e_str, space};
	meta_serialize (&mi, key, sizeof (key), val, sizeof (val));
	bool exists = sdb_exists (DB, key);

	sdb_set (DB, key, val, 0);
	free (e_str);

	// XXX: This is totally inefficient, using array_add withuot
	// checking return value is wrong practice, also it may lead
	// to inconsistent DB, and pretty bad performance. We should
	// store this list in a different storage that doesnt have
	// those limits and it's O(1) instead of O(n)
	snprintf (key, sizeof (key) - 1, "meta.0x%"PFMT64x, from);
	if (exists) {
		const char *value = sdb_const_get (DB, key, 0);
		if (value) {
			int idx = sdb_array_indexof (DB, key, value, 0);
			if (idx >= 0) {
				sdb_array_delete (DB, key, idx, 0);
			}
		}
	}
	val[0] = type;
	val[1] = '\0';
	sdb_array_add (DB, key, val, 0);
	meta_inrange_add (a, from, to - from);
	return true;
}

R_API int r_meta_add(RAnal *a, int type, ut64 from, ut64 to, const char *str) {
	return meta_add (a, type, 0, from, to, str);
}

R_API int r_meta_add_with_subtype(RAnal *a, int type, int subtype, ut64 from, ut64 to, const char *str) {
	return meta_add (a, type, subtype, from, to, str);
}

static RAnalMetaItem *r_meta_find_(RAnal *a, ut64 at, int type, int where, int excl_type) {
	const char *infos, *metas;
	char key[100];
	Sdb *s = a->sdb_meta;
	RAnalMetaItem *mi = NULL;
	if (where != R_META_WHERE_HERE) {
		eprintf ("THIS WAS NOT SUPPOSED TO HAPPEN\n");
		return NULL;
	}

	snprintf (key, sizeof (key), "meta.0x%" PFMT64x, at);
	infos = sdb_const_get (s, key, 0);
	if (!infos) {
		return NULL;
	}
	mi =  R_NEW0 (RAnalMetaItem);
	for (; *infos; infos++) {
		if (*infos == ',') {
			continue;
		}
		if (type != R_META_TYPE_ANY && type != *infos) {
			continue;
		}
		if (excl_type && excl_type == *infos) {
			continue;
		}
		snprintf (key, sizeof (key), "meta.%c.0x%" PFMT64x, *infos, at);
		metas = sdb_const_get (s, key, 0);
		if (metas) {
			if (!r_meta_deserialize_val (a, mi, *infos, at, metas)) {
				continue;
			}
			return mi;
		}
	}
	r_meta_item_free (mi);
	return NULL;
}

// TODO should be named get imho
R_API RAnalMetaItem *r_meta_find(RAnal *a, ut64 at, int type, int where) {
	return r_meta_find_ (a, at, type, where, R_META_TYPE_NONE);
}

R_API RAnalMetaItem *r_meta_find_any_except(RAnal *a, ut64 at, int type, int where) {
	return r_meta_find_ (a, at, R_META_TYPE_ANY, where, type);
}

R_API RAnalMetaItem *r_meta_find_in(RAnal *a, ut64 at, int type, int where) {
	char *res = meta_inrange_get (a, at, 1);
	if (!res) {
		return NULL;
	}
	RList *list = r_str_split_list (res, ",", 0);
	RListIter *iter;
	const char *meta;
	r_list_foreach (list, iter, meta) {
		ut64 mia = r_num_math (NULL, meta);
		RAnalMetaItem *mi = r_meta_find (a, mia, type, where);
		if (mi) {
			if ((at >= mi->from && at < mi->to)) {
				free (res);
				return mi;
			}
			r_meta_item_free (mi);
		}
	}
	r_list_free (list);
	free (res);
	return NULL;
}

R_API RList *r_meta_find_list_in(RAnal *a, ut64 at, int type, int where) {
	char *res = meta_inrange_get (a, at, 1);
	if (!res) {
		return NULL;
	}
	RList *list = r_str_split_list (res, ",", 0);
	RList *out = r_list_newf (r_meta_item_free);
	if (!out) {
		return NULL;
	}
	RListIter *iter;
	const char *meta;
	r_list_foreach (list, iter, meta) {
		Sdb *s = a->sdb_meta;
		ut64 mia = r_num_math (NULL, meta);
		const char *key = sdb_fmt ("meta.0x%" PFMT64x, mia);
		const char *infos = sdb_const_get (s, key, 0);
		if (!infos) {
			continue;
		}
		for (; *infos; infos++) {
			if (*infos == ',') {
				continue;
			}
			const char *key = sdb_fmt ("meta.%c.0x%" PFMT64x, *infos, mia);
			const char *metas = sdb_const_get (s, key, 0);
			if (metas) {
				RAnalMetaItem *mi = R_NEW0 (RAnalMetaItem);
				if (mi) {
					if (r_meta_deserialize_val (a, mi, *infos, mia, metas) &&
						(at >= mi->from && at < mi->to)) {
						r_list_append (out, mi);
					} else {
						r_meta_item_free (mi);
					}
				}
			}
		}
	}
	r_list_free (list);
	free (res);
	return out;
}

R_API const char *r_meta_type_to_string(int type) {
	// XXX: use type as '%c'
	switch (type) {
	case R_META_TYPE_DATA: return "Cd";
	case R_META_TYPE_CODE: return "Cc";
	case R_META_TYPE_STRING: return "Cs";
	case R_META_TYPE_FORMAT: return "Cf";
	case R_META_TYPE_MAGIC: return "Cm";
	case R_META_TYPE_HIDE: return "Ch";
	case R_META_TYPE_COMMENT: return "CCu";
	case R_META_TYPE_RUN: return "Cr"; // not in C? help
	case R_META_TYPE_HIGHLIGHT: return "CH"; // not in C?
	case R_META_TYPE_VARTYPE: return "Ct";
	}
	return "# unknown meta # ";
}

R_API void r_meta_print(RAnal *a, RAnalMetaItem *d, int rad, PJ *pj, bool show_full) {
	r_return_if_fail (!(rad == 'j' && !pj)); // rad == 'j' => pj != NULL
	char *pstr, *str, *base64_str;
	RCore *core = a->coreb.core;
	bool esc_bslash = core ? core->print->esc_bslash : false;
	if (r_spaces_current (&a->meta_spaces) &&
	    r_spaces_current (&a->meta_spaces) != d->space) {
		return;
	}
	if (d->type == 's') {
		if (d->subtype == R_STRING_ENC_UTF8) {
			str = r_str_escape_utf8 (d->str, false, esc_bslash);
		} else {
			if (!d->subtype) {  /* temporary legacy workaround */
				esc_bslash = false;
			}
			str = r_str_escape_latin1 (d->str, false, esc_bslash, false);
		}
	} else {
		str = r_str_escape (d->str);
	}
	if (str || d->type == 'd') {
		if (d->type=='s' && !*str) {
			free (str);
			return;
		}
		if (!str) {
			pstr = "";
		} else if (d->type == 'f') {
			pstr = str;
		} else if (d->type == 's') {
			pstr = str;
		} else if (d->type == 't') {
			// Sanitize (don't escape) Ct comments so we can see "char *", etc.
			free (str);
			str = strdup (d->str);
			r_str_sanitize (str);
			pstr = str;
		} else if (d->type != 'C') {
			r_name_filter (str, 0);
			pstr = str;
		} else {
			pstr = d->str;
		}
//		r_str_sanitize (str);
		switch (rad) {
		case 'j':
			pj_o (pj);
			pj_kn (pj, "offset", d->from);
			pj_ks (pj, "type", r_meta_type_to_string (d->type));

			pj_k (pj, "name");
			if (d->type == 's' && (base64_str = r_base64_encode_dyn (d->str, -1))) {
				pj_s (pj, base64_str);
				free (base64_str);
			} else {
				pj_s (pj, str);
			}

			if (d->type == 'd') {
				pj_kn (pj, "size", d->size);
			} else if (d->type == 's') {
				const char *enc;
				switch (d->subtype) {
				case R_STRING_ENC_UTF8:
					enc = "utf8";
					break;
				case 0:  /* temporary legacy encoding */
					enc = "iz";
					break;
				default:
					enc = "latin1";
				}
				pj_ks (pj, "enc", enc);
				pj_kb (pj, "ascii", r_str_is_ascii (d->str));
			}

			pj_end (pj);
			break;
		case 0:
		case 1:
		case '*':
		default:
			switch (d->type) {
			case 'a': //var and arg comments
			case 'v':
			case 'e':
				//XXX I think they do not belong to here
				break;
			case 'C':
				{
				const char *type = r_meta_type_to_string (d->type);
				char *s = sdb_encode ((const ut8*)pstr, -1);
				if (!s) {
					s = strdup (pstr);
				}
				if (rad) {
					if (!strcmp (type, "CCu")) {
						a->cb_printf ("%s base64:%s @ 0x%08"PFMT64x"\n",
							type, s, d->from);
					} else {
						a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
							type, pstr, d->from);
					}
				} else {
					if (!strcmp (type, "CCu")) {
						char *mys = r_str_escape (pstr);
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								d->from, type, mys);
						free (mys);
					} else {
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								d->from, type, pstr);
					}
				}
				free (s);
				}
				break;
			case 's': /* string */
				if (rad) {
					char cmd[] = "Cs#";
					switch (d->subtype) {
					case 'a':
					case '8':
						cmd[2] = d->subtype;
						break;
					default:
						cmd[2] = 0;
					}
					a->cb_printf ("%s %d @ 0x%08"PFMT64x" # %s\n",
							cmd, (int)d->size, d->from, pstr);
				} else {
					const char *enc;
					switch (d->subtype) {
					case '8':
						enc = "utf8";
						break;
					default:
						enc = r_str_is_ascii (d->str) ? "ascii" : "latin1";
					}
					if (show_full) {
						a->cb_printf ("0x%08"PFMT64x" %s[%d] \"%s\"\n",
						              d->from, enc, (int)d->size, pstr);
					} else {
						a->cb_printf ("%s[%d] \"%s\"\n",
						              enc, (int)d->size, pstr);
					}
				}
				break;
			case 'h': /* hidden */
			case 'd': /* data */
				if (rad) {
					a->cb_printf ("%s %d @ 0x%08"PFMT64x"\n",
							r_meta_type_to_string (d->type),
							(int)d->size, d->from);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'h' ? "hidden" : "data";
						a->cb_printf ("0x%08" PFMT64x " %s %s %d\n",
						              d->from, dtype,
						              r_meta_type_to_string (d->type), (int)d->size);
					} else {
						a->cb_printf ("%d\n", (int)d->size);
					}
				}
				break;
			case 'm': /* magic */
			case 'f': /* formatted */
				if (rad) {
					a->cb_printf ("%s %d %s @ 0x%08"PFMT64x"\n",
							r_meta_type_to_string (d->type),
							(int)d->size, pstr, d->from);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'm' ? "magic" : "format";
						a->cb_printf ("0x%08" PFMT64x " %s %d %s\n",
						              d->from, dtype, (int)d->size, pstr);
					} else {
						a->cb_printf ("%d %s\n", (int)d->size, pstr);
					}
				}
				break;
			case 't': /* vartype */
				if (rad) {
					a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
						r_meta_type_to_string (d->type), pstr, d->from);
				} else {
					a->cb_printf ("0x%08"PFMT64x" %s\n", d->from, pstr);
				}
				break;
			default:
				if (rad) {
					a->cb_printf ("%s %d 0x%08"PFMT64x" # %s\n",
						r_meta_type_to_string (d->type),
						(int)d->size, d->from, pstr);
				} else {
					// TODO: use b64 here
					a->cb_printf ("0x%08"PFMT64x" array[%d] %s %s\n",
						d->from, (int)d->size,
						r_meta_type_to_string (d->type), pstr);
				}
				break;
			}
			break;
		}
		if (str) {
			free (str);
		}
	}
}

static int meta_print_item(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RAnalMetaItem it;
	if (!meta_deserialize (ui->anal, &it, k, v)) {
		return 1;
	}
	if (ui->fcn && !r_anal_function_contains (ui->fcn, it.from)) {
		goto beach;
	}
	if (!it.str) {
		it.str = strdup (""); // don't break in free
		if (!it.str) {
			goto beach;
		}
	}
	r_meta_print (ui->anal, &it, ui->rad, ui->pj, true);
beach:
	free (it.str);
	return 1;
}

R_API void r_meta_list_offset(RAnal *a, ut64 addr, char input) {
	const int types[] = {
		R_META_TYPE_VARTYPE,
		R_META_TYPE_HIGHLIGHT,
		R_META_TYPE_RUN,
		R_META_TYPE_COMMENT,
		R_META_TYPE_HIDE,
		R_META_TYPE_MAGIC,
		R_META_TYPE_FORMAT,
		R_META_TYPE_STRING,
		R_META_TYPE_CODE,
		R_META_TYPE_DATA,
	};

	char key[100];
	int i;

	for (i = 0; i < sizeof (types) / sizeof (types[0]); i ++) {
		snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, types[i], addr);
		const char *k = sdb_const_get (DB, key, 0);
		if (!k) {
			continue;
		}

		RAnalMetaUserItem ui = { a };

		meta_print_item ((void *)&ui, key, k);
	}
}


R_API int r_meta_list_cb(RAnal *a, int type, int rad, SdbForeachCallback cb, void *user, ut64 addr) {
	PJ *pj = NULL;
	if (rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return 0;
		}
		pj_a (pj);
	}

	RAnalMetaUserItem ui = { a, type, rad, cb, user, 0, NULL, pj };

	if (addr != UT64_MAX) {
		ui.fcn = r_anal_get_fcn_in (a, addr, 0);
		if (!ui.fcn) {
			goto beach;
		}
	}

	SdbList *ls = sdb_foreach_list (DB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		if (type == R_META_TYPE_ANY || (strlen (sdbkv_key (kv)) > 5 && sdbkv_key (kv)[5] == type)) {
			if (cb) {
				cb ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			} else {
				meta_print_item ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			}
		}
	}
	ls_free (ls);

beach:
	if (pj) {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	return ui.count;
}

R_API int r_meta_list(RAnal *a, int type, int rad) {
	return r_meta_list_cb (a, type, rad, NULL, NULL, UT64_MAX);
}

R_API int r_meta_list_at(RAnal *a, int type, int rad, ut64 addr) {
	return r_meta_list_cb (a, type, rad, NULL, NULL, addr);
}

static int meta_enumerate_cb(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RList *list = ui->user;
	RAnalMetaItem *it = R_NEW0 (RAnalMetaItem);
	if (!it) {
		return 0;
	}
	if (!meta_deserialize (ui->anal, it, k, v)) {
		free (it);
		goto beach;
	}
	if (!it->str) {
		free (it);
		goto beach;
	}
	r_list_append (list, it);
beach:
	return 1;
}

R_API RList *r_meta_enumerate(RAnal *a, int type) {
	RList *list = r_list_newf (r_meta_item_free);
	r_meta_list_cb (a, type, 0, meta_enumerate_cb, list, UT64_MAX);
	return list;
}

static int meta_unset_cb(void *user, const char *k, const char *v) {
	char nk[128], nv[4096];
	RAnalMetaUserItem *ui = user;
	RAnal *a = ui->anal;
	RAnalMetaItem it = {0};
	if (!strstr (k, ".0x")) {
		return 1;
	}
	meta_deserialize (ui->anal, &it, k, v);
	if (it.space && it.space == ui->user) {
		it.space = NULL;
		meta_serialize (&it, nk, sizeof (nk), nv, sizeof (nv));
		sdb_set (DB, nk, nv, 0);
	}
	return 1;
}

R_API void r_meta_space_unset_for(RAnal *a, const RSpace *space) {
	RAnalMetaUserItem ui = { .anal = a, .user = (void *)space };
	r_meta_list_cb (a, R_META_TYPE_ANY, 0, meta_unset_cb, &ui, UT64_MAX);
}

typedef struct {
	int count;
	int index;
	const RSpace *ctx;
} myMetaUser;

static int meta_count_cb(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	myMetaUser *mu = ui->user;
	RAnalMetaItem it = {0};
	if (!strstr (k, ".0x")) {
		return 1;
	}
	meta_deserialize (ui->anal, &it, k, v);
	if (mu && it.space == mu->ctx) {
		mu->count++;
	}
	r_meta_item_fini (&it);
	return 1;
}

static int get_meta_size(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RAnalMetaItem it;
	if (!meta_deserialize (ui->anal, &it, k, v)) {
		return -1;
	}
	if (ui->fcn && !r_anal_function_contains (ui->fcn, it.from)) {
		goto beach;
	}
	if (!it.str) {
		it.str = strdup (""); // don't break in free
		if (!it.str) {
			goto beach;
		}
	}
	return it.size;
beach:
	free (it.str);
	return -1;
}

R_API int r_meta_get_size(RAnal *a, int type) {
	RAnalMetaUserItem ui = { a, type, 0, NULL, NULL, 0, NULL };
	SdbList *ls = sdb_foreach_list (DB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	int tot_size = 0;
	int meta_size;
	ls_foreach (ls, lsi, kv) {
		if ((strlen (sdbkv_key (kv)) > 5 && sdbkv_key (kv)[5] == type)) {

			meta_size = get_meta_size ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			tot_size += meta_size > -1 ? meta_size : 0;
		}
	}
	ls_free (ls);
	return tot_size;
}


R_API int r_meta_space_count_for(RAnal *a, const RSpace *space) {
	myMetaUser mu = { .ctx = space };
	r_meta_list_cb (a, R_META_TYPE_ANY, 0, meta_count_cb, &mu, UT64_MAX);
	return mu.count;
}
