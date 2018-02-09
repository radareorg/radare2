/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_anal.h>
#include <r_cons.h>
#include <sdb.h>

#define DB anal->sdb_xrefs

#if 0
DICT
====

refs
  10 -> 20 C
  16 -> 10 J
  20 -> 10 C

xrefs
  20 -> [ 10 C ]
  10 -> [ 16 J, 20 C ]

10: call 20
16: jmp 10
20: call 10
#endif

static const char *analref_toString(RAnalRefType type) {
	switch (type) {
	case R_ANAL_REF_TYPE_NULL:
		/* do nothing */
		break;
	case R_ANAL_REF_TYPE_CODE:
		return "code.jmp";
	case R_ANAL_REF_TYPE_CALL:
		return "code.call";
	case R_ANAL_REF_TYPE_DATA:
		return "data.mem";
	case R_ANAL_REF_TYPE_STRING:
		return "data.string";
	}
	return "unk";
}

static void XREFKEY(char * const key, const size_t key_len,
	char const * const kind, const RAnalRefType type, const ut64 addr) {
	char const * _sdb_type = analref_toString (type);
	snprintf (key, key_len, "%s.%s.0x%"PFMT64x, kind, _sdb_type, addr);
}

R_API bool r_anal_xrefs_save(RAnal *anal, const char *prjDir) {
#if USE_DICT
	anal->sdb_xrefs = sdb_new0 ();
#endif
	char *xrefs_path = r_str_newf ("%s" R_SYS_DIR "xrefs.sdb", prjDir);
	sdb_file (anal->sdb_xrefs, xrefs_path);
	free (xrefs_path);
	return sdb_sync (anal->sdb_xrefs);
}

#if USE_DICT
static void appendRef(RList *list, dicti k, dicti v, void *u) {
	RAnalRef *ref = r_anal_ref_new ();
	if (ref) {
#if 0
		eprintf ("%s 0x%08llx -> 0x%08llx (0x%llx)\n",
				kv->u, kv->k, kv->v, addr);
#endif
		ref->at = k;
		ref->addr = v;
		if (strcmp (u, "JMP") == 0) {
			ref->type = R_ANAL_REF_TYPE_CODE;
		} else if (strcmp (u, "CALL") == 0) {
			ref->type = R_ANAL_REF_TYPE_CALL;
		} else if (strcmp (u, "DATA") == 0) {
			ref->type = R_ANAL_REF_TYPE_DATA;
		} else if (strcmp (u, "STRING") == 0) {
			ref->type = R_ANAL_REF_TYPE_STRING;
		} else {
			ref->type = R_ANAL_REF_TYPE_NULL;
		}

		r_list_append (list, ref);
	}
}

static void mylistrefs(dict *m, ut64 addr, RList *list) {
	int i, j;
	for (i = 0; i < m->size; i++) {
		dictkv *kv = m->table[i];
		if (!kv) {
			continue;
		}
		while (kv->k != MHTNO) {
			if (addr == UT64_MAX || addr == kv->k) {
				appendRef (list, kv->k, kv->v, kv->u);
			}
			kv++;
		}
	}
}

static void listrefs(dict *m, ut64 addr, RList *list) {
	int i;
	if (addr == UT64_MAX) {
		for (i = 0; i < m->size; i++) {
			dictkv *kv = m->table[i];
			if (kv) {
				dict *ht = kv->u;
				while (kv->k != MHTNO) {
					mylistrefs (ht, UT64_MAX, list);
					kv++;
				}
			}
		}
	} else {
		dict *d = dict_getu (m, addr);
		if (!d) {
			return;
		}
		mylistrefs (d, addr, list);
		for (i = 0; i < m->size; i++) {
			dictkv *kv = m->table[i];
			if (kv) {
				while (kv->k != MHTNO) {
					if (kv->k == addr) {
						appendRef (list, kv->k, kv->v, kv->u);
					}
				//	mylistrefs (ht, UT64_MAX, list);
					kv++;
				}
			}
		}
	}
}

static void listxrefs(dict *m, ut64 addr, RList *list) {
	int i;
	if (addr == UT64_MAX) {
		for (i = 0; i < m->size; i++) {
			dictkv *kv = m->table[i];
			if (kv) {
				dict *ht = kv->u;
				while (kv->k != MHTNO) {
					mylistrefs (ht, UT64_MAX, list);
					kv++;
				}
			}
		}
	} else {
		dict *d = dict_getu (m, addr);
		if (!d) {
			return;
		}
		mylistrefs (d, addr, list);
	}
}

// [from=[from:to,],]
// 10->20
static void setref(dict *m, ut64 from, ut64 to, int type) {
	dict_set (m, from, to, r_anal_xrefs_type_tostring (type));
}

static void setxref(dict *m, ut64 from, ut64 to, int type) {
	dictkv *kv = dict_getr (m, from);
	dict *d = NULL;
	if (kv) {
		d = kv->u;
	} else {
		d = R_NEW0 (dict);
		if (d) {
			dict_init (d, 9, dict_free);
			dict_set (m, from, to, d);
		}
	}
	if (d) {
		dict_set (d, from, to, r_anal_xrefs_type_tostring (type));
	}
}

static void delref(dict *m, ut64 from, ut64 to, int type) {
	dict_del (m, to);
#if 0
	dictkv *kv = dict_getr (m, from);
	if (kv) {
		dict *ht = kv->u;
		if (ht) {
			dict_del (ht, to);
		}
	}
#endif
}
#endif

R_API int r_anal_xrefs_set (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	char key[33];
	if (!anal || !DB) {
		return false;
	}
	if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
		return false;
	}
	// unknown refs should not be stored. seems wrong
#if 0
	if (type == R_ANAL_REF_TYPE_NULL) {
		return false;
	}
#endif
#if USE_DICT
	eprintf ("Add ref %llx to %llx %c\n", from, to, type);
	setxref (anal->dict_xrefs, to, from, type);
	setxref (anal->dict_refs, from, to, type);
	// setref (anal->dict_refs, from, to, type);
//	setref (anal->dict_xrefs, from, to, type);
//	setref (anal->dict_refs, to, from, type);
// eprintf ("set %llx %llx %p\n", from , to, dict_getr(anal->dict_refs, from));
	// dict_getu(m, from, checkType, "ref");
#else
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_add_num (DB, key, to, 0);

	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_add_num (DB, key, from, 0);
#endif

	anal->ref_cache++;
	return true;
}

R_API int r_anal_xrefs_deln (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	char key[33];
	if (!anal || !DB) {
		return false;
	}
#if USE_DICT
	delref (anal->dict_refs, from, to, type);
	delref (anal->dict_xrefs, to, from, type);
#else
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_remove_num (DB, key, to, 0);
	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_remove_num (DB, key, from, 0);
#endif
	anal->ref_cache++;
	return true;
}

//static int xrefs_list_cb_any(RAnal *anal, const char *k, const char *v) {
//	//ut64 dst, src = r_num_get (NULL, v);
//	if (!strncmp (_kpfx, k, strlen (_kpfx))) {
//		RAnalRef *ref = r_anal_ref_new ();
//		eprintf ("K: %s V: %s\n", k, v);
//		if (ref) {
//			ref->addr = r_num_get (NULL, k + strlen (_kpfx) + 1);
//			ref->at = r_num_get (NULL, v); // XXX
//			ref->type = _type;
//			r_list_append (_list, ref);
//		}
//	}
//	return true;
//}

#if USE_DICT
R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	listrefs (anal->dict_refs, addr, list);
	return true;
}
#else
R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	char *next, *s, *str, *ptr, key[256];
	RAnalRef *ref = NULL;
	if (addr == UT64_MAX) {
		ut64 src, dst;
		SdbListIter *sdb_iter;
		SdbKv *kv;
		char *sdb_query = r_str_newf ("^%s.", kind);
		RAnalRefType t = R_ANAL_REF_TYPE_NULL;
		SdbList *sdb_list = sdb_foreach_match (DB, sdb_query, false);
		ls_foreach (sdb_list, sdb_iter, kv) {
			const char *p = r_str_rchr (kv->key, NULL, '.');
			if (p) {
				dst = r_num_get (NULL, p + 1);
				if (strstr (kv->key, "code.jmp")) {
					t = R_ANAL_REF_TYPE_CODE;
				} else if (strstr (kv->key, "code.call")) {
					t = R_ANAL_REF_TYPE_CALL;
				} else if (strstr (kv->key, "data.mem")) {
					t = R_ANAL_REF_TYPE_DATA;
				} else if (strstr (kv->key, "data.string")) {
					t = R_ANAL_REF_TYPE_STRING;
				}
			}
			const char *p2 = strchr (kv->value, ',');
			if (p2) {
				while (p2) {
					src = r_num_get (NULL, p2 + 1);
					ref = r_anal_ref_new ();
					ref->at = src;
					ref->addr = dst;
					ref->type = t;
					r_list_append (list, ref);
					p2 = strchr (p2 + 1, ',');
				}
			} else {
				src = r_num_get (NULL, kv->value);
				ref = r_anal_ref_new ();
				ref->at = src;
				ref->addr = dst;
				ref->type = t;
				r_list_append (list, ref);
			}
		}
		free (sdb_query);
		return true;
	}
	XREFKEY(key, sizeof (key), kind, type, addr);
	str = sdb_get (DB, key, 0);
	if (!str) {
		return false;
	}
	for (next = ptr = str; next; ptr = next) {
		s = sdb_anext (ptr, &next);
		if (!(ref = r_anal_ref_new ())) {
			return false;
		}
		ref->addr = r_num_get (NULL, s);
		ref->at = addr;
		ref->type = type;
		r_list_append (list, ref);
	}
	free (str);
	return true;
}
#endif

static void mylistrefs_cb(dict *m, RAnalRefCmp cmp, void *data, RList *list) {
	int i, j;
	for (i = 0; i < m->size; i++) {
		dictkv *kv = m->table[i];
		if (!kv) {
			continue;
		}
		while (kv->k != MHTNO) {
			RAnalRef ref;
			ref.at = kv->k;
			ref.addr = kv->v;
			ref.type = kv->u;
			if (cmp (&ref, data)) {
				appendRef (list, kv->k, kv->v, kv->u);
			}
			kv++;
		}
	}
}

static void listxrefs_cb(dict *m, RAnalRefCmp cmp, void *data, RList *ret) {
	int i;
	for (i = 0; i < m->size; i++) {
		dictkv *kv = m->table[i];
		if (kv) {
			dict *ht = kv->u;
			while (kv->k != MHTNO) {
				mylistrefs_cb (ht, cmp, data, ret);
				kv++;
			}
		}
	}
}

R_API RList *r_anal_xref_get_cb (RAnal *anal, RAnalRefCmp cmp, void *data) {
	RList *ret = r_list_newf (r_anal_ref_free);
	listxrefs_cb (anal->dict_xrefs, cmp, data, ret);
	return ret;
}

R_API RList *r_anal_ref_get_cb (RAnal *anal, RAnalRefCmp cmp, void *data) {
	RList *ret = r_list_newf (r_anal_ref_free);
	listxrefs_cb (anal->dict_refs, cmp, data, ret);
	return ret;
}

R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 to) {
	RList *list = r_list_newf (r_anal_ref_free);
	if (!list) {
		return NULL;
	}
#if USE_DICT
	// listrefs (anal->dict_refs, to, list);
// XXX, one or the other?
	listxrefs (anal->dict_xrefs, to, list);
	// listrefs (anal->dict_xrefs, to, list);
#else
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_NULL, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_CODE, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_CALL, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_DATA, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_STRING, to);
#endif
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_refs_get (RAnal *anal, ut64 from) {
	RList *list = r_list_newf (r_anal_ref_free);
	if (!list) {
		return NULL;
	}
#if USE_DICT
//	listrefs (anal->dict_refs, from, list);
	listxrefs (anal->dict_xrefs, from, list);
// eprintf ("refs_get from %llx %d\n", from, r_list_length (list));
#else
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_NULL, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CODE, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CALL, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_DATA, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_STRING, from);
#endif
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_xrefs_get_from (RAnal *anal, ut64 to) {
	RList *list = r_list_newf (NULL);
	if (!list) {
		return NULL;
	}
#if USE_DICT
	listxrefs (anal->dict_xrefs, to, list);
	//listrefs (anal->dict_refs, to, list);
#else
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_NULL, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CODE, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CALL, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_DATA, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_STRING, to);
#endif
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API bool r_anal_xrefs_init(RAnal *anal) {
	sdb_reset (DB);
	if (DB) {
		sdb_array_set (DB, "types", -1, "code.jmp,code.call,data.mem,data.string", 0);
		return true;
	}
	return false;
}

static int xrefs_list_cb_rad(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4)) {
		const char *p = r_str_rchr (k, NULL, '.');
		if (p) {
			dst = r_num_get (NULL, p + 1);
			anal->cb_printf ("ax 0x%"PFMT64x" 0x%"PFMT64x"\n", src, dst);
		}
	}
	return 1;
}

static int xrefs_list_cb_quiet(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4)) {
		const char *p = r_str_rchr (k, NULL, '.');
		if (p) {
			dst = r_num_get (NULL, p + 1);
			char * type = strchr (k, '.');
			if (type) {
				type = strdup (type + 1);
				char *t = strchr (type, '.');
				if (t) {
					*t = ' ';
				}
				char *T = (char *)r_str_rchr (type, NULL, '.');
				if (T) {
					T = (char *)r_str_rchr (T, NULL, '.');
					if (T) {
						*T = 0;
						anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s\n", src, dst, type);
					}
				} else {
					if (t) {
						*t = 0;
					}
				}
				anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s\n", src, dst, type);
				free (type);
			}
		}
	}
	return 1;
}

static int xrefs_list_cb_normal(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4)) {
		const char *p = r_str_rchr (k, NULL, '.');
		if (p) {
			dst = r_num_get (NULL, p + 1);
			char * type = strchr (k, '.');
			if (type) {
				type = strdup (type + 1);
				char *ot = strchr (type, '.');
				if (ot) {
					*ot = ' ';
				}
				char *t = (char *)r_str_rchr (type, NULL, '.');
				if (t) {
					t = (char *)r_str_rchr (t, NULL, '.');
					if (t) {
						*t = 0;
					}
				} else {
					if (ot) {
						*ot = 0;
					}
				}
				{
					char *name = anal->coreb.getNameDelta (anal->coreb.core, src);
					r_str_replace_char (name, ' ', 0);
					anal->cb_printf ("%40s", name? name: "");
					free (name);
					anal->cb_printf (" 0x%"PFMT64x" -> %9s -> 0x%"PFMT64x, src, type, dst);
					name = anal->coreb.getNameDelta (anal->coreb.core, dst);
					r_str_replace_char (name, ' ', 0);
					if (name && *name) {
						anal->cb_printf (" %s\n", name);
					} else {
						anal->cb_printf ("\n");
					}
					free (name);
				}
				free (type);
			}
		}
	}
	return 1;
}

static bool xrefs_list_cb_json(RAnal *anal, bool is_first, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (strlen (k) > 8) {
		const char *p = r_str_rchr (k, NULL, '.');
		if (p) {
			if (is_first) {
				is_first = false;
			} else {
				anal->cb_printf (",");
			}
			dst = r_num_get (NULL, p + 1);
			sscanf (p + 1, "0x%"PFMT64x, &dst);
			anal->cb_printf ("\"%"PFMT64d"\":%"PFMT64d, src, dst);
		}
	}
	return is_first;
}

static int xrefs_list_cb_plain(RAnal *anal, const char *k, const char *v) {
	anal->cb_printf ("%s=%s\n", k, v);
	return 1;
}

R_API void r_anal_xrefs_list(RAnal *anal, int rad) {
#if USE_DICT
	RListIter *iter;
	RAnalRef *ref;
	RList *list = r_list_new();
	listxrefs (anal->dict_xrefs, UT64_MAX, list);
	r_list_foreach (list, iter, ref) {
		int type = ref->type? ref->type: ' ';
		r_cons_printf ("%c 0x%08llx -> 0x%08llx\n", type, ref->at, ref->addr);
	}
	r_list_free (list);
#else
	switch (rad) {
	case 1:
	case '*':
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_rad, anal);
		break;
	case '\0':
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_normal, anal);
		break;
	case 'q':
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_quiet, anal);
		break;
	case 'j':
		{
		anal->cb_printf ("{");
		bool is_first = true;
		SdbListIter *sdb_iter;
		SdbKv *kv;
		SdbList *sdb_list = sdb_foreach_match (DB, "^ref.", false);
		ls_foreach (sdb_list, sdb_iter, kv) {
			is_first = xrefs_list_cb_json (anal, is_first, kv->key, kv->value);
		}
		ls_free (sdb_list);
		anal->cb_printf ("}\n");
		}
		break;
	default:
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_plain, anal);
		break;
	}
#endif
}

R_API const char *r_anal_xrefs_type_tostring (char type) {
	switch (type) {
	case R_ANAL_REF_TYPE_CODE:
		return "JMP";
	case R_ANAL_REF_TYPE_CALL:
		return "CALL";
	case R_ANAL_REF_TYPE_DATA:
		return "DATA";
	case R_ANAL_REF_TYPE_STRING:
		return "STRING";
	case R_ANAL_REF_TYPE_NULL:
	default:
		return "UNKNOWN";
	}
}

typedef struct {
	RAnal *anal;
	int count;
} CountState;

static int countcb(CountState *cs, const char *k, const char *v) {
	if (!strncmp (k, "ref.", 4)) {
		cs->count ++;
	}
	return 1;
}

R_API int r_anal_xrefs_count(RAnal *anal) {
	CountState cs = { anal, 0 };
	sdb_foreach (DB, (SdbForeachCallback)countcb, &cs);
	return cs.count;
}
