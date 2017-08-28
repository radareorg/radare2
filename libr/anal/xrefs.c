/* radare - LGPL - Copyright 2009-2016 - pancake, nibble */

#include <r_anal.h>
#include <r_cons.h>
#include <sdb.h>

#define DB anal->sdb_xrefs

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
	char *xrefs_path = r_str_newf ("%s" R_SYS_DIR "xrefs.sdb", prjDir);
	sdb_file (anal->sdb_xrefs, xrefs_path);
	free (xrefs_path);
	return sdb_sync (anal->sdb_xrefs);
}

R_API int r_anal_xrefs_set (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	char key[33];
	if (!anal || !DB) {
		return false;
	}
	if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
		return false;
	}
	// unknown refs should not be stored. seems wrong
	if (type == R_ANAL_REF_TYPE_NULL) {
		return false;
	}
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_add_num (DB, key, to, 0);
	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_add_num (DB, key, from, 0);
	return true;
}

R_API int r_anal_xrefs_deln (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	char key[33];
	if (!anal || !DB) {
		return false;
	}
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_remove_num (DB, key, to, 0);
	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_remove_num (DB, key, from, 0);
	return true;
}

static int _type = -1;
static RList *_list = NULL;
static char *_kpfx = NULL;

static int xrefs_list_cb_any(RAnal *anal, const char *k, const char *v) {
	//ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (_kpfx, k, strlen (_kpfx))) {
		RAnalRef *ref = r_anal_ref_new ();
		if (ref) {
			ref->addr = r_num_get (NULL, k + strlen (_kpfx) + 1);
			ref->at = r_num_get (NULL, v); // XXX
			ref->type = _type;
			r_list_append (_list, ref);
		}
	}
	return true;
}

R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	char *next, *s, *str, *ptr, key[256];
	RAnalRef *ref = NULL;
	if (addr == UT64_MAX) {
		_type = type;
		_list = list;
		_kpfx = r_str_newf ("xref.%s", analref_toString (type));
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_any, anal);
		free (_kpfx);
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

R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 to) {
	RList *list = r_list_newf (r_anal_ref_free);
	if (!list) {
		return NULL;
	}
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_NULL, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_CODE, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_CALL, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_DATA, to);
	r_anal_xrefs_from (anal, list, "xref", R_ANAL_REF_TYPE_STRING, to);
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
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_NULL, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CODE, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CALL, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_DATA, from);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_STRING, from);
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API RList *r_anal_xrefs_get_from (RAnal *anal, ut64 to) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = NULL; // XXX
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_NULL, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CODE, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_CALL, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_DATA, to);
	r_anal_xrefs_from (anal, list, "ref", R_ANAL_REF_TYPE_STRING, to);
	if (r_list_length (list)<1) {
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
				type ++;
				type = strdup (type);
				char *t = strchr (type, '.');
				if (t) {
					*t = ' ';
				}
				t = (char *)r_str_rchr (type, NULL, '.');
				if (t) {
					t = (char *)r_str_rchr (t, NULL, '.');
					if (t) {
						*t = 0;
						anal->cb_printf ("0x%"PFMT64x" -> 0x%"PFMT64x"  %s\n", src, dst, type);
					}
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
	switch (rad) {
	case 1:
	case '*':
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_rad, anal);
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
	if (!strncmp (k, "ref.", 4))
		cs->count ++;
	return 1;
}

R_API int r_anal_xrefs_count(RAnal *anal) {
	CountState cs = { anal, 0 };
	sdb_foreach (DB, (SdbForeachCallback)countcb, &cs);
	return cs.count;
}
