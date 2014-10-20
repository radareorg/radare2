/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <r_anal.h>
#include <sdb.h>

#define DB anal->sdb_xrefs

static void XREFKEY(char * const key, const size_t key_len,
	char const * const kind, const RAnalRefType type, const ut64 addr) {
	char const * _sdb_type = "unk";
	switch (type) {
	case R_ANAL_REF_TYPE_NULL:
		_sdb_type = "unk";
		break;
	case R_ANAL_REF_TYPE_CODE:
		_sdb_type = "code.jmp";
		break;
	case R_ANAL_REF_TYPE_CALL:
		_sdb_type = "code.call";
		break;
	case R_ANAL_REF_TYPE_DATA:
		_sdb_type = "data.mem";
		break;
	case R_ANAL_REF_TYPE_STRING:
		_sdb_type = "data.string";
		break;
	}
	snprintf (key, key_len, "%s.%s.0x%"PFMT64x, kind, _sdb_type, addr);
}

R_API int r_anal_xrefs_load(RAnal *anal, const char *prjfile) {
        char *path, *db = r_str_newf (R2_HOMEDIR"/projects/%s.d", prjfile);
	if (!db) return R_FALSE;
	path = r_str_home (db);
	if (!path) {
		free (db);
		return R_FALSE;
	}
	sdb_free (DB);
	DB = sdb_new (path, "xrefs", 0);
	if (!DB) {
		free (db);
		free (path);
		return R_FALSE;
	}
	sdb_ns_set (anal->sdb, "xrefs", DB);
	free (path);
	free (db);
	return R_TRUE;
}

R_API void r_anal_xrefs_save(RAnal *anal, const char *prjfile) {
	sdb_sync (anal->sdb_xrefs);
}

R_API int r_anal_xrefs_set (RAnal *anal, const RAnalRefType type,
			     ut64 from, ut64 to) {
	char key[32];
	if (!anal || !DB)
		return R_FALSE;
	// unknown refs should not be stored. seems wrong
	if (type == R_ANAL_REF_TYPE_NULL) {
		return R_FALSE;
	}
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_add_num (DB, key, to, 0);
	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_add_num (DB, key, from, 0);
	return R_TRUE;
}

R_API int r_anal_xrefs_deln (RAnal *anal, const RAnalRefType type, ut64 from, ut64 to) {
	char key[32];
	if (!anal || !DB)
		return R_FALSE;
	XREFKEY (key, sizeof (key), "ref", type, from);
	sdb_array_remove_num (DB, key, to, 0);
	XREFKEY (key, sizeof (key), "xref", type, to);
	sdb_array_remove_num (DB, key, from, 0);
	return R_TRUE;
}

R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const RAnalRefType type, ut64 addr) {
	char *next, *s, *str, *ptr, key[256];
	RAnalRef *ref = NULL;
	XREFKEY(key, sizeof (key), kind, type, addr);
	str = sdb_get (DB, key, 0);
	if (!str) return R_FALSE;
	for (ptr=str; ; ptr = next) {
		s = sdb_anext (ptr, &next);
		if (!(ref = r_anal_ref_new ()))
			return R_FALSE;
		ref->addr = r_num_get (NULL, s);
		ref->at = addr;
		ref->type = type;
		r_list_append (list, ref);
		if (!next)
			break;
	}
	free (str);
	return R_TRUE;
}

R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 to) {
	RList *list = r_list_new ();
	list->free = NULL; // XXX
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

R_API RList *r_anal_xrefs_get_from (RAnal *anal, ut64 to) {
	RList *list = r_list_new ();
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

R_API int r_anal_xrefs_init (RAnal *anal) {
	sdb_reset (DB);
	if (!DB) return R_FALSE;
	sdb_array_set (DB, "types", -1, "code.jmp,code.call,data.mem,data.string", 0);
	return R_TRUE;
}

static int xrefs_list_cb_rad(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4)) {
		char *p = strchr (k+4, '.');
		if (p) {
			dst = r_num_get (NULL, p+1);
			anal->printf ("ax 0x%"PFMT64x" 0x%"PFMT64x"\n", src, dst);
		}
	}
	return 1;
}

static int xrefs_list_cb_json(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4) && (strlen (k)>8)) {
		char *p = strchr (k+4, '.');
		if (p) {
			dst = r_num_get (NULL, p+1);
			sscanf (p+1, "0x%"PFMT64x, &dst);
			anal->printf ("%"PFMT64d":%"PFMT64d",", src, dst);
		}
	}
	return 1;
}

static int xrefs_list_cb_plain(RAnal *anal, const char *k, const char *v) {
	anal->printf ("%s=%s\n", k, v);
	return 1;
}

R_API void r_anal_xrefs_list(RAnal *anal, int rad) {
	switch (rad) {
	case 1:
	case '*':
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_rad, anal);
		break;
	case 'j':
		anal->printf ("{");
		sdb_foreach (DB, (SdbForeachCallback)xrefs_list_cb_json, anal);
		anal->printf ("}\n");
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

