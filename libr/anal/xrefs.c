/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <r_anal.h>
#include <sdb.h>

#define DB anal->sdb_xrefs

R_API void r_anal_xrefs_load(RAnal *anal, const char *prjfile) {
        char *path, *db = r_str_newf (R2_HOMEDIR"/rdb/%s.d/xrefs", prjfile);
	path = r_str_home (db);
	//eprintf ("Open (%s)\n", path);
	sdb_free (DB);
	DB = sdb_new (path, "xrefs", 0);
	sdb_array_set (DB, "types", -1, "code,data", 0);
	free (db);
}

#define TODO(x) eprintf(__FUNCTION__"  "x)

R_API void r_anal_xrefs_save(RAnal *anal, const char *prjfile) {
	sdb_sync (anal->sdb_xrefs);
}

R_API RList *r_anal_xrefs_set (RAnal *anal, const char *type, ut64 from, ut64 to) {
	char key[32];
	snprintf (key, sizeof (key), "ref.%s.0x%"PFMT64x, type, from);
	sdb_array_add_num (DB, key, -1, to, 0);
	snprintf (key, sizeof (key), "xref.%s.0x%"PFMT64x, type, to);
	sdb_array_add_num (DB, key, -1, from, 0);
	// (-1)funfor.%d=%d
	return NULL;
}

R_API RList *r_anal_xrefs_deln (RAnal *anal, const char *type, ut64 from, ut64 to) {
	char key[32];
	snprintf (key, sizeof (key), "%s.0x%"PFMT64x, type, from);
	sdb_array_del_num (DB, key, to, 0);
	return NULL;
}

R_API int r_anal_xrefs_from (RAnal *anal, RList *list, const char *kind, const char *type, ut64 addr) {
	char *s, *str, *ptr, key[256];
	RAnalRef *ref = NULL;
	int hasnext = 1;
	snprintf (key, sizeof (key), "%s.%s.0x%"PFMT64x, kind, type, addr);
	str = sdb_get (DB, key, 0);
	if (!str) return R_FALSE;
	for (ptr=str; hasnext; ptr = (char *)sdb_array_next (s)) {
		s = sdb_array_string (ptr, &hasnext);
		if (!(ref = r_anal_ref_new ()))
			return R_FALSE;
		ref->addr = addr;
		ref->at = r_num_get (NULL, s);
		ref->type = (!strcmp (type, "code"))?'C':'d'; // XXX
		r_list_append (list, ref);
	}
	free (str);
	return R_TRUE;
}

// (in,out)[code,data]
R_API RList *r_anal_xrefs_get (RAnal *anal, ut64 addr) {
	RList *list = r_list_new ();
	list->free = NULL; // XXX
// XXX: not all!
	//r_anal_xrefs_from (anal, list, "xref", "code", addr);
	//r_anal_xrefs_from (anal, list, "xref", "data", addr);
	r_anal_xrefs_from (anal, list, "ref", "code", addr);
	r_anal_xrefs_from (anal, list, "ref", "data", addr);
	if (r_list_length (list)<1) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

R_API void r_anal_xrefs_init (RAnal *anal) {
	DB = NULL;
	DB = sdb_new (NULL, "xrefs", 0); // TODO
	sdb_array_set (DB, "types", -1, "code,data", 0);
#if 0
	//...
	r_anal_xrefs_get (anal, "code", 0);
#endif
}

static void xrefs_list_cb_rad(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4)) {
		char *p = strchr (k+4, '.');
		if (p) {
			dst = r_num_get (NULL, p+1);
			anal->printf ("ar 0x%"PFMT64x" 0x%"PFMT64x"\n", src, dst);
		}
	}
}

static void xrefs_list_cb_json(RAnal *anal, const char *k, const char *v) {
	ut64 dst, src = r_num_get (NULL, v);
	if (!strncmp (k, "ref.", 4) && (strlen (k)>8)) {
		char *p = strchr (k+4, '.');
		if (p) {
			dst = r_num_get (NULL, p+1);
			sscanf (p+1, "0x%"PFMT64x, &dst);
			anal->printf ("%"PFMT64d":%"PFMT64d",", src, dst);
		}
	}
}

static void xrefs_list_cb_plain(RAnal *anal, const char *k, const char *v) {
	anal->printf ("%s=%s\n", k, v);
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
