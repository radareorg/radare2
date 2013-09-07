/* radare - LGPL - Copyright 2013 - pancake */

#include "r_anal.h"

R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val) {
	Sdb *DB = anal->sdb_types;
	const char *kind;
	char var[128];
	sprintf (var, "link.%08"PFMT64x, at);
	kind = sdb_getc (DB, var, NULL);
	if (kind) {
		const char *p = sdb_getc (DB, kind, NULL);
		if (p) {
			snprintf (var, sizeof (var), "%s.%s.%s", p, kind, field);
			int off = sdb_agetn (DB, var, 1, NULL);
			int siz = sdb_agetn (DB, var, 2, NULL);
eprintf ("wv 0x%08"PFMT64x" @ 0x%08"PFMT64x, val, at+off);
			return R_TRUE;
		} else eprintf ("Invalid kind of type\n");
	}
	return R_FALSE;
}

R_API void r_anal_type_del(RAnal *anal, const char *name) {
	int n;
	char *p, str[128], str2[128];
	Sdb *DB = anal->sdb_types;
	const char *kind = sdb_getc (DB, name, 0);
	snprintf (str, sizeof (str), "%s.%s", kind, name);
	eprintf ("(((%s)))\n", str);

#define SDB_FOREACH(x,y,z) for (z = 0; (p = sdb_aget (x, y, z, NULL)); z++)
#define SDB_FOREACH_NEXT() free(p)
	SDB_FOREACH (DB, str, n) {
		snprintf (str2, sizeof (str2), "%s.%s", str, p);
		sdb_remove (DB, str2, 0);
		SDB_FOREACH_NEXT ();
	}
	sdb_set (DB, name, NULL, 0);
	sdb_remove (DB, name, 0);
	sdb_remove (DB, str, 0);
}

R_API char* r_anal_type_to_str(RAnal *a, const char *type) {
	// convert to C text... maybe that should be in format string..
	return NULL;
}

#if 0
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	return NULL;
}
#endif

R_API RList *r_anal_type_list_new() {
	return NULL;
}

R_API void r_anal_type_header (RAnal *anal, const char *hdr) {
}

R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value) {

}

R_API int r_anal_type_frame (RAnal *anal, ut64 addr, const char *type, const char *name, int off, int size) {
	Sdb *DB = anal->sdb_types;
	// TODO: check if type already exists and return false
	sdb_queryf (DB, "frame.%08"PFMT64x".%s=%s,%d,%d",
		addr, name, type, off, size);
	sdb_queryf (DB,
		"()frame.%08"PFMT64x"=%s", addr, name);
	return R_TRUE;
	
}

R_API int r_anal_type_frame_del (RAnal *anal, ut64 addr, const char *name) {
	//"(-)frame.%08"PFMT64x"=%s", addr, name
	//"frame.%08"PFMT64x".%s=", addr, name
}

R_API int r_anal_type_link (RAnal *anal, const char *val, ut64 addr) {
	char var[128];
	if (sdb_getc (anal->sdb_types, val, 0)) {
		sprintf (var, "link.%08"PFMT64x, addr);
		sdb_set (anal->sdb_types, var, val, 0);
		return R_TRUE;
	} 
	// eprintf ("Cannot find type\n");
	return R_FALSE;
}

static void filter_type(char *t) {
	for (;*t; t++) {
		if (*t == ' ')
			*t = '_';
		// memmove (t, t+1, strlen (t));
	}
}

R_API char *r_anal_type_format (RAnal *anal, const char *t) {
	int n;
	char *p, var[128], var2[128], var3[128];
	char *fmt = NULL;
	char *vars = NULL;
	Sdb *DB = anal->sdb_types;
	const char *kind = sdb_getc (DB, t, NULL);
	if (!kind) return NULL;
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_getc (DB, var, NULL);
		if (fmt)
			return strdup (fmt);
	} else
	if (!strcmp (kind, "struct")) {
		// assumes var list is sorted by offset.. should do more checks here
		for (n = 0; (p = sdb_aget (DB, var, n, NULL)); n++) {
			const char *tfmt;
			char *type;
			int off;
			int size;
			snprintf (var2, sizeof (var2), "%s.%s", var, p);
			type = sdb_aget (DB, var2, 0, NULL);
			if (type) {
				off = sdb_agetn (DB, var2, 1, NULL);
				size = sdb_agetn (DB, var2, 2, NULL);
				snprintf (var3, sizeof (var3), "type.%s", type);
				tfmt = sdb_getc (DB, var3, NULL);
				if (tfmt) {
					filter_type (type);
					fmt = r_str_concat (fmt, tfmt);
					vars = r_str_concat (vars, p);
					vars = r_str_concat (vars, " ");
				} else eprintf ("Cannot resolve type '%s'\n", type);
			}
			free (type);
			free (p);
		}
		fmt = r_str_concat (fmt, " ");
		fmt = r_str_concat (fmt, vars);
		free (vars);
		return fmt;
	}
	return NULL;
}
