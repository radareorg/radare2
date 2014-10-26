/* radare - LGPL - Copyright 2013 - pancake */

#include "r_anal.h"

R_API int r_anal_type_set(RAnal *anal, ut64 at, const char *field, ut64 val) {
	Sdb *DB = anal->sdb_types;
	const char *kind;
	char var[128];
	sprintf (var, "link.%08"PFMT64x, at);
	kind = sdb_const_get (DB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get (DB, kind, NULL);
		if (p) {
			snprintf (var, sizeof (var), "%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num (DB, var, 1, NULL);
			//int siz = sdb_array_get_num (DB, var, 2, NULL);
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
	const char *kind = sdb_const_get (DB, name, 0);
	snprintf (str, sizeof (str), "%s.%s", kind, name);

#define SDB_FOREACH(x,y,z) for (z = 0; (p = sdb_array_get (x, y, z, NULL)); z++)
#define SDB_FOREACH_NEXT() free(p)
	SDB_FOREACH (DB, str, n) {
		snprintf (str2, sizeof (str2), "%s.%s", str, p);
		sdb_unset (DB, str2, 0);
		SDB_FOREACH_NEXT ();
	}
	sdb_set (DB, name, NULL, 0);
	sdb_unset (DB, name, 0);
	sdb_unset (DB, str, 0);
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

#if UNUSED_CODE
// Define local vars using ctypes! this is code reuse!
// ctypes must store get/set access?
// where's the scope?
R_API int r_anal_type_frame (RAnal *anal, ut64 addr, const char *type, const char *name, int off, int size) {
	Sdb *DB = anal->sdb_types;
	// TODO: check if type already exists and return false
	sdb_queryf (DB, "frame.%08"PFMT64x".%s=%s,%d,%d",
		addr, name, type, off, size);
	sdb_queryf (DB,
		"frame.%08"PFMT64x"=%s", addr, name);
	return R_TRUE;
	
}

R_API int r_anal_type_frame_del (RAnal *anal, ut64 addr, const char *name) {
	//"(-)frame.%08"PFMT64x"=%s", addr, name
	//"frame.%08"PFMT64x".%s=", addr, name
	return R_TRUE;
}
#endif

R_API int r_anal_type_link (RAnal *anal, const char *type, ut64 addr) {
	char laddr[128];
	if (sdb_const_get (anal->sdb_types, type, 0)) {
		snprintf (laddr, sizeof (laddr)-1, "link.%08"PFMT64x, addr);
		sdb_set (anal->sdb_types, laddr, type, 0);
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
	int n, m;
	char *p, *q, var[128], var2[128], var3[128];
	char *fmt = NULL;
	char *vars = NULL;
	Sdb *DB = anal->sdb_types;
	const char *kind = sdb_const_get (DB, t, NULL);
	if (!kind) return NULL;
	// only supports struct atm
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_get (DB, var, NULL);
		if (fmt)
			return strdup (fmt);
	} else
	if (!strcmp (kind, "struct")) {
		// assumes var list is sorted by offset.. should do more checks here
		for (n = 0; (p = sdb_array_get (DB, var, n, NULL)); n++) {
			const char *tfmt;
			char *type, *type2;
			//int off;
			//int size;
			snprintf (var2, sizeof (var2), "%s.%s", var, p);
			type = sdb_array_get (DB, var2, 0, NULL);
			if (type) {
				//off = sdb_array_get_num (DB, var2, 1, NULL);
				//size = sdb_array_get_num (DB, var2, 2, NULL);
				if (!strncmp (type, "struct ", 7)) {
					// TODO: iterate over all the struct fields, and format the format and vars
					snprintf (var3, sizeof (var3), "struct.%s", type+7);
					for (m = 0; (q = sdb_array_get (DB, var3, m, NULL)); m++) {
						snprintf (var2, sizeof (var2), "%s.%s", var3, q);
						type2 = sdb_array_get (DB, var2, 0, NULL); // array of type, size, ..
						if (type2) {
							char var4[128];
							snprintf (var4, sizeof (var4), "type.%s", type2);
							tfmt = sdb_const_get (DB, var4, NULL);
							if (tfmt) {
								filter_type (type2);
								fmt = r_str_concat (fmt, tfmt);
								vars = r_str_concat (vars, q);
								vars = r_str_concat (vars, " ");
							} else eprintf ("Cannot resolve type '%s'\n", var3);
						} else eprintf ("Cannot resolve type '%s'\n", var2);
						free (type2);
						free (q);
					}
				} else {
					snprintf (var3, sizeof (var3), "type.%s", type);
					tfmt = sdb_const_get (DB, var3, NULL);
					if (tfmt) {
						filter_type (type);
						fmt = r_str_concat (fmt, tfmt);
						vars = r_str_concat (vars, p);
						vars = r_str_concat (vars, " ");
					} else eprintf ("Cannot resolve type '%s'\n", var3);
				}
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

#if 0
//NOTES FROM THE OLD CPARSE IMPLEMENTATION
enum {
	R_ANAL_TYPE_VARIABLE = 1,
	R_ANAL_TYPE_POINTER = 2,
	R_ANAL_TYPE_ARRAY = 3,
	R_ANAL_TYPE_STRUCT = 4,
	R_ANAL_TYPE_UNION = 5,
	R_ANAL_TYPE_ALLOCA = 6,
	R_ANAL_TYPE_FUNCTION = 7,
	R_ANAL_TYPE_ANY = 8,
};

// [0:3] bits - place to store variable size
#define R_ANAL_VAR_TYPE_SIZE_MASK 0xF

enum {
	R_ANAL_VAR_TYPE_CHAR = 1,
	R_ANAL_VAR_TYPE_BYTE = 2,
	R_ANAL_VAR_TYPE_WORD = 3,
	R_ANAL_VAR_TYPE_DWORD = 4,
	R_ANAL_VAR_TYPE_QWORD = 5,
	R_ANAL_VAR_TYPE_SHORT = 6,
	R_ANAL_VAR_TYPE_INT = 7,
	R_ANAL_VAR_TYPE_LONG = 8,
	R_ANAL_VAR_TYPE_LONGLONG = 9,
	R_ANAL_VAR_TYPE_FLOAT = 10,
	R_ANAL_VAR_TYPE_DOUBLE = 11,
	R_ANAL_VAR_TYPE_VOID = 12,
};


// [4:7] bits - place to store sign of variable
#define R_ANAL_VAR_TYPE_SIGN_MASK 0xF0
#define R_ANAL_VAR_TYPE_SIGN_SHIFT 4

enum {
	R_ANAL_VAR_TYPE_SIGNED = 1,
	R_ANAL_VAR_TYPE_UNSIGNED = 2,
};

// [8:11] bits - place to store variable modifiers/parameters
#define R_ANAL_VAR_TYPE_MODIFIER_MASK 0xF00
#define R_ANAL_VAR_TYPE_MODIFIER_SHIFT 8

enum {
	R_ANAL_VAR_TYPE_REGISTER = 1,
	R_ANAL_VAR_TYPE_CONST = 2,
	R_ANAL_VAR_TYPE_STATIC = 3,
	R_ANAL_VAR_TYPE_VOLATILE = 4,
};
#endif
