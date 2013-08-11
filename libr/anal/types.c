/* radare - LGPL - Copyright 2013 - pancake */

#include "r_anal.h"

R_API void r_anal_type_del(RAnal *anal, const char *name) {
	Sdb *D = anal->sdb_types;
	const char *type = sdb_getc (D, name, 0);
	//sdb_getcf (D, "%s.%s", type, name);
	// foreach element, delete row
}

R_API char* r_anal_type_to_str(RAnal *a, RAnalType *t, const char *sep) {
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
