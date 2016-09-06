/* radare - LGPL - Copyright 2011-2016 - pancake, Oddcoder */

/* Universal calling convention implementation based on sdb */

#include <r_anal.h>
#define DB anal->sdb_cc

R_API int r_anal_cc_exist (RAnal *anal, const char *convention) {
	const char *x = sdb_const_get (DB, convention, 0);
	return x && *x && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_arg(RAnal *anal, const char *convention, int n) {
	const char *query, *ret;
	if (n < 1) {
		return 0;
	}
	query = sdb_fmt (-1, "cc.%s.arg%d", convention, n);
	ret = sdb_const_get (DB, query, 0);
	if (!ret) {
		query = sdb_fmt (-1, "cc.%s.argn", convention);
		ret = sdb_const_get (DB, query, 0);
	}
	return ret;

}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention) {
	char *query = sdb_fmt (-1, "cc.%s.ret", convention);
	return sdb_const_get (DB, query, 0);
}

R_API const char *r_anal_cc_default(RAnal *anal) {
	return sdb_const_get (DB, "default.cc", 0);
}

R_API const char *r_anal_cc_to_constant(RAnal *anal, char *convention) {
	char *query = sdb_fmt (-1, "cc.%s.name", convention);
	return sdb_const_get (DB, query, 0);
}
