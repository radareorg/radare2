/* radare - LGPL - Copyright 2011-2016 - pancake, Oddcoder */

/* Universal calling convention implementation based on sdb */

#include <r_anal.h>
#define DB anal->sdb_cc

R_API bool r_anal_cc_exist (RAnal *anal, const char *convention) {
	r_return_val_if_fail (anal && convention, false);
	const char *x = sdb_const_get (DB, convention, 0);
	return x && *x && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_arg(RAnal *anal, const char *convention, int n) {
	r_return_val_if_fail (anal && convention, NULL);
	if (n < 1) {
		return NULL;
	}
	const char *query = sdb_fmt ("cc.%s.arg%d", convention, n);
	const char *ret = sdb_const_get (DB, query, 0);
	if (!ret) {
		query = sdb_fmt ("cc.%s.argn", convention);
		ret = sdb_const_get (DB, query, 0);
	}
	return ret;

}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int ret = 0;
	const char *query, *res;
	r_return_val_if_fail (anal && cc, 0);
	do {
		query = sdb_fmt ("cc.%s.arg%d", cc, ret + 1);
		res = sdb_const_get (DB, query, 0);
		if (res) {
			ret++;
		}
	} while (res && ret < 6);
	return ret;
}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention) {
	r_return_val_if_fail (anal && convention, NULL);
	char *query = sdb_fmt ("cc.%s.ret", convention);
	return sdb_const_get (DB, query, 0);
}

R_API const char *r_anal_cc_default(RAnal *anal) {
	r_return_val_if_fail (anal, NULL);
	return sdb_const_get (DB, "default.cc", 0);
}

R_API const char *r_anal_cc_func(RAnal *anal, const char *func_name) {
	r_return_val_if_fail (anal && func_name, NULL);
	const char *query = sdb_fmt ("func.%s.cc", func_name);
	const char *cc = sdb_const_get (anal->sdb_types, query, 0);
	return cc ? cc : r_anal_cc_default (anal);
}

R_API const char *r_anal_cc_to_constant(RAnal *anal, char *convention) {
	r_return_val_if_fail (anal && convention, NULL);
	char *query = sdb_fmt ("cc.%s.name", convention);
	return sdb_const_get (DB, query, 0);
}
