/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_anal.h>

R_API int r_anal_function_instrcount(RAnalFunction *fcn) {
	int amount = 0;
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		amount += bb->ninstr;
	}
	return amount;
}

R_API bool r_anal_function_islineal(RAnalFunction *fcn) {
	if (r_anal_function_linear_size (fcn) != r_anal_function_realsize (fcn)) {
		return false;
	}
	RListIter *iter;
	RAnalBlock *bb;
	ut64 at = r_anal_function_min_addr (fcn);
	bool found;
	ut64 end = r_anal_function_max_addr (fcn);
	for (at = fcn->addr; at < end; at ++) {
		found = false;
		r_list_foreach (fcn->bbs, iter, bb) {
			if (r_anal_block_contains (bb, at)) {
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
		at = bb->addr + bb->size - 1;
	}
	return true;
}

// pin.c

R_API const char *r_anal_pin_get(RAnal *a, const char *name) {
	r_strf_buffer (128);
	char *ckey = r_strf ("cmd.%s", name);
	return sdb_const_get (a->sdb_pins, ckey, NULL);
}

R_API const char *r_anal_pin_at(RAnal *a, ut64 addr) {
	char buf[SDB_NUM_BUFSZ];
	const char *key = sdb_itoa (addr, 16, buf, sizeof (buf));
	return sdb_const_get (a->sdb_pins, key, NULL);
}

R_API bool r_anal_pin_set(RAnal *a, const char *name, const char *cmd) {
	r_strf_buffer (128);
	char *ckey = r_strf ("cmd.%s", name);
	return sdb_add (a->sdb_pins, ckey, cmd, 0);
}

typedef void (*REsilPin)(RAnal *a);

/* pin api */

#define DB a->sdb_pins

R_API void r_anal_pin_init(RAnal *a) {
	sdb_free (DB);
	DB = sdb_new0 ();
	r_anal_pin_set (a, "strlen", "dr R0=`pszl@r:A0`;aexa ret");
	r_anal_pin_set (a, "memcpy", "wf `dr?A1` `dr?A2` @ `dr?A0`;aexa ret");
	r_anal_pin_set (a, "puts", "psz@r:A0; aexa ret");
	r_anal_pin_set (a, "ret0", "dr R0=0;aexa ret");
//	sdb_ptr_set (DB, "strlen", pin_strlen, 0);
//	sdb_ptr_set (DB, "write", pin_write, 0);
}

R_API void r_anal_pin_fini(RAnal *a) {
	if (sdb_free (DB)) {
		DB = NULL;
	}
}

R_API void r_anal_pin(RAnal *a, ut64 addr, const char *name) {
	char buf[SDB_NUM_BUFSZ];
	const char *eq = strchr (name, '=');
	if (eq) {
		char *n = r_str_ndup (name, (int)(size_t)(eq -name));
		char *key = r_str_newf ("cmd.%s", n);
		free (n);
		sdb_set (DB, key, eq + 1, 0);
		free (key);
	} else {
		const char *key = sdb_itoa (addr, 16, buf, sizeof (buf));
		sdb_set (DB, key, name, 0);
	}
}

R_API void r_anal_pin_unset(RAnal *a, ut64 addr) {
	char buf[SDB_NUM_BUFSZ];
	const char *key = sdb_itoa (addr, 16, buf, sizeof (buf));
	sdb_unset (DB, key, 0);
}

R_API const char *r_anal_pin_call(RAnal *a, ut64 addr) {
	char buf[SDB_NUM_BUFSZ];
	const char *key = sdb_itoa (addr, 16, buf, sizeof (buf));
	if (key) {
		r_strf_buffer (128);
		const char *name = sdb_const_get (DB, key, NULL);
		if (!name) {
			return NULL;
		}
		if (r_str_startswith (name, "soft.")) {
			// do not call soft esil pins from here
			return NULL;
		}
		char *ckey = r_strf ("cmd.%s", name);
		const char *cmd = sdb_const_get (DB, ckey, NULL);
		if (R_STR_ISNOTEMPTY (cmd)) {
			a->coreb.cmdf (a->coreb.core, "%s", cmd);
			r_cons_flush ();
		} else { if (name && a->pincmd) {
			a->coreb.cmdf (a->coreb.core, "%s %s", a->pincmd, name);
			r_cons_flush ();
		}
		return name;
	}
#if 0
		const char *name;
		if (name) {
			REsilPin fcnptr = (REsilPin)
				sdb_ptr_get (DB, name, NULL);
			if (fcnptr) {
				fcnptr (a);
				return true;
			}
		}
#endif
	}
	return NULL;
}

static bool cb_list(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal*)user;
	if (*k == '0') {
		// bind
		a->cb_printf ("aep %s @ %s\n", v, k);
	//	a->cb_printf ("%s = %s\n", k, v);
	} else {
		if (r_str_startswith (k, "cmd.")) {
			a->cb_printf ("\"aep %s=%s\"\n", k + 4, v);
		} else {
			a->cb_printf ("\"aep %s\"\n", k);
		}
	}
	return true;
}

R_API void r_anal_pin_list(RAnal *a) {
	sdb_foreach (DB, cb_list, a);
}
