/* radare - LGPL - Copyright 2015 - pancake, nibble */

#include <r_anal.h>

typedef void (*RAnalEsilPin)(RAnal *a);

#if 0
// TODO: those hardcoded functions should go
/* default pins from libc */
static void pin_strlen(RAnal *a) {
	// get a0 register
	// read memory and interpret it as a string
	// set a0 to the result of strlen;
	eprintf ("esilpin: strlen\n");
}

static void pin_write(RAnal *a) {
	// get a0 register for fd
	// get a1 register for data
	// get a2 register for len
	// read len bytes from data and print them to screen + fd
	// set a0 to the result of write;
	eprintf ("esilpin: write\n");
}
#endif

/* pin api */

#define DB a->sdb_pins

R_API void r_anal_pin_init(RAnal *a) {
	sdb_free (DB);
	DB = sdb_new0();
//	sdb_ptr_set (DB, "strlen", pin_strlen, 0);
//	sdb_ptr_set (DB, "write", pin_write, 0);
}

R_API void r_anal_pin_fini(RAnal *a) {
	if (sdb_free (DB)) {
		DB = NULL;
	}
}

R_API void r_anal_pin(RAnal *a, ut64 addr, const char *name) {
	char buf[64];
	const char *key = sdb_itoa (addr, buf, 16);
	sdb_set (DB, key, name, 0);
}

R_API void r_anal_pin_unset(RAnal *a, ut64 addr) {
	char buf[64];
	const char *key = sdb_itoa (addr, buf, 16);
	sdb_unset (DB, key, 0);
}

R_API const char *r_anal_pin_call(RAnal *a, ut64 addr) {
	char buf[64];
	const char *key = sdb_itoa (addr, buf, 16);
	if (key) {
		return sdb_const_get (DB, key, NULL);
#if 0
		const char *name;
		if (name) {
			RAnalEsilPin fcnptr = (RAnalEsilPin)
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
		a->cb_printf ("%s = %s\n", k, v);
	} else {
		// ptr
		a->cb_printf ("PIN %s\n", k);
	}
	return true;
}

R_API void r_anal_pin_list(RAnal *a) {
	sdb_foreach (DB, cb_list, a);
}
