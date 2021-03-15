/* radare - LGPL - Copyright 2014-2020 - pancake, thestr4ng3r */

#include <r_anal.h>

HEAPTYPE (ut64);

R_API ut64 r_anal_function_get_label(RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (fcn, UT64_MAX);
	ut64 *addr = ht_pp_find (fcn->label_addrs, name, NULL);
	return addr? *addr: UT64_MAX;
}

R_API const char *r_anal_function_get_label_at(RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (fcn, NULL);
	return ht_up_find (fcn->labels, addr, NULL);
}

R_API bool r_anal_function_set_label(RAnalFunction *fcn, const char *name, ut64 addr) {
	r_return_val_if_fail (fcn && name, false);
	if (ht_pp_find (fcn->label_addrs, name, NULL)) {
		return false;
	}
	char *n = strdup (name);
	if (!ht_up_insert (fcn->labels, addr, n)) {
		free (n);
		return false;
	}
	ht_pp_insert (fcn->label_addrs, name, ut64_new (addr));
	return true;
}

R_API bool r_anal_function_delete_label(RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (fcn && name, false);
	ut64 *addr = ht_pp_find (fcn->label_addrs, name, NULL);
	if (!addr) {
		return false;
	}
	ht_up_delete (fcn->labels, *addr);
	ht_pp_delete (fcn->label_addrs, name);
	return true;
}

R_API bool r_anal_function_delete_label_at(RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (fcn, false);
	char *name = ht_up_find (fcn->labels, addr, NULL);
	if (!name) {
		return false;
	}
	ht_pp_delete (fcn->label_addrs, name);
	ht_up_delete (fcn->labels, addr);
	return true;
}
