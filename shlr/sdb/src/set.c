/* sdb - MIT - Copyright 2019 - pancake */

#include "set.h"

// p

SDB_API SetP *set_p_new(void) {
	return ht_pp_new0 ();
}

SDB_API void set_p_add(SetP *s, void *u) {
	ht_pp_insert (s, u, (void*)1);
}

SDB_API bool set_p_contains(SetP *s, void *u) {
	return ht_pp_find (s, u, NULL) != NULL;
}

SDB_API void set_p_delete(SetP *s, void *u) {
	ht_pp_delete (s, u);
}

SDB_API void set_p_free(SetP *p) {
	ht_pp_free ((HtPP*)p);
}

// u

SDB_API SetU *set_u_new(void) {
	return (SetU*)ht_up_new0 ();
}

SDB_API void set_u_add(SetU *s, ut64 u) {
	ht_up_insert (s, u, (void*)1);
}

SDB_API bool set_u_contains(SetU *s, ut64 u) {
	return ht_up_find (s, u, NULL) != NULL;
}

SDB_API void set_u_delete(SetU *s, ut64 u) {
	ht_up_delete (s, u);
}

SDB_API void set_u_free(SetU *s) {
	ht_up_free (s);
}
