/* radare - LGPL - Copyright 2011 -- pancake<nopcode.org> */
/* this file contains a test implementation of the ~O(1) function search */

// TODO: REFACTOR: This must be a generic data structure named RListRange
// TODO: We need a standard struct named Surface1D {.addr, .size}, so we can
// simplify all this by just passing the offset of the field of the given ptr
// TODO: RListComparator does not supports *user
// TODO: RRef - reference counting

#define RANGEBITS 10
// 1024
#define RANGE (1<<RANGEBITS)
#include <r_anal.h>
#if USE_NEW_FCN_STORE

static int cmpfun(void *a, void *b) {
	RAnalFunction *fa = (RAnalFunction*)a;
	RAnalFunction *fb = (RAnalFunction*)b;
	// TODO: swap sort order here or wtf?
	return (fb->addr - fa->addr);
}

R_API RListRange* r_listrange_new () {
	RListRange *s = R_NEW (RListRange);
	s->h = r_hashtable64_new ();
	s->l = r_list_new ();
	return s;
}

// FIXME: Do not hardcode such things/values!!!
static inline ut64 r_listrange_key(ut64 addr) {
	const ut64 KXOR = 0x18abc3e127d549ac; // XXX wrong for mingw32
	ut64 key = addr & 0xfffffffffffff400;
	key ^= KXOR;
	//eprintf ("%llx = %llx\n", addr, key);
	return key;
	//return (addr >> RANGEBITS);
}

static inline ut64 r_listrange_next(ut64 addr) {
	return (addr + RANGE);
}

R_API void r_listrange_free(RListRange *s) {
	if (!s) return;
	r_hashtable64_free (s->h);
	r_list_free (s->l);
	free (s);
}

R_API void r_listrange_add(RListRange *s, RAnalFunction *f) {
	ut64 addr;
	RList *list;
	ut64 from = f->addr;
	ut64 to = f->addr + f->size;
	for (addr = from; addr<to; addr = r_listrange_next (addr)) {
		ut64 key = r_listrange_key (addr);
		list = r_hashtable64_lookup (s->h, key);
		if (list) {
			if (!r_list_contains (list, f))
			//r_list_add_sorted (list, f, cmpfun);
			r_list_append (list, f);
		} else {
			list = r_list_new ();
			//r_list_add_sorted (list, f, cmpfun);
			r_list_append (list, f);
			r_hashtable64_insert (s->h, key, list);
		}
	}
	r_list_add_sorted (s->l, f, cmpfun);
}

R_API void r_listrange_del(RListRange *s, RAnalFunction *f) {
	RList *list;
	ut64 addr, from, to;
	if (!f) return;
	from = f->addr;
	to = f->addr + f->size;
	for (addr = from; addr<to; addr = r_listrange_next (addr)) {
		list = r_hashtable64_lookup (s->h, r_listrange_key (addr));
		if (list) r_list_delete_data (list, f);
	}
	r_list_delete_data (s->l, f);
}

R_API void r_listrange_resize(RListRange *s, RAnalFunction *f, int newsize) {
	if (!f) return;
	r_listrange_del (s, f);
	f->size = newsize;
	r_listrange_add (s, f);
}

R_API RAnalFunction *r_listrange_find_in_range(RListRange* s, ut64 addr) {
	RAnalFunction *f;
	RListIter *iter;
	RList *list = r_hashtable64_lookup (s->h, r_listrange_key (addr));
	if (list)
	r_list_foreach (list, iter, f) {
		if (R_BETWEEN (f->addr, addr, f->addr+f->size))
			return f;
	}
	return NULL;
}

R_API RAnalFunction *r_listrange_find_root(RListRange* s, ut64 addr) {
	RAnalFunction *f;
	RListIter *iter;
	RList *list = r_hashtable64_lookup (s->h, r_listrange_key (addr));
	if (list)
	r_list_foreach (list, iter, f) {
		if (addr == f->addr)
			return f;
	}
	return NULL;
}

#endif
