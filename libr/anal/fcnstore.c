/* this file contains a test implementation of the ~O(1) function search */

#define RANGEBITS 10
#define RANGE (1<<RANGEBITS)
#include <r_anal.h>

RAnalFcnStore* hl_new() {
	RAnalFcnStore *s = R_NEW (RAnalFcnStore);
	s->h = r_hashtable64_new();
	s->l = r_list_new();
	return s;
}

static inline ut64 hl_key(ut64 addr) {
	return (addr >> RANGEBITS);
}

static inline ut64 hl_next(ut64 addr) {
	return (addr + RANGE);
}

void hl_free(RAnalFcnStore *s) {
	r_hashtable64_free (s->h);
	r_list_destroy (s->l);
	free (s);
}

static int cmpfun(void *a, void *b) {
	// TODO
	return 0;
}

void hl_add(RAnalFcnStore *s, RAnalFcn *f) {
	ut64 addr;
	RList *list;
	ut64 from = f->addr;
	ut64 to = f->addr + f->size;
	for (addr = from; addr<to; addr = hl_next (addr)) {
		list = r_hashtable64_lookup (s->h, hl_key (addr));
		if (!list) list = r_list_new ();
		if (!r_list_contains (list, f)) // double rainbow :(
			r_list_add_sorted (list, f, cmpfun);
	}
}

void hl_del(RAnalFcnStore *s, RAnalFcn *f) {
	// TODO
	
}

RAnalFcn *hl_find(RAnalFcnStore* s, ut64 addr) {
	RAnalFcn *f;
	RListIter *iter;
	RList *list = r_hashtable64_lookup (s->h, hl_key (addr));
	if (list)
	r_list_foreach (list, iter, f) {
		if (addr >= f->addr && (addr < f->addr+f->size))
			return f;
	}
	return NULL;
}

#if 0
main() {
	RHashTable64 *h = hl_new();
	hl_add (h, f1);
}
#endif
