/* radare - LGPL - Copyright 2009-2023 - pancake, nibble */

#include <r_anal.h>

typedef struct {
	HtUP *ht;
} RAnalBacktracesPrivate;

R_API void r_anal_backtrace_add(RAnal *a, ut64 addr, RVecBacktrace *bt) {
	RAnalBacktracesPrivate *b = a->btstore.priv;
	// save backtrace in given offset
	ht_up_insert (b->ht, addr, bt);
}

R_API void r_anal_backtrace_del(RAnal *a, ut64 addr) {
	RAnalBacktracesPrivate *b = a->btstore.priv;
	ht_up_delete (b->ht, addr);
}

typedef struct {
	RAnal *a;
	ut64 arg;
	int opt;
} Args;

static bool cblist(void *user, const ut64 offset, const void *val) {
	RVecBacktrace *bt = (RVecBacktrace*)val;
	Args *args = (Args *)user;
	ut64 *addr;
	if (args->opt == 'x') {
		R_VEC_FOREACH (bt, addr) {
			r_cons_printf ("ax 0x%08"PFMT64x" 0x%08"PFMT64x"\n", offset, *addr);
		}
	} else {
		r_cons_printf ("-> 0x%08"PFMT64x"\n", offset);
		R_VEC_FOREACH (bt, addr) {
			r_cons_printf (" `-> 0x%08"PFMT64x"\n", *addr);
		}
	}
	return true;
}

R_API void r_anal_backtrace_list(RAnal *a, ut64 addr, int opt) {
	RAnalBacktracesPrivate *b = a->btstore.priv;
	Args args = { a, addr, opt };
	ht_up_foreach (b->ht, cblist, &args);
}

R_API void r_anal_backtrace_fini(RAnal *a) {
	RAnalBacktracesPrivate *b = a->btstore.priv;
	ht_up_free (b->ht);
	R_FREE (a->btstore.priv);
}

R_API void r_anal_backtrace_init(RAnal *a) {
	a->btstore.priv = R_NEW0 (RAnalBacktracesPrivate);
	RAnalBacktracesPrivate *b = a->btstore.priv;
	b->ht = ht_up_new0 ();
}
