#include <r_cons.h>

static R_TH_LOCAL RCons s_cons_thread = {0};

// conceptually wrong, needs redesign
R_API void r_cons_thready(void) {
	I = &s_cons_thread;
#if 0
	if (I->refcnt > 0) {
		R_CRITICAL_ENTER (I);
	}
#endif
	RCons *cons = r_cons_singleton ();
	RConsContext *ctx = cons->context;
	if (ctx) {
		ctx->unbreakable = true;
	}
	r_sys_signable (false); // disable signal handling
#if 0
	if (I->refcnt == 0) {
		r_cons_new ();
	}
	if (I->refcnt > 0) {
		R_CRITICAL_LEAVE (I);
	}
#endif
}

