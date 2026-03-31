#include <r_cons.h>

// Call from background threads before using r_core_cmd via a GUI wrapper.
// Marks the console context as unbreakable (no SIGINT handler installation)
// and disables signal handling for the calling thread. Does NOT overwrite
// the global singleton pointer, so r_cons_singleton() keeps working.
R_API void r_cons_thready(void) {
	RCons *cons = r_cons_singleton ();
	if (!cons) {
		return;
	}
	RConsContext *ctx = cons->context;
	if (ctx) {
		ctx->unbreakable = true;
	}
	cons->is_embedded = true;
	r_sys_signable (false);
}

