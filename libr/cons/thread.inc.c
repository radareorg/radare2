#include <r_cons.h>

// Call after creating the console used by a background thread.
// Marks the console context as unbreakable (no SIGINT handler installation)
// and disables signal handling for the calling thread.
R_API void r_cons_thready(void) {
	RCons *cons = r_cons_global (NULL);
	if (cons) {
		cons->context->unbreakable = true;
		cons->is_embedded = true;
	}
	r_sys_signable (false);
}
