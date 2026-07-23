#include <r_cons.h>

// Marks the console context as unbreakable (no SIGINT handler installation)
// and disables signal handling for the calling thread.
R_API void r_cons_thready(RCons *cons) {
	R_RETURN_IF_FAIL (cons);
	cons->context->unbreakable = true;
	cons->is_embedded = true;
	r_sys_signable (false);
}
