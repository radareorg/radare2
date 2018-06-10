/* radare2 - LGPL - Copyright 2018 */

#include <r_util.h>

void r_srand (int seed) {
#if !HAVE_ARC4RANDOM_UNIFORM
	srand (seed);
#else
	// no-op
	(void)seed;
#endif
}

int r_rand (void) {
#if !HAVE_ARC4RANDOM_UNIFORM
	return rand ();
#else
	return (int)arc4random ();
#endif
}
