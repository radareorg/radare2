/* radare2 - LGPL - Copyright 2018 */

#include <r_util.h>

R_API void r_srand (int seed) {
#if !HAVE_ARC4RANDOM
  srand (seed);
#else
// no-op
  (void)seed;
#endif
}

R_API int r_rand (void) {
#if !HAVE_ARC4RANDOM
  return rand();
#else
  return (int)arc4random();
#endif
}
