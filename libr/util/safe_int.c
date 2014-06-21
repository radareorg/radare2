/* radare - LGPL - Copyright 2009-2014 - Tosh */


/* =========================================================================
   This file implement functions used to prevent integer overflow when
   add, sub or mul two integers
   ======================================================================= */

#include <r_types.h>
#include <stdlib.h>

/* All functions have the form :
   r_safe_[OP][S][SIZE]
   - OP is one of mul, add, sub
   - S is 'u' for unsigned and 's' for signed
   - SIZE is one of 8, 16, 32, 64.

   The operand 'r' is the result, and can be NULL.
   'a' and 'b' are the two operands for the given operation.
*/

R_API int r_safe_addu64(ut64 *r, ut64 a, ut64 b) {
  if(UT64_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

R_API int r_safe_addu32(ut32 *r, ut32 a, ut32 b) {
  if(UT32_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

R_API int r_safe_addu16(ut16 *r, ut16 a, ut16 b) {
  if(UT16_MAX - a < b)
    return 0;

  if(r != NULL)
    *r = a + b;

  return 1;
}

R_API int r_safe_mulu64(ut64 *r, ut64 a, ut64 b) {
  if(UT64_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

R_API int r_safe_mulu32(ut32 *r, ut32 a, ut32 b) {
  if(UT32_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

R_API int r_safe_mulu16(ut16 *r, ut16 a, ut16 b) {
  if(UT16_MAX / a < b)
    return 0;

  if(r != NULL)
    *r = a * b;

  return 1;
}

R_API int r_safe_subu64(ut64 *r, ut64 a, ut64 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}

R_API int r_safe_subu32(ut32 *r, ut32 a, ut32 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}

R_API int r_safe_subu16(ut16 *r, ut16 a, ut16 b) {
  if(b > a)
    return 0;

  if(r != NULL)
    *r = a - b;

  return 1;
}
