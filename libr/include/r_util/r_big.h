#ifndef R_BIG_H
#define R_BIG_H

#include "../r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_LIB_GMP
/* Use GMP's data struct */
#define RNumBig mpz_t
#elif HAVE_LIB_SSL
#define RNumBig BIGNUM
#else
/* Use default impl */
#define R_BIG_WORD_SIZE 4
/* Let's support 4096-bit big number */
#define R_BIG_ARRAY_SIZE (512 / R_BIG_WORD_SIZE)
/* R_BIG_WORD_SIZE == 4, 32 bits long */
#define R_BIG_DTYPE ut32
#define R_BIG_DTYPE_TMP ut64
#define R_BIG_SPRINTF_FORMAT_STR "%.08x"
#define R_BIG_FORMAT_STR_LEN 9
#define R_BIG_SSCANF_FORMAT_STR "%8x"
#define R_BIG_MAX_VAL (R_BIG_DTYPE_TMP) UT32_MAX

typedef struct r_num_big_t {
	R_BIG_DTYPE array[R_BIG_ARRAY_SIZE];
	int sign;
} RNumBig;
#endif

R_API RNumBig *r_big_new(void);
R_API void r_big_free(RNumBig *b);
R_API void r_big_init(RNumBig *b);
R_API void r_big_fini(RNumBig *b);

/* Assignment operations */
R_API void r_big_from_int(RNumBig *b, st64 v);
R_API st64 r_big_to_int(RNumBig *b);
R_API void r_big_from_hexstr(RNumBig *b, const char *str);
R_API char *r_big_to_hexstr(RNumBig *b);
R_API void r_big_assign(RNumBig *dst, RNumBig *src);

/* Basic arithmetic operations */
R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a + b */
R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a - b */
R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a * b */
R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a / b */
R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a % b */
R_API void r_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b); /* c = a/b, d = a%b */

/* Bitwise operations(for >= 0) */
R_API void r_big_and(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a & b */
R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a | b */
R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a ^ b */
R_API void r_big_lshift(RNumBig *c, RNumBig *a, size_t nbits); /* c = a << nbits */
R_API void r_big_rshift(RNumBig *c, RNumBig *a, size_t nbits); /* c = a >> nbits */

/* Special operators and comparison */
R_API int r_big_cmp(RNumBig *a, RNumBig *b); /* Return 1 if a>b, -1 if a<b, else 0 */
R_API int r_big_is_zero(RNumBig *a); /* For comparison with zero */
R_API void r_big_inc(RNumBig *a); /* Increment: add one to n */
R_API void r_big_dec(RNumBig *a); /* Decrement: subtract one from n */
R_API void r_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m); /* Calculate a^b -- e.g. 2^10 => 1024 */
R_API void r_big_isqrt(RNumBig *c, RNumBig *a); /* Integer square root -- e.g. isqrt(5) => 2*/

#ifdef __cplusplus
}
#endif

#endif //  R_BIG_H
