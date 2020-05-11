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
#ifndef WORD_SIZ
#define WORD_SIZ 4
#endif
/* Let's support 4096-bit big number */
#define BN_ARRAY_SIZE (512 / WORD_SIZ)
#ifndef WORD_SIZ
#error Must define WORD_SIZ to be 1, 2, 4
/* If WORD_SIZ == 1, 8 bits long */
#elif (WORD_SIZ == 1)
/* Actual element type used during operation */
#define DTYPE ut8
#define DTYPE_MSB ((DTYPE_TMP) (0x80))
/* Middle variable type, must be bigger than DTYPE */
#define DTYPE_TMP ut16
/* Type to be passed as variable */
#define DTYPE_VAR st16
#define SPRINTF_FORMAT_STR "%.02x"
#define SSCANF_FORMAT_STR "%2hhx"
#define MAX_VAL ((DTYPE_TMP)0xFF)
/* If WORD_SIZ == 2, 16 bits long */
#elif (WORD_SIZ == 2)
#define DTYPE ut16
#define DTYPE_TMP ut32
#define DTYPE_VAR st32
#define DTYPE_MSB ((DTYPE_TMP) (0x8000))
#define SPRINTF_FORMAT_STR "%.04x"
#define SSCANF_FORMAT_STR "%4hx"
#define MAX_VAL ((DTYPE_TMP)0xFFFF)
/* If WORD_SIZ == 4, 32 bits long */
#elif (WORD_SIZ == 4)
#define DTYPE ut32
#define DTYPE_TMP ut64
#define DTYPE_VAR st64
#define DTYPE_MSB ((DTYPE_TMP) (0x80000000))
#define SPRINTF_FORMAT_STR "%.08x"
#define SSCANF_FORMAT_STR "%8x"
#define MAX_VAL ((DTYPE_TMP)0xFFFFFFFF)
#endif
#ifndef DTYPE
#error DTYPE must be defined to ut8, ut16 ut32 or whatever
#endif

typedef struct r_num_big_t {
	DTYPE array[BN_ARRAY_SIZE];
	int sign;
} RNumBig;
#endif

R_API RNumBig *r_big_new(void);
R_API void r_big_free(RNumBig *b);
R_API void r_big_init(RNumBig *b);
R_API void r_big_fini(RNumBig *b);

/* Assignment operations */
R_API void r_big_from_int(RNumBig *b, signed long int v);
R_API signed long int r_big_to_int(RNumBig *b);
R_API void r_big_from_hexstr (RNumBig *b, const char *str);
R_API char *r_big_to_hexstr (RNumBig *b);
R_API void r_big_assign (RNumBig *dst, RNumBig *src);

/* Basic arithmetic operations */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a + b */
R_API void r_big_sub (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a - b */
R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a * b */
R_API void r_big_div (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a / b */
R_API void r_big_mod (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a % b */
R_API void r_big_divmod (RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b); /* c = a/b, d = a%b */

/* Bitwise operations(for >= 0) */
R_API void r_big_and (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a & b */
R_API void r_big_or (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a | b */
R_API void r_big_xor (RNumBig *c, RNumBig *a, RNumBig *b); /* c = a ^ b */
R_API void r_big_lshift (RNumBig *c, RNumBig *a, size_t nbits); /* c = a << nbits */
R_API void r_big_rshift (RNumBig *c, RNumBig *a, size_t nbits); /* c = a >> nbits */

/* Special operators and comparison */
R_API int r_big_cmp (RNumBig *a, RNumBig *b); /* Return 1 if a>b, -1 if a<b, else 0 */
R_API int r_big_is_zero (RNumBig *a); /* For comparison with zero */
R_API void r_big_inc (RNumBig *a); /* Increment: add one to n */
R_API void r_big_dec (RNumBig *a); /* Decrement: subtract one from n */
R_API void r_big_powm (RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m); /* Calculate a^b -- e.g. 2^10 => 1024 */
R_API void r_big_isqrt (RNumBig *c, RNumBig *a); /* Integer square root -- e.g. isqrt(5) => 2*/

#ifdef __cplusplus
}
#endif

#endif //  R_BIG_H
