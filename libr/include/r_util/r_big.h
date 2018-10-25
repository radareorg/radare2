#ifndef R_BIG_H
#define R_BIG_H

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_LIB_GMP
#define RNumBig mpz_t
#elif HAVE_LIB_SSL
#define RNumBig BIGNUM
#else
#define	R_BIG_SIZE 10000
typedef struct r_num_big_t {
	char dgts[R_BIG_SIZE];
	int sign, last;
} RNumBig;
#endif

R_API RNumBig *r_big_new(RNumBig *b);
R_API void r_big_free(RNumBig *b);
R_API void r_big_sub(RNumBig *a, RNumBig *b, RNumBig *c);
R_API void r_big_print(RNumBig *n);
R_API void r_big_set(RNumBig *a, RNumBig *b);
R_API void r_big_set_st(RNumBig *n, int v);
R_API void r_big_set_st64(RNumBig *n, st64 v);
R_API void r_big_set_str(RNumBig *n, const char *str);
R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b);
R_API int r_big_cmp(RNumBig *a, RNumBig *b);
R_API int r_big_cmp_st(RNumBig *n, int v);
R_API void r_big_shift(RNumBig *n, int d);
R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_mul_ut(RNumBig *c, RNumBig *a, ut32 b);
R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_div_ut(RNumBig *a, RNumBig *b, ut32 c);
R_API int r_big_divisible_ut(RNumBig *n, ut32 v);
R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b);

#ifdef __cplusplus
}
#endif

#endif //  R_BIG_H
