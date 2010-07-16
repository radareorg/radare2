/* TODO: Implement all functions using gmp code */
#include <stdio.h>
#include <r_util.h>
#include <gmp.h>

static inline void r_big_zero(RNumBig *n) {
	/* TODO */
}

R_API void r_big_print(RNumBig *n) {
	/* TODO */
}

R_API void r_big_set_str(RNumBig *n, const char *str) {
	mpz_set_str (*n, str, 10);
}

R_API RNumBig *r_big_new(RNumBig *b) {
	RNumBig *n = R_NEW (RNumBig);
	if (n) {
		if (b) memcpy (n, b, sizeof (RNumBig));
		else mpz_init (*n);
	}
	return n;
}

R_API void r_big_free(RNumBig *b) {
	free (b);
}

R_API void r_big_set(RNumBig *a, RNumBig *b) {
	mpz_set (*a, *b);
}

R_API void r_big_set_st(RNumBig *n, int v) {
	/* TODO */
}

R_API void r_big_set_st64(RNumBig *n, st64 v) {
	/* TODO */
}

/* c = a [+*-/] b; */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b) {
	/* TODO */
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	/* TODO */
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	return mpz_cmp (*a, *b);
}

R_API int r_big_cmp_st(RNumBig *n, int v) {
	return mpz_cmp_si (*n, v);
}

/* multiply n by 10^d */
R_API void r_big_shift(RNumBig *n, int d) {
	/* TODO */
}

R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_mul (*c, *a, *b);
}

R_API void r_big_mul_ut (RNumBig *c, RNumBig *a, ut32 b) {
	mpz_mul_ui (*c, *a, b);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	/* TODO */
}

R_API void r_big_div_ut(RNumBig *c, RNumBig *a, ut32 b) {
	mpz_divexact_ui (*c, *a, b);
}

R_API int r_big_divisible_ut(RNumBig *n, ut32 v) {
	return mpz_divisible_ui_p (*n, v);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	/* TODO */
}
