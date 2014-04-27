/* TODO: Implement all functions using gmp code */
#include <stdio.h>
#include <r_util.h>

static inline void r_big_zero(RNumBig *n) {
	BN_zero (n);
}

R_API void r_big_print(RNumBig *n) {
	/* TODO */
}

R_API void r_big_set_str(RNumBig *n, const char *str) {
	BN_set_word (n, atoi (str));
}

R_API RNumBig *r_big_new(RNumBig *b) {
	return BN_new ();
}

R_API void r_big_free(RNumBig *b) {
	BN_free (b);
}

R_API void r_big_set(RNumBig *a, RNumBig *b) {
	BN_copy (a, b);
}

R_API void r_big_set_st(RNumBig *n, int v) {
	BN_set_word (n, v);
}

R_API void r_big_set_st64(RNumBig *n, st64 v) {
	BN_set_word (n, v);
}

/* c = a [+*-/] b; */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_add (c, a, b);
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_sub (c, a, b);
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	return BN_ucmp (a, b);
}

R_API int r_big_cmp_st(RNumBig *n, int v) {
	return BN_cmp (a, b);
}

/* multiply n by 10^d */
R_API void r_big_shift(RNumBig *n, int d) {
	RNumBig a;
	BN_copy (&a, n);
	BN_lshift, (n, a, d);
}

R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b) {
	/* TODO: last parameter must be BN_CTX */
	BN_mul (c, a, b, NULL);
}

R_API void r_big_mul_ut (RNumBig *c, RNumBig *a, ut32 b) {
	RNumBig *b = BN_new ();
	BN_set_word (b, b);
	r_big_mul (c, a, &b);
	BN_free (b);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_div (c, NULL, a, b);
}

R_API void r_big_div_ut(RNumBig *c, RNumBig *a, ut32 b) {
	eprintf (__FUNCTION__": TODO\n");
//	mpz_divexact_ui (*c, *a, b);
}

R_API int r_big_divisible_ut(RNumBig *n, ut32 v) {
	eprintf (__FUNCTION__": TODO\n");
//	return mpz_divisible_ui_p (*n, v);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_div (NULL, c, a, b);
}
