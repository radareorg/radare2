#include <r_util.h>

R_API RNumBig *r_big_new(void) {
	return BN_new ();
}

R_API void r_big_free(RNumBig *b) {
	BN_free (b);
}

R_API void r_big_init(RNumBig *b) {
	BN_zero (b);
}

R_API void r_big_fini(RNumBig *b) {
	BN_clear (b);
}

R_API void r_big_from_int(RNumBig *b, st64 v) {
	if (v < 0) {
		BN_set_word (b, -v);
		BN_set_negative (b, v);
	} else {
		BN_set_word (b, v);
	}
}

R_API st64 r_big_to_int(RNumBig *b) {
	signed long int res;
	res = BN_get_word (b);
	res *= (BN_is_negative (b)? -1: 1);
	return res;
}

R_API void r_big_from_hexstr(RNumBig *b, const char *str) {
	BN_hex2bn (&b, str);
}

R_API char *r_big_to_hexstr(RNumBig *b) {
	return BN_bn2hex (b);
}

R_API void r_big_assign(RNumBig *dst, RNumBig *src) {
	BN_copy (dst, src);
}

R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_add (c, a, b);
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_sub (c, a, b);
}

R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new ();
	BN_mul (c, a, b, bn_ctx);
	BN_CTX_free (bn_ctx);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new ();
	BN_div (c, NULL, a, b, bn_ctx);
	BN_CTX_free (bn_ctx);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new ();
	BN_mod (c, a, b, bn_ctx);
	BN_CTX_free (bn_ctx);
}

R_API void r_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new ();
	BN_div (c, d, a, b, bn_ctx);
	BN_CTX_free (bn_ctx);
}

R_API void r_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
}

R_API void r_big_lshift(RNumBig *c, RNumBig *a, size_t nbits) {
	BN_lshift (c, a, nbits);
}

R_API void r_big_rshift(RNumBig *c, RNumBig *a, size_t nbits) {
	BN_rshift (c, a, nbits);
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	return BN_cmp (a, b);
}

R_API int r_big_is_zero(RNumBig *a) {
	return BN_is_zero (a);
}

R_API void r_big_inc(RNumBig *a) {
	BN_add_word (a, 1);
}

R_API void r_big_dec(RNumBig *a) {
	BN_sub_word (a, 1);
}

R_API void r_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	BN_CTX *bn_ctx = BN_CTX_new ();
	BN_mod_exp (c, a, b, m, bn_ctx);
	BN_CTX_free (bn_ctx);
}

R_API void r_big_isqrt(RNumBig *c, RNumBig *a) {
}
