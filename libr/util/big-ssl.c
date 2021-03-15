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
	BN_ULONG maxx = 0;
	maxx = ~maxx;
	BN_ULONG res = BN_get_word (b);
	if (res == maxx) {
		RNumBig *B = r_big_new ();
		r_big_assign (B, b);
		BN_mask_bits (B, BN_BYTES * 8 - 1);
		res = BN_get_word (B);
		r_big_free (B);
	}
	res *= (BN_is_negative (b)? -1: 1);
	return res;
}

R_API void r_big_from_hexstr(RNumBig *b, const char *str) {
	if (r_str_startswith (str, "0x")) {
		str += 2;
		BN_hex2bn (&b, str);
	} else if (r_str_startswith (str, "-0x")) {
		str += 3;
		BN_hex2bn (&b, str);
		BN_set_negative (b, -1);
	}
}

R_API char *r_big_to_hexstr(RNumBig *b) {
	char *tmp = BN_bn2hex (b);
	char *res;
	size_t i;
	if (tmp[0] == '-') {
		res = r_str_newf ("-0x%s", &tmp[1]);
	} else {
		res = r_str_newf ("0x%s", tmp);
	}
	OPENSSL_free (tmp);
	for (i = 0; res[i]; i++) {
		res[i] = tolower (res[i]);
	}
	return res;
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
	RNumBig *A = r_big_new ();
	RNumBig *B = r_big_new ();
	RNumBig *C = r_big_new ();
	RNumBig *addition = r_big_new ();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	r_big_assign (A, a);
	r_big_assign (B, b);

	while (!r_big_is_zero (A) || !r_big_is_zero (B)) {
		tmp = r_big_to_int (A);
		tmp &= r_big_to_int (B);
		r_big_rshift (A, A, step);
		r_big_rshift (B, B, step);
		r_big_from_int (addition, tmp);
		r_big_lshift (addition, addition, move);
		r_big_add (C, C, addition);

		move += step;
	}

	r_big_assign (c, C);

	r_big_free (A);
	r_big_free (B);
	r_big_free (C);
	r_big_free (addition);
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig *A = r_big_new ();
	RNumBig *B = r_big_new ();
	RNumBig *C = r_big_new ();
	RNumBig *addition = r_big_new ();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	r_big_assign (A, a);
	r_big_assign (B, b);

	while (!r_big_is_zero (A) || !r_big_is_zero (B)) {
		tmp = r_big_to_int (A);
		tmp |= r_big_to_int (B);
		r_big_rshift (A, A, step);
		r_big_rshift (B, B, step);
		r_big_from_int (addition, tmp);
		r_big_lshift (addition, addition, move);
		r_big_add (C, C, addition);

		move += step;
	}

	r_big_assign (c, C);

	r_big_free (A);
	r_big_free (B);
	r_big_free (C);
	r_big_free (addition);
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig *A = r_big_new ();
	RNumBig *B = r_big_new ();
	RNumBig *C = r_big_new ();
	RNumBig *addition = r_big_new ();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	r_big_assign (A, a);
	r_big_assign (B, b);

	while (!r_big_is_zero (A) || !r_big_is_zero (B)) {
		tmp = r_big_to_int (A);
		tmp ^= r_big_to_int (B);
		r_big_rshift (A, A, step);
		r_big_rshift (B, B, step);
		r_big_from_int (addition, tmp);
		r_big_lshift (addition, addition, move);
		r_big_add (C, C, addition);

		move += step;
	}

	r_big_assign (c, C);

	r_big_free (A);
	r_big_free (B);
	r_big_free (C);
	r_big_free (addition);
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

R_API void r_big_isqrt(RNumBig *b, RNumBig *a) {
	RNumBig *tmp = r_big_new ();
	RNumBig *low = r_big_new ();
	RNumBig *high = r_big_new ();
	RNumBig *mid = r_big_new ();

	r_big_assign (high, a);
	r_big_rshift (mid, high, 1);
	r_big_inc (mid);

	while (r_big_cmp (high, low) > 0) {
		r_big_mul (tmp, mid, mid);
		if (r_big_cmp (tmp, a) > 0) {
			r_big_assign (high, mid);
			r_big_dec (high);
		} else {
			r_big_assign (low, mid);
		}
		r_big_sub (mid, high, low);
		r_big_rshift (mid, mid, 1);
		r_big_add (mid, mid, low);
		r_big_inc (mid);
	}
	r_big_assign (b, low);

	r_big_free (tmp);
	r_big_free (low);
	r_big_free (high);
	r_big_free (mid);
}
