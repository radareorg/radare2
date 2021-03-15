#include <r_util.h>

R_API RNumBig *r_big_new(void) {
	RNumBig *n = R_NEW (RNumBig);
	if (n) {
		mpz_init (*n);
	}
	return n;
}

R_API void r_big_free(RNumBig *b) {
	mpz_clear (*b);
	free (b);
}

R_API void r_big_init(RNumBig *b) {
	mpz_init (*b);
}

R_API void r_big_fini(RNumBig *b) {
	mpz_clear (*b);
}

R_API void r_big_from_int(RNumBig *b, st64 v) {
	mpz_set_si (*b, v);
}

R_API st64 r_big_to_int(RNumBig *b) {
	return mpz_get_si (*b);
}

R_API void r_big_from_hexstr(RNumBig *b, const char *str) {
	if (r_str_startswith (str, "0x")) {
		str += 2;
		mpz_set_str (*b, str, 16);
	} else if (r_str_startswith (str, "-0x")) {
		str += 3;
		mpz_set_str (*b, str, 16);
		mpz_mul_si (*b, *b, -1);
	}
}

R_API char *r_big_to_hexstr(RNumBig *b) {
	char *tmp = mpz_get_str (NULL, 16, *b);
	char *res;
	if (tmp[0] == '-') {
		res = r_str_newf ("-0x%s", &tmp[1]);
	} else {
		res = r_str_newf ("0x%s", tmp);
	}
	free (tmp);
	return res;
}

R_API void r_big_assign(RNumBig *dst, RNumBig *src) {
	mpz_set (*dst, *src);
}

R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_add (*c, *a, *b);
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_sub (*c, *a, *b);
}

R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_mul (*c, *a, *b);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_tdiv_q (*c, *a, *b);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_mod (*c, *a, *b);
}

R_API void r_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
	mpz_tdiv_qr (*c, *d, *a, *b);
}

R_API void r_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_and (*c, *a, *b);
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_ior (*c, *a, *b);
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	mpz_xor (*c, *a, *b);
}

R_API void r_big_lshift(RNumBig *c, RNumBig *a, size_t nbits) {
	mpz_mul_2exp (*c, *a, nbits);
}

R_API void r_big_rshift(RNumBig *c, RNumBig *a, size_t nbits) {
	mpz_tdiv_q_2exp (*c, *a, nbits);
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	int res = mpz_cmp (*a, *b);
	if (res > 0) {
		return 1;
	} else if (res < 0) {
		return -1;
	} else {
		return 0;
	}
}

R_API int r_big_is_zero(RNumBig *a) {
	return mpz_cmp_ui (*a, 0) == 0;
}

R_API void r_big_inc(RNumBig *a) {
	RNumBig tmp;
	mpz_init_set_si (tmp, 1);
	mpz_add (*a, *a, tmp);
}

R_API void r_big_dec(RNumBig *a) {
	RNumBig tmp;
	mpz_init_set_si (tmp, 1);
	mpz_sub (*a, *a, tmp);
}

R_API void r_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	mpz_powm (*c, *a, *b, *m);
}

R_API void r_big_isqrt(RNumBig *c, RNumBig *a) {
	mpz_sqrt (*c, *a);
}
