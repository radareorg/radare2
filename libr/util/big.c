/* radare2 - LGPL - Copyright 2010-2025 - FXTi, pancake */
/* Based on https://github.com/kokke/tiny-bignum-c */

#include <r_util.h>

#if !HAVE_LIB_GMP && !HAVE_LIB_SSL

/* Private / Static functions. */
static void _rshift_word(RNumBig *a, int nwords) {
	R_RETURN_IF_FAIL (a && nwords >= 0);

	size_t i;
	if (nwords >= R_BIG_ARRAY_SIZE) {
		for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
			a->array[i] = 0;
		}
		return;
	}

	for (i = 0; i < R_BIG_ARRAY_SIZE - nwords; i++) {
		a->array[i] = a->array[i + nwords];
	}
	for (; i < R_BIG_ARRAY_SIZE; i++) {
		a->array[i] = 0;
	}
}

static void _lshift_word(RNumBig *a, int nwords) {
	R_RETURN_IF_FAIL (a && nwords >= 0);

	int i;
	/* Shift whole words */
	for (i = (R_BIG_ARRAY_SIZE - 1); i >= nwords; i--) {
		a->array[i] = a->array[i - nwords];
	}
	/* Zero pad shifted words. */
	for (; i >= 0; i--) {
		a->array[i] = 0;
	}
}

static void _lshift_one_bit(RNumBig *a) {
	R_RETURN_IF_FAIL (a);

	int i;
	for (i = (R_BIG_ARRAY_SIZE - 1); i > 0; i--) {
		a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * R_BIG_WORD_SIZE) - 1));
	}
	a->array[0] <<= 1;
}

static void _rshift_one_bit(RNumBig *a) {
	R_RETURN_IF_FAIL (a);

	int i;
	for (i = 0; i < (R_BIG_ARRAY_SIZE - 1); i++) {
		a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * R_BIG_WORD_SIZE) - 1));
	}
	a->array[R_BIG_ARRAY_SIZE - 1] >>= 1;
}

static void _r_big_zero_out(RNumBig *a) {
	R_RETURN_IF_FAIL (a);

	size_t i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		a->array[i] = 0;
	}
	a->sign = 1; /* hack to avoid -0 */
}

static R_BIG_DTYPE_TMP safe_abs(st64 n) {
	if (n < 0) {
		/* Avoid overflow for n == INT64_MIN */
		return ((R_BIG_DTYPE_TMP)(-(n + 1))) + 1;
	}
	return (R_BIG_DTYPE_TMP)n;
}

R_API RNumBig *r_big_new(void) {
	RNumBig *n = R_NEW (RNumBig);
	_r_big_zero_out (n);
	return n;
}

R_API void r_big_free(RNumBig *b) {
	free (b);
}

R_API void r_big_init(RNumBig *b) {
	_r_big_zero_out (b);
}

R_API void r_big_fini(RNumBig *b) {
	_r_big_zero_out (b);
}

R_API void r_big_from_int(RNumBig *b, st64 n) {
	R_RETURN_IF_FAIL (b);
	_r_big_zero_out (b);
	b->sign = (n < 0) ? -1 : 1;
	R_BIG_DTYPE_TMP v = safe_abs (n);

	int num_words = sizeof (v) / R_BIG_WORD_SIZE;
	if (num_words > R_BIG_ARRAY_SIZE)
		num_words = R_BIG_ARRAY_SIZE;
	int i;
	for (i = 0; i < num_words; i++) {
		b->array[i] = (R_BIG_DTYPE)((v >> (i * R_BIG_WORD_SIZE * 8)) & R_BIG_MAX_VAL);
	}
}

static void r_big_from_unsigned(RNumBig *b, ut64 v) {
	R_RETURN_IF_FAIL (b);
	_r_big_zero_out (b);
	b->sign = 1;
	int num_words = sizeof (v) / R_BIG_WORD_SIZE;
	if (num_words > R_BIG_ARRAY_SIZE) {
		num_words = R_BIG_ARRAY_SIZE;
	}
	int i;
	for (i = 0; i < num_words; i++) {
		b->array[i] = (R_BIG_DTYPE)((v >> (i * R_BIG_WORD_SIZE * 8)) & R_BIG_MAX_VAL);
	}
}

R_API st64 r_big_to_int(RNumBig *b) {
	R_RETURN_VAL_IF_FAIL(b, 0);
	R_BIG_DTYPE_TMP ret = 0;
	int num_words = sizeof(ret) / R_BIG_WORD_SIZE;
	if (num_words > R_BIG_ARRAY_SIZE) {
		num_words = R_BIG_ARRAY_SIZE;
	}
	int i;
	for (i = 0; i < num_words; i++) {
		ret |= ((R_BIG_DTYPE_TMP)b->array[i]) << (i * R_BIG_WORD_SIZE * 8);
	}
	if (b->sign < 0) {
		return -(st64)ret;
	}
	return (st64)ret;
}

R_API void r_big_from_hexstr(RNumBig *n, const char *str) {
	R_RETURN_IF_FAIL (n && str);
	int nbytes = strlen (str);
	_r_big_zero_out (n);
	if (str[0] == '-') {
		n->sign = -1;
		str++;
		nbytes--;
	} else {
		n->sign = 1;
	}
	if (nbytes >= 2 && str[0] == '0' && str[1] == 'x') {
		str += 2;
		nbytes -= 2;
	}
	R_RETURN_IF_FAIL (nbytes > 0);

	const int hex_digits_per_word = 2 * R_BIG_WORD_SIZE;
	int j = 0;
	int i = nbytes - hex_digits_per_word;
	char buffer[(2 * R_BIG_WORD_SIZE) + 1];
	buffer[hex_digits_per_word] = '\0';

	while (i >= 0 && j < R_BIG_ARRAY_SIZE) {
		strncpy (buffer, &str[i], hex_digits_per_word);
		buffer[hex_digits_per_word] = '\0';
		unsigned int tmp = 0;
		sscanf (buffer, "%x", &tmp);
		n->array[j] = tmp;
		j++;
		i -= hex_digits_per_word;
	}
	if (i > -hex_digits_per_word && j < R_BIG_ARRAY_SIZE && i < 0) {
		int leftover = i + hex_digits_per_word;
		memset(buffer, 0, sizeof(buffer));
		/* Copy the leftover digits into the rightmost part of the buffer */
		strncpy (buffer + (hex_digits_per_word - leftover), str, leftover);
		buffer[hex_digits_per_word] = '\0';
		unsigned int tmp = 0;
		sscanf (buffer, "%x", &tmp);
		n->array[j] = tmp;
	}
}

R_API char *r_big_to_hexstr(RNumBig *b) {
	R_RETURN_VAL_IF_FAIL (b, NULL);
	int hex_digits_per_word = 2 * R_BIG_WORD_SIZE;
	int j = R_BIG_ARRAY_SIZE - 1;
	while (j >= 0 && b->array[j] == 0) {
		j--;
	}
	if (j < 0) {
		return strdup ("0x0");
	}
	size_t size = 3 + (hex_digits_per_word * (j + 1)) + ((b->sign < 0) ? 1 : 0) + 1;
	char *ret_str = calloc (size, sizeof (char));
	if (!ret_str) {
		return NULL;
	}
	size_t i = 0;
	if (b->sign < 0) {
		ret_str[i++] = '-';
	}
	ret_str[i++] = '0';
	ret_str[i++] = 'x';
	char temp[hex_digits_per_word + 1];
	snprintf (temp, sizeof (temp), "%x", b->array[j]);
	strcpy (ret_str + i, temp);
	i += strlen (temp);
	j--;
	for (; j >= 0; j--) {
		snprintf (temp, sizeof (temp), "%0*x", hex_digits_per_word, b->array[j]);
		strcpy (ret_str + i, temp);
		i += strlen (temp);
	}
	return ret_str;
}

static int r_big_mod2(RNumBig *b) {
	R_RETURN_VAL_IF_FAIL(b, 0);
	return b->array[0] & 1;
}

R_API void r_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	R_RETURN_IF_FAIL(a && b && c && m);

	RNumBig *bcopy = r_big_new ();
	RNumBig *acopy = r_big_new ();
	r_big_assign (bcopy, b);
	r_big_assign (acopy, a);
	r_big_mod (acopy, acopy, m);
	r_big_from_int (c, 1);

	while (!r_big_is_zero (bcopy)) {
		if (r_big_mod2 (bcopy) == 1) {
			r_big_mul (c, c, acopy);
			r_big_mod (c, c, m);
		}
		_rshift_one_bit (bcopy);
		r_big_mul (acopy, acopy, acopy);
		r_big_mod (acopy, acopy, m);
	}
	r_big_free (bcopy);
	r_big_free (acopy);
}

R_API void r_big_assign(RNumBig *dst, RNumBig *src) {
	R_RETURN_IF_FAIL (dst && src);
	memcpy (dst, src, sizeof (RNumBig));
}

static void r_big_add_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_BIG_DTYPE_TMP tmp;
	int i, carry = 0;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		tmp = (R_BIG_DTYPE_TMP)a->array[i] + b->array[i] + carry;
		carry = (tmp > R_BIG_MAX_VAL) ? 1 : 0;
		c->array[i] = (R_BIG_DTYPE)(tmp & R_BIG_MAX_VAL);
	}
	if (carry) {
		R_LOG_WARN ("Overflow occurred in r_big_add_inner");
	}
}

static void r_big_sub_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_BIG_DTYPE_TMP res;
	RNumBig *tmp;
	R_BIG_DTYPE_TMP tmp1;
	R_BIG_DTYPE_TMP tmp2;
	int borrow = 0;
	int sign = r_big_cmp (a, b);
	c->sign = (sign >= 0? 1: -1);
	if (sign < 0) {
		tmp = a;
		a = b;
		b = tmp;
	}
	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		tmp1 = (R_BIG_DTYPE_TMP)a->array[i] + (R_BIG_MAX_VAL + 1); /* + number_base */
		tmp2 = (R_BIG_DTYPE_TMP)b->array[i] + borrow;

		res = (tmp1 - tmp2);
		c->array[i] = (R_BIG_DTYPE) (res & R_BIG_MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if nu    mber_base is 2^N */
		borrow = (res <= R_BIG_MAX_VAL);
	}
}

R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);

	if (a->sign >= 0 && b->sign >= 0) {
		r_big_add_inner (c, a, b);
		c->sign = 1;
		return;
	}
	if (a->sign >= 0 && b->sign < 0) {
		r_big_sub_inner (c, a, b);
		return;
	}
	if (a->sign < 0 && b->sign >= 0) {
		r_big_sub_inner (c, b, a);
		return;
	}
	if (a->sign < 0 && b->sign < 0) {
		r_big_add_inner (c, a, b);
		c->sign = -1;
		return;
	}
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);

	if (a->sign >= 0 && b->sign >= 0) {
		r_big_sub_inner (c, a, b);
		return;
	}
	if (a->sign >= 0 && b->sign < 0) {
		r_big_add_inner (c, a, b);
		c->sign = 1;
		return;
	}
	if (a->sign < 0 && b->sign >= 0) {
		r_big_add_inner (c, a, b);
		c->sign = -1;
		return;
	}
	if (a->sign < 0 && b->sign < 0) {
		r_big_sub_inner (c, b, a);
		return;
	}
}

R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);

	RNumBig *row = r_big_new ();
	RNumBig *tmp = r_big_new ();
	RNumBig *res = r_big_new ();
	int i, j;

	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		_r_big_zero_out (row);

		for (j = 0; j < R_BIG_ARRAY_SIZE; j++) {
			if (i + j < R_BIG_ARRAY_SIZE) {
				_r_big_zero_out (tmp);
				R_BIG_DTYPE_TMP intermediate = ((R_BIG_DTYPE_TMP)a->array[i] * (R_BIG_DTYPE_TMP)b->array[j]);
				r_big_from_unsigned (tmp, intermediate);
				_lshift_word (tmp, i + j);
				r_big_add (row, row, tmp);
			}
		}
		r_big_add (res, row, res);
	}

	res->sign = a->sign * b->sign;
	if (r_big_is_zero (res)) {
		res->sign = 1; // For -1 * 0 case
	}
	r_big_assign (c, res);

	r_big_free (row);
	r_big_free (tmp);
	r_big_free (res);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL(a && b && c);
	R_RETURN_IF_FAIL(!r_big_is_zero(b));

	RNumBig *current = r_big_new ();
	RNumBig *denom = r_big_new ();
	RNumBig *tmp = r_big_new ();
	int sign = a->sign * b->sign;

	/* Work with absolute value of a */
	RNumBig *absA = r_big_new ();
	r_big_assign (absA, a);
	absA->sign = 1;

	r_big_from_int (current, 1);
	r_big_assign (denom, b);
	denom->sign = 1;
	r_big_assign (tmp, denom);
	_lshift_one_bit (tmp);

	while (r_big_cmp (tmp, absA) != 1) {
		if ((denom->array[R_BIG_ARRAY_SIZE - 1] >> (R_BIG_WORD_SIZE * 8 - 1)) == 1) {
			break; // max value reached
		}
		_lshift_one_bit (tmp);
		_lshift_one_bit (denom);
		_lshift_one_bit (current);
	}
	r_big_assign (tmp, absA);
	_r_big_zero_out (c);
	while (!r_big_is_zero (current)) {
		if (r_big_cmp (tmp, denom) != -1) {
			r_big_sub (tmp, tmp, denom);
			r_big_or (c, current, c);
		}
		_rshift_one_bit (current);
		_rshift_one_bit (denom);
	}
	c->sign = sign;
	if (r_big_is_zero (c)) {
		c->sign = 1;
	}
	r_big_free (current);
	r_big_free (denom);
	r_big_free (tmp);
	r_big_free (absA);
}

// Take divmod and throw away div part
R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);
	R_RETURN_IF_FAIL (!r_big_is_zero (b));

	RNumBig *tmp = r_big_new ();

	r_big_divmod (tmp, c, a, b);

	r_big_free (tmp);
}

R_API void r_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
	/*
	Puts a%b in d
	and a/b in c

	mod(a,b) = a - ((a / b) * b)

	example:
	mod(8, 3) = 8 - ((8 / 3) * 3) = 2
	*/
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);
	R_RETURN_IF_FAIL (!r_big_is_zero (b));

	RNumBig *tmp = r_big_new ();

	/* c = (a / b) */
	r_big_div (c, a, b);

	/* tmp = (c * b) */
	r_big_mul (tmp, c, b);

	/* d = a - tmp */
	r_big_sub (d, a, tmp);

	r_big_free (tmp);
}

R_API void r_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);
	R_RETURN_IF_FAIL (a->sign > 0);
	R_RETURN_IF_FAIL (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] & b->array[i]);
	}
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);
	R_RETURN_IF_FAIL (a->sign > 0);
	R_RETURN_IF_FAIL (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] | b->array[i]);
	}
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (c);
	R_RETURN_IF_FAIL (a->sign > 0);
	R_RETURN_IF_FAIL (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] ^ b->array[i]);
	}
}

R_API void r_big_lshift(RNumBig *b, RNumBig *a, size_t nbits) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (a->sign > 0);
	R_RETURN_IF_FAIL (b->sign > 0);

	r_big_assign (b, a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (R_BIG_WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;
	if (nwords != 0) {
		_lshift_word (b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}

	if (nbits != 0) {
		int i;
		for (i = (R_BIG_ARRAY_SIZE - 1); i > 0; i--) {
			b->array[i] = (b->array[i] << nbits) | (b->array[i - 1] >> ((8 * R_BIG_WORD_SIZE) - nbits));
		}
		b->array[i] <<= nbits;
	}
}

R_API void r_big_rshift(RNumBig *b, RNumBig *a, size_t nbits) {
	R_RETURN_IF_FAIL (a);
	R_RETURN_IF_FAIL (b);
	R_RETURN_IF_FAIL (a->sign > 0);
	R_RETURN_IF_FAIL (b->sign > 0);

	r_big_assign (b, a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (R_BIG_WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;
	if (nwords != 0) {
		_rshift_word (b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}

	if (nbits != 0) {
		int i;
		for (i = 0; i < (R_BIG_ARRAY_SIZE - 1); i++) {
			b->array[i] = (b->array[i] >> nbits) | (b->array[i + 1] << ((8 * R_BIG_WORD_SIZE) - nbits));
		}
		b->array[i] >>= nbits;
	}
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	R_RETURN_VAL_IF_FAIL (a, 0);
	R_RETURN_VAL_IF_FAIL (b, 0);

	if (a->sign != b->sign)
		return a->sign > 0? 1: -1;

	int i = R_BIG_ARRAY_SIZE;
	do {
		i -= 1; /* Decrement first, to start with last array element */
		if (a->array[i] > b->array[i]) {
			return 1 * a->sign;
		}
		if (a->array[i] < b->array[i]) {
			return -1 * a->sign;
		}
	} while (i != 0);

	return 0;
}

R_API int r_big_is_zero(RNumBig *a) {
	R_RETURN_VAL_IF_FAIL (a, -1);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		if (a->array[i]) {
			return 0;
		}
	}

	return 1;
}

R_API void r_big_inc(RNumBig *a) {
	R_RETURN_IF_FAIL (a);
	RNumBig *tmp = r_big_new ();

	r_big_from_int (tmp, 1);
	r_big_add (a, a, tmp);

	r_big_free (tmp);
}

R_API void r_big_dec(RNumBig *a) {
	R_RETURN_IF_FAIL (a);
	RNumBig *tmp = r_big_new ();

	r_big_from_int (tmp, 1);
	r_big_sub (a, a, tmp);

	r_big_free (tmp);
}

R_API void r_big_isqrt(RNumBig *b, RNumBig *a) {
	R_RETURN_IF_FAIL (a && b);

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
		_rshift_one_bit (mid);
		r_big_add (mid, mid, low);
		r_big_inc (mid);
	}
	r_big_assign (b, low);

	r_big_free (tmp);
	r_big_free (low);
	r_big_free (high);
	r_big_free (mid);
}


#endif
