/* Based on https://github.com/kokke/tiny-bignum-c.
 * Enjoy it --FXTi
 */

#include <r_util.h>

/* Functions for shifting number in-place. */
static void _lshift_one_bit(RNumBig *a);
static void _rshift_one_bit(RNumBig *a);
static void _lshift_word(RNumBig *a, int nwords);
static void _rshift_word(RNumBig *a, int nwords);
static void _r_big_zero_out(RNumBig *n);

R_API RNumBig *r_big_new(void) {
	RNumBig *n = R_NEW (RNumBig);
	if (n) {
		_r_big_zero_out (n);
	}
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
	r_return_if_fail (b);

	_r_big_zero_out (b);
	b->sign = (n < 0)? -1: 1;
	R_BIG_DTYPE_TMP v = n * b->sign;

	/* Endianness issue if machine is not little-endian? */
#ifdef R_BIG_WORD_SIZE
#if (R_BIG_WORD_SIZE == 1)
	b->array[0] = (v & 0x000000ff);
	b->array[1] = (v & 0x0000ff00) >> 8;
	b->array[2] = (v & 0x00ff0000) >> 16;
	b->array[3] = (v & 0xff000000) >> 24;
#elif (R_BIG_WORD_SIZE == 2)
	b->array[0] = (v & 0x0000ffff);
	b->array[1] = (v & 0xffff0000) >> 16;
#elif (R_BIG_WORD_SIZE == 4)
	b->array[0] = v;
	R_BIG_DTYPE_TMP num_32 = 32;
	R_BIG_DTYPE_TMP tmp = v >> num_32;
	b->array[1] = tmp;
#endif
#endif
}

static void r_big_from_unsigned(RNumBig *b, ut64 v) {
	r_return_if_fail (b);

	_r_big_zero_out (b);

	/* Endianness issue if machine is not little-endian? */
#ifdef R_BIG_WORD_SIZE
#if (R_BIG_WORD_SIZE == 1)
	b->array[0] = (v & 0x000000ff);
	b->array[1] = (v & 0x0000ff00) >> 8;
	b->array[2] = (v & 0x00ff0000) >> 16;
	b->array[3] = (v & 0xff000000) >> 24;
#elif (R_BIG_WORD_SIZE == 2)
	b->array[0] = (v & 0x0000ffff);
	b->array[1] = (v & 0xffff0000) >> 16;
#elif (R_BIG_WORD_SIZE == 4)
	b->array[0] = v;
	R_BIG_DTYPE_TMP num_32 = 32;
	R_BIG_DTYPE_TMP tmp = v >> num_32;
	b->array[1] = tmp;
#endif
#endif
}

R_API st64 r_big_to_int(RNumBig *b) {
	r_return_val_if_fail (b, 0);

	R_BIG_DTYPE_TMP ret = 0;

	/* Endianness issue if machine is not little-endian? */
#if (R_BIG_WORD_SIZE == 1)
	ret += b->array[0];
	ret += b->array[1] << 8;
	ret += b->array[2] << 16;
	ret += b->array[3] << 24;
#elif (R_BIG_WORD_SIZE == 2)
	ret += b->array[0];
	ret += b->array[1] << 16;
#elif (R_BIG_WORD_SIZE == 4)
	ret += b->array[1];
	ret <<= 32;
	ret += b->array[0];
#endif

	if (b->sign < 0) {
		return -ret;
	}
	return ret;
}

R_API void r_big_from_hexstr(RNumBig *n, const char *str) {
	r_return_if_fail (n);
	r_return_if_fail (str);
	int nbytes = strlen (str);

	_r_big_zero_out (n);

	if (str[0] == '-') {
		n->sign = -1;
		str += 1;
		nbytes -= 1;
	}

	if (str[0] == '0' && str[1] == 'x') {
		str += 2;
		nbytes -= 2;
	}
	r_return_if_fail (nbytes > 0);

	R_BIG_DTYPE tmp;
	int i = nbytes - (2 * R_BIG_WORD_SIZE); /* index into string */
	int j = 0; /* index into array */

	while (i >= 0) {
		tmp = 0;
		sscanf (&str[i], R_BIG_SSCANF_FORMAT_STR, &tmp);
		n->array[j] = tmp;
		i -= (2 * R_BIG_WORD_SIZE); /* step R_BIG_WORD_SIZE hex-byte(s) back in the string. */
		j += 1; /* step one element forward in the array. */
	}

	if (-2 * R_BIG_WORD_SIZE < i) {
		char buffer[2 * R_BIG_WORD_SIZE];
		memset (buffer, 0, sizeof (buffer));
		i += 2 * R_BIG_WORD_SIZE - 1;
		for (; i >= 0; i--) {
			buffer[i] = str[i];
		}
		tmp = 0;
		sscanf (buffer, R_BIG_SSCANF_FORMAT_STR, &tmp);
		n->array[j] = tmp;
	}
}

R_API char *r_big_to_hexstr(RNumBig *b) {
	r_return_val_if_fail (b, NULL);

	int j = R_BIG_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
	size_t i = 0; /* index into string representation. */
	size_t k = 0; /* Leading zero's amount */
	size_t z, last_z = 2 * R_BIG_WORD_SIZE;

	for (; b->array[j] == 0 && j >= 0; j--) {
	}
	if (j == -1) {
		return "0x0";
	}

	size_t size = 3 + 2 * R_BIG_WORD_SIZE * (j + 1) + ((b->sign > 0)? 0: 1);
	char *ret_str = calloc (size, sizeof (char));
	if (!ret_str) {
		return NULL;
	}

	if (b->sign < 0) {
		ret_str[i++] = '-';
	}
	ret_str[i++] = '0';
	ret_str[i++] = 'x';

	r_snprintf (ret_str + i, R_BIG_FORMAT_STR_LEN, R_BIG_SPRINTF_FORMAT_STR, b->array[j--]);
	for (; ret_str[i + k] == '0' && k < 2 * R_BIG_WORD_SIZE; k++) {
	}
	for (z = k; ret_str[i + z] && z < last_z; z++) {
		ret_str[i + z - k] = ret_str[i + z];
	}
	i += z - k;
	ret_str[i] = '\x00'; // Truncate string for case(j < 0)

	for (; j >= 0; j--) {
		r_snprintf (ret_str + i, R_BIG_FORMAT_STR_LEN, R_BIG_SPRINTF_FORMAT_STR, b->array[j]);
		i += 2 * R_BIG_WORD_SIZE;
	}

	return ret_str;
}

R_API void r_big_assign(RNumBig *dst, RNumBig *src) {
	r_return_if_fail (dst);
	r_return_if_fail (src);

	memcpy (dst, src, sizeof (RNumBig));
}

static void r_big_add_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
	R_BIG_DTYPE_TMP tmp;
	int carry = 0;
	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		tmp = (R_BIG_DTYPE_TMP)a->array[i] + b->array[i] + carry;
		carry = (tmp > R_BIG_MAX_VAL);
		c->array[i] = (tmp & R_BIG_MAX_VAL);
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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (!r_big_is_zero (b));

	RNumBig *current = r_big_new ();
	RNumBig *denom = r_big_new ();
	;
	RNumBig *tmp = r_big_new ();
	int sign = a->sign * b->sign;

	r_big_from_int (current, 1); // int current = 1;
	r_big_assign (denom, b); // denom = b
	denom->sign = 1;
	r_big_assign (tmp, denom); // tmp = denom = b
	_lshift_one_bit (tmp); // tmp <= 1

	while (r_big_cmp (tmp, a) != 1) { // while (tmp <= a)
		if ((denom->array[R_BIG_ARRAY_SIZE - 1] >> (R_BIG_WORD_SIZE * 8 - 1)) == 1) {
			break; // Reach the max value
		}
		_lshift_one_bit (tmp); // tmp <= 1
		_lshift_one_bit (denom); // denom <= 1
		_lshift_one_bit (current); // current <= 1
	}

	r_big_assign (tmp, a); // tmp = a
	tmp->sign = 1;
	_r_big_zero_out (c); // int answer = 0;

	while (!r_big_is_zero (current)) // while (current != 0)
	{
		if (r_big_cmp (tmp, denom) != -1) //   if (dividend >= denom)
		{
			r_big_sub (tmp, tmp, denom); //     dividend -= denom;
			r_big_or (c, current, c); //     answer |= current;
		}
		_rshift_one_bit (current); //   current >>= 1;
		_rshift_one_bit (denom); //   denom >>= 1;
	} // return answer;

	c->sign = sign;
	if (r_big_is_zero (c)) {
		c->sign = 1; // For -1 * 0 case
	}
	r_big_free (current);
	r_big_free (denom);
	r_big_free (tmp);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	/*  
    Take divmod and throw away div part
    */
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (!r_big_is_zero (b));

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (!r_big_is_zero (b));

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (a->sign > 0);
	r_return_if_fail (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] & b->array[i]);
	}
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (a->sign > 0);
	r_return_if_fail (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] | b->array[i]);
	}
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (a->sign > 0);
	r_return_if_fail (b->sign > 0);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] ^ b->array[i]);
	}
}

R_API void r_big_lshift(RNumBig *b, RNumBig *a, size_t nbits) {
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (a->sign > 0);
	r_return_if_fail (b->sign > 0);

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
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (a->sign > 0);
	r_return_if_fail (b->sign > 0);

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
	r_return_val_if_fail (a, 0);
	r_return_val_if_fail (b, 0);

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
	r_return_val_if_fail (a, -1);

	int i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		if (a->array[i]) {
			return 0;
		}
	}

	return 1;
}

R_API void r_big_inc(RNumBig *a) {
	r_return_if_fail (a);
	RNumBig *tmp = r_big_new ();

	r_big_from_int (tmp, 1);
	r_big_add (a, a, tmp);

	r_big_free (tmp);
}

R_API void r_big_dec(RNumBig *a) {
	r_return_if_fail (a);
	RNumBig *tmp = r_big_new ();

	r_big_from_int (tmp, 1);
	r_big_sub (a, a, tmp);

	r_big_free (tmp);
}

R_API void r_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	r_return_if_fail (a);
	r_return_if_fail (b);
	r_return_if_fail (c);
	r_return_if_fail (m);

	RNumBig *bcopy = r_big_new ();
	RNumBig *acopy = r_big_new ();

	r_big_assign (bcopy, b);
	r_big_assign (acopy, a);
	r_big_mod (acopy, acopy, m);
	r_big_from_int (c, 1);

	while (!r_big_is_zero (bcopy)) {
		if (r_big_to_int (bcopy) % 2 == 1) {
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

R_API void r_big_isqrt(RNumBig *b, RNumBig *a) {
	r_return_if_fail (a);
	r_return_if_fail (b);

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

/* Private / Static functions. */
static void _rshift_word(RNumBig *a, int nwords) {
	/* Naive method: */
	r_return_if_fail (a);
	r_return_if_fail (nwords >= 0);

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
	r_return_if_fail (a);
	r_return_if_fail (nwords >= 0);

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
	r_return_if_fail (a);

	int i;
	for (i = (R_BIG_ARRAY_SIZE - 1); i > 0; i--) {
		a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * R_BIG_WORD_SIZE) - 1));
	}
	a->array[0] <<= 1;
}

static void _rshift_one_bit(RNumBig *a) {
	r_return_if_fail (a);

	int i;
	for (i = 0; i < (R_BIG_ARRAY_SIZE - 1); i++) {
		a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * R_BIG_WORD_SIZE) - 1));
	}
	a->array[R_BIG_ARRAY_SIZE - 1] >>= 1;
}

static void _r_big_zero_out(RNumBig *a) {
	r_return_if_fail (a);

	size_t i;
	for (i = 0; i < R_BIG_ARRAY_SIZE; i++) {
		a->array[i] = 0;
	}
	a->sign = 1; /* hack to avoid -0 */
}
