/* Based on Steven Skiena source code. licensed as LGPL 
 * http://www.cs.sunysb.edu/~skiena/392/programs/bignum.c
 * --pancake
 */

/* XXX : seems broken for big numbers */
#include <stdio.h>
#include <r_util.h>

static inline void r_big_zero(RNumBig *n) {
	while ((n->last>0) && !n->dgts[n->last])
		n->last--;
        if (!n->last && !*n->dgts)
		n->sign = 1; /* hack to avoid -0 */
}

R_API void r_big_print(RNumBig *n) {
	int i;
	if (n->last>=0) {
		if (n->sign<0)
			printf ("-");
		for (i=n->last; i>=0; i--)
			printf ("%c", '0'+n->dgts[i]);
		printf ("\n");
	}
}

R_API void r_big_set_str(RNumBig *n, const char *str) {
	int i, len;
	if (*str=='-') {
		n->sign = -1;
		str++;
	} else n->sign = 1;
	for (i=len=strlen (str)-1; *str; i--, str++)
		n->dgts[i] = *str-'0';
	n->last = len;
}

R_API RNumBig *r_big_new(RNumBig *b) {
	RNumBig *n = R_NEW (RNumBig);
	if (n) {
		if (b) memcpy (n, b, sizeof (RNumBig));
		else r_big_set_st (n, 0);
	}
	return n;
}

R_API void r_big_free(RNumBig *b) {
	free (b);
}

R_API void r_big_set(RNumBig *a, RNumBig *b) {
	memcpy (a, b, sizeof (RNumBig));
}

R_API void r_big_set_st(RNumBig *n, int v) {
	int t;
	n->last = 0;
	n->sign = (v>=0)?1:-1;
	memset (n->dgts, 0, R_BIG_SIZE);
	for (n->last=0, t=R_ABS (v); t>0; t/=10, n->last++)
		n->dgts[n->last] = (t % 10);
	if (!v) n->last = 0;
}

R_API void r_big_set_st64(RNumBig *n, st64 v) {
	st64 t;
	n->sign = (v<0)?-1:1;
	memset (n->dgts, 0, R_BIG_SIZE);
	n->last = 0;//-1;
	for (t=R_ABS(v); t>0; t/=10) {
		n->last++;
		n->dgts[n->last] = t%10;
	}
	if (!v) n->last = 0;
}

/* c = a [+*-/] b; */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b) {
	int i, carry;
	RNumBig t;
	r_big_set_st (&t, 0);
	if (a->sign != b->sign) {
		a->sign = 1;
		if (a->sign == -1)
			r_big_sub (&t, b, a);
		else r_big_sub (&t, a, b);
		a->sign = -1;
		*c = t;
		return;
	} else t.sign = a->sign;

	t.last = R_MAX (a->last, b->last)+1;

	for (carry=i=0; i<=t.last && i<R_BIG_SIZE; i++) {
		t.dgts[i] = (char) (carry+a->dgts[i]+b->dgts[i]) % 10;
		carry = (carry + a->dgts[i] + b->dgts[i]) / 10;
	}
	*c = t;
	r_big_zero (c);
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig t;
	int i, v, borrow;

	r_big_set_st (&t, 0);

	if ((a->sign == -1) || (b->sign == -1)) {
                b->sign *= -1;
                r_big_add (&t, a, b);
                b->sign *= -1;
		*c = t;
		return;
        }

	if (r_big_cmp (a, b) == 1) {
		r_big_sub (&t, b, a);
		t.sign = -1;
		*c = t;
		return;
	}

        t.last = R_MAX (a->last, b->last);
        for (borrow=i=0; i<=(t.last) &&i<R_BIG_SIZE; i++) {
		v = (a->dgts[i] - borrow - b->dgts[i]);
		if (v < 0) {
			v += 10;
			borrow = 1;
		} else
		if (a->dgts[i] > 0)
			borrow = 0;
                t.dgts[i] = (char) v % 10;
        }
	*c = t;
	r_big_zero (c);
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
	int i;
	if ((a->sign == -1) && (b->sign == 1)) return 1;
	if ((a->sign == 1) && (b->sign == -1)) return -1;
	if (b->last > a->last) return a->sign;
	if (a->last > b->last) return a->sign*-1;
	for (i = a->last; i>=0; i--) {
		if (a->dgts[i] > b->dgts[i]) return a->sign*-1;
		if (b->dgts[i] > a->dgts[i]) return a->sign;
	}
	return 0;
}

R_API int r_big_cmp_st(RNumBig *n, int v) {
	return 0;
}

/* multiply n by 10^d */
R_API void r_big_shift(RNumBig *n, int d) {
	int i;
	if (!n->last && !*n->dgts)
		return;
	for (i=n->last; i>=0; i--)
		n->dgts[i+d] = n->dgts[i];
	memset (n->dgts, 0, d);
	n->last += d;
}

R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig t, tmp, row;
	int i,j;
	r_big_set_st (&t, 0);
	r_big_set_st (&tmp, 0);
	row = *a;
	for (i=0; i<=b->last && i<R_BIG_SIZE; i++) {
		for (j=1; j<=b->dgts[i]; j++) {
			r_big_add (&tmp, &t, &row);
			t = tmp;
		}
		r_big_shift (&row, 1);
	}
	*c = t;
	c->sign = a->sign * b->sign;
	r_big_zero (c);
}

R_API void r_big_mul_ut (RNumBig *c, RNumBig *a, ut32 b) {
	return;
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig t, tmp, row;
	int i, asign, bsign;

	r_big_set_st (&t, 0);
	t.sign = a->sign * b->sign;
	asign = a->sign;
	bsign = b->sign;
	a->sign = b->sign = 1;
	r_big_set_st (&row, 0);
	r_big_set_st (&tmp, 0);
	t.last = a->last;

	for (i=a->last; i>=0; i--) {
		r_big_shift (&row, 1);
		*row.dgts = a->dgts[i];
		c->dgts[i] = 0;
		while (r_big_cmp (&row, b) != 1) {
			t.dgts[i]++;
			r_big_sub (&tmp, &row, b);
			row = tmp;
		}
	}
	*c = t;
	r_big_zero (c);
	a->sign = asign;
	b->sign = bsign;
}

R_API void r_big_div_ut(RNumBig *c, RNumBig *a, ut32 b) {
	return;
}

R_API int r_big_divisible_ut(RNumBig *n, ut32 v) {
	return 0;
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig t; // a%b = a-((a/b)*b)
	r_big_div (c, a, b); // c=a/b
	r_big_mul (&t, c, b); // t=c*b
	r_big_sub (c, a, &t); // c=a-t
}
