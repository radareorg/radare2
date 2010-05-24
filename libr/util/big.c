/* Based on Steven Skiena source code. licensed as LGPL 
 * http://www.cs.sunysb.edu/~skiena/392/programs/bignum.c
 * --pancake
 */

/* TODO: Implement gmp code */

#include <stdio.h>
#include <r_util.h>
#ifdef HAVE_LIB_GMP
#include <gmp.h>
#endif

static inline void r_big_zero(RNumBig *n) {
#ifdef HAVE_LIB_GMP
	return;
#else
	while ((n->last>0) && !n->dgts[n->last])
		n->last--;
        if (!n->last && !*n->dgts)
		n->sign = 1; /* hack to avoid -0 */
#endif
}

R_API void r_big_print(RNumBig *n) {
#ifdef HAVE_LIB_GMP
	return;
#else
	int i;
	if (n->last>=0) {
		if (n->sign<0)
			printf ("-");
		for (i=n->last; i>=0; i--)
			printf ("%c", '0'+n->dgts[i]);
		printf ("\n");
	}
#endif
}

R_API void r_big_set_str(RNumBig *n, const char *str) {
#ifdef HAVE_LIB_GMP
	return;
#else
	int i, len;
	if (*str=='-') {
		n->sign = -1;
		str++;
	} else n->sign = 1;
	for (i=len=strlen (str)-1; *str; i--, str++)
		n->dgts[i] = *str-'0';
	n->last = len;
#endif
}

R_API RNumBig *r_big_new(RNumBig *b) {
	RNumBig *n = R_NEW (RNumBig);
	if (b) memcpy (n, b, sizeof (RNumBig));
	else
#ifdef HAVE_LIB_GMP
	mpz_init (*n);
#else
	r_big_set (n, 0);
#endif
	return n;
}

R_API void r_big_free(RNumBig *b) {
	free (b);
}

R_API void r_big_set(RNumBig *n, int v) {
#ifdef HAVE_LIB_GMP
	return;
#else
	int t;
	n->last = 0;
	n->sign = (v>=0)?1:-1;
	memset (n->dgts, 0, R_BIG_SIZE);
	for (n->last=0, t=R_ABS (v); t>0; t/=10, n->last++)
		n->dgts[n->last] = (t % 10);
	if (!v) n->last = 0;
#endif
}

R_API void r_big_set64(RNumBig *n, st64 v) {
#ifdef HAVE_LIB_GMP
	return;
#else
	st64 t;
	n->sign = (v<0)?-1:1;
	memset (n->dgts, 0, R_BIG_SIZE);
	n->last = 0;//-1;
	for (t=R_ABS(v); t>0; t/=10) {
		n->last++;
		n->dgts[n->last] = t%10;
	}
	if (!v) n->last = 0;
#endif
}

/* c = a [+*-/] b; */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return;
#else
	int i, carry;
	RNumBig t;
	r_big_set (&t, 0);
	if (a->sign != b->sign) {
		a->sign = 1;
		if (a->sign == -1)
			r_big_sub (&t, b, a);
		else r_big_sub (&t, a, b);
		a->sign = -1;
		return;
	} else t.sign = a->sign;

	t.last = R_MAX (a->last, b->last)+1;

	for (carry=i=0; i<=t.last && i<R_BIG_SIZE; i++) {
		t.dgts[i] = (char) (carry+a->dgts[i]+b->dgts[i]) % 10;
		carry = (carry + a->dgts[i] + b->dgts[i]) / 10;
	}
	*c = t;
	r_big_zero (c);
#endif
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return;
#else
	RNumBig t;
	int i, v, borrow;

	r_big_set (&t, 0);

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
#endif
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return 0;
#else
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
#endif
}

/* multiply n by 10^d */
R_API void r_big_shift(RNumBig *n, int d) {
#ifdef HAVE_LIB_GMP
	return;
#else
	int i;
	if (!n->last && !*n->dgts)
		return;
	for (i=n->last; i>=0; i--)
		n->dgts[i+d] = n->dgts[i];
	memset (n->dgts, 0, d);
	n->last += d;
#endif
}

R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return;
#else
	RNumBig t, tmp, row;
	int i,j;
	r_big_set (&t, 0);
	r_big_set (&tmp, 0);
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
#endif
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return;
#else
	RNumBig t, tmp, row;
	int i, asign, bsign;

	r_big_set (&t, 0);
	t.sign = a->sign * b->sign;
	asign = a->sign;
	bsign = b->sign;
	a->sign = b->sign = 1;
	r_big_set (&row, 0);
	r_big_set (&tmp, 0);
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
#endif
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
#ifdef HAVE_LIB_GMP
	return;
#else
	RNumBig t; // a%b = a-((a/b)*b)
	r_big_div (c, a, b); // c=a/b
	r_big_mul (&t, c, b); // t=c*b
	r_big_sub (c, a, &t); // c=a-t
#endif
}

#if TEST

void main() {
	int a,b;
	RNumBig n1, n2, n3, zero;

	r_big_set (&n2, -2);
	r_big_set_str (&n3, "-3");
	//r_big_set (&n3, -3);
printf ("n3last = %d\n", n3.last);
printf ("%d %d\n", n3.dgts[0], n3.dgts[1]);
	r_big_mul (&n2, &n2, &n3);
	r_big_print (&n2);
printf("--\n");

	r_big_set (&n1, 2);
	r_big_set (&n2, 3);
	r_big_mul(&n1, &n1, &n2);
	r_big_print (&n1);

	r_big_set (&n3, 923459999);
	r_big_mul (&n1, &n2, &n3);
	r_big_mul (&n2, &n1, &n3);
	r_big_mul (&n1, &n2, &n3);
	r_big_print (&n1);

	r_big_set64 (&n2, 9999923459999999);
	r_big_set64 (&n3, 9999992345999999);
	r_big_mul (&n1, &n2, &n3);
	r_big_mul (&n2, &n1, &n3);
	r_big_mul (&n1, &n2, &n3);
	r_big_print (&n1);

	while (scanf ("%d %d\n",&a,&b) != EOF) {
		printf("a = %d    b = %d\n",a,b);
		r_big_set(&n1, a);
		r_big_set(&n2, b);

		r_big_add (&n3, &n1, &n2);
		printf ("addition -- ");
		r_big_print (&n3);

		printf ("r_big_cmp a ? b = %d\n",r_big_cmp(&n1, &n2));

		r_big_sub (&n3,&n1,&n2);
		printf("subtraction -- ");
		r_big_print (&n3);

                r_big_mul (&n3,&n1,&n2);
		printf("multiplication -- ");
                r_big_print (&n3);

		r_big_set(&zero, 0);
		if (r_big_cmp(&zero, &n2) == 0)
			printf("division -- NaN \n");
                else {
			r_big_div (&n3,&n1,&n2);
			printf("division -- ");
                	r_big_print (&n3);
		}
		printf("--------------------------\n");
	}
}
#endif
