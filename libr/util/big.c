/* Based on Steven Skiena source code. licensed as LGPL 
 * http://www.cs.sunysb.edu/~skiena/392/programs/bignum.c
 * --pancake
 */

#include <stdio.h>
#include <r_util.h>


R_API void r_big_print(RNumBig *n) {
	int i;
	if (n->last>=0) {
		if (n->sign<0)
			printf ("-");
		for (i=n->last; i>=0; i--)
			printf ("%c",'0'+ n->dgts[i]);
		printf ("\n");
	}
}

static inline void r_big_zero(RNumBig *n) {
	while ((n->last > 0) && (n->dgts[ n->last ] == 0))
		n->last --;
        if (!n->last && !*n->dgts)
		n->sign = 1; /* hack to avoid -0 */
}

R_API void r_big_set(RNumBig *n, int v) {
	int i, t;
	n->sign = (v>=0)?1:-1;
	memset (n->dgts, 0, R_BIG_SIZE);
	n->last = -1;
	for (t=R_ABS (v); t>0; t/=10) {
		n->last++;
		n->dgts[n->last] = (t % 10);
	}
	if (!v) n->last = 0;
}

R_API void r_big_set64(RNumBig *n, ut64 v) {
	ut64 i, t;
	n->sign = (v<0)?-1:1;
	memset (n->dgts, 0, R_BIG_SIZE);
	n->last = -1;
	for (t=R_ABS(v); t>0; t/=10) {
		n->last ++;
		n->dgts[ n->last ] = (t % 10);
	}
	if (!v) n->last = 0;
}

/* c = a [+*-/] b; */
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b) {
	int i, carry;

	r_big_set (c, 0);
	if (a->sign != b->sign) {
		a->sign = 1;
		if (a->sign == -1)
			r_big_sub (c, b, a);
		else r_big_sub (c, a, b);
		a->sign = -1;
		return;
	} else c->sign = a->sign;

	c->last = R_MAX (a->last, b->last)+1;

	for (carry=i=0; i<=c->last; i++) {
		c->dgts[i] = (char) (carry+a->dgts[i]+b->dgts[i]) % 10;
		carry = (carry + a->dgts[i] + b->dgts[i]) / 10;
	}
	r_big_zero (c);
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	int i, v, borrow;

	r_big_set (c, 0);

	if ((a->sign == -1) || (b->sign == -1)) {
                b->sign *= -1;
                r_big_add (c, a, b);
                b->sign *= -1;
		return;
        }

	if (r_big_cmp (a, b) == 1) {
		r_big_sub (c, b, a);
		c->sign = -1;
		return;
	}

        c->last = R_MAX (a->last, b->last);

        for (borrow=i=0; i<=(c->last); i++) {
		v = (a->dgts[i] - borrow - b->dgts[i]);
		if (v < 0) {
			v += 10;
			borrow = 1;
		} else
		if (a->dgts[i] > 0)
			borrow = 0;
                c->dgts[i] = (char) v % 10;
        }
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
	RNumBig tmp, row;
	int i,j;

	r_big_set (c, 0);
	row = *a;
	for (i=0; i<=b->last; i++) {
		for (j=1; j<=b->dgts[i]; j++) {
			r_big_add (&tmp, &row, c);
			*c = tmp;
		}
		r_big_shift (&row, 1);
	}
	c->sign = a->sign * b->sign;
	r_big_zero (c);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
        RNumBig tmp, row;
	int i, j, asign, bsign;

	r_big_set (c, 0);
	c->sign = a->sign * b->sign;
	asign = a->sign;
	bsign = b->sign;
	a->sign = b->sign = 1;
	r_big_set (&row, 0);
	r_big_set (&tmp, 0);
	c->last = a->last;

	for (i=a->last; i>=0; i--) {
		r_big_shift (&row, 1);
		*row.dgts = a->dgts[i];
		c->dgts[i] = 0;
		while (r_big_cmp (&row, b) != 1) {
			c->dgts[i] ++;
			r_big_sub (&tmp, &row, b);
			row = tmp;
		}
	}

	r_big_zero (c);
	a->sign = asign;
	b->sign = bsign;
}

#if TEST

void main() {
	int a,b;
	RNumBig n1, n2, n3, zero;

	r_big_set (&n2, 1);
	r_big_print (&n2);

	r_big_set (&n1, 2);
	r_big_set (&n2, 3);
	r_big_set (&n3, 0);
	r_big_mul(&n3, &n1, &n2);
	r_big_print (&n3);

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
