#include "ge.h"
#include "precomp_data.h"

static void ge_add (ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
static void ge_sub (ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
static void ge_madd (ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
static void ge_msub (ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
static void ge_p1p1_to_p2 (ge_p2 *r, const ge_p1p1 *p);
static void ge_p1p1_to_p3 (ge_p3 *r, const ge_p1p1 *p);
static void ge_p2_0 (ge_p2 *h);
static void ge_p2_dbl (ge_p1p1 *r, const ge_p2 *p);
static void ge_p3_0 (ge_p3 *h);
static void ge_p3_dbl (ge_p1p1 *r, const ge_p3 *p);
static void ge_p3_to_cached (ge_cached *r, const ge_p3 *p);
static void ge_p3_to_p2 (ge_p2 *r, const ge_p3 *p);

/*
r = p + q
*/

static void ge_add (ge_p1p1 *r, const ge_p3 *p, const ge_cached *q) {
	fe t0;
	fe_add (r->X, p->Y, p->X);
	fe_sub (r->Y, p->Y, p->X);
	fe_mul (r->Z, r->X, q->YplusX);
	fe_mul (r->Y, r->Y, q->YminusX);
	fe_mul (r->T, q->T2d, p->T);
	fe_mul (r->X, p->Z, q->Z);
	fe_add (t0, r->X, r->X);
	fe_sub (r->X, r->Z, r->Y);
	fe_add (r->Y, r->Z, r->Y);
	fe_add (r->Z, t0, r->T);
	fe_sub (r->T, t0, r->T);
}

static void slide(signed char *r, const unsigned char *a) {
	int i;
	int b;
	int k;

	for (i = 0; i < 256; i++) {
		r[i] = 1 & (a[i >> 3] >> (i & 7));
	}

	for (i = 0; i < 256; i++) {
		if (r[i]) {
			for (b = 1; b <= 6 && i + b < 256; b++) {
				if (r[i + b]) {
					if (r[i] + (r[i + b] << b) <= 15) {
						r[i] += r[i + b] << b;
						r[i + b] = 0;
					} else if (r[i] - (r[i + b] << b) >= -15) {
						r[i] -= r[i + b] << b;

						for (k = i + b; k < 256; k++) {
							if (!r[k]) {
								r[k] = 1;
								break;
							}

							r[k] = 0;
						}
					} else {
						break;
					}
				}
			}
		}
	}
}

/*
r = a * A + b * B
where a = a[0]+256*a[1]+...+256^31 a[31].
and b = b[0]+256*b[1]+...+256^31 b[31].
B is the Ed25519 base point (x,4/5) with x positive.
*/

void ge_double_scalarmult_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b) {
	signed char aslide[256];
	signed char bslide[256];
	ge_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
	ge_p1p1 t;
	ge_p3 u;
	ge_p3 A2;
	int i;
	slide (aslide, a);
	slide (bslide, b);
	ge_p3_to_cached (&Ai[0], A);
	ge_p3_dbl (&t, A);
	ge_p1p1_to_p3 (&A2, &t);
	ge_add (&t, &A2, &Ai[0]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[1], &u);
	ge_add (&t, &A2, &Ai[1]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[2], &u);
	ge_add (&t, &A2, &Ai[2]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[3], &u);
	ge_add (&t, &A2, &Ai[3]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[4], &u);
	ge_add (&t, &A2, &Ai[4]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[5], &u);
	ge_add (&t, &A2, &Ai[5]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[6], &u);
	ge_add (&t, &A2, &Ai[6]);
	ge_p1p1_to_p3 (&u, &t);
	ge_p3_to_cached (&Ai[7], &u);
	ge_p2_0 (r);

	for (i = 255; i >= 0; --i) {
		if (aslide[i] || bslide[i]) {
			break;
		}
	}

	for (; i >= 0; --i) {
		ge_p2_dbl (&t, r);

		if (aslide[i] > 0) {
			ge_p1p1_to_p3 (&u, &t);
			ge_add (&t, &u, &Ai[aslide[i] / 2]);
		} else if (aslide[i] < 0) {
			ge_p1p1_to_p3 (&u, &t);
			ge_sub (&t, &u, &Ai[(-aslide[i]) / 2]);
		}

		if (bslide[i] > 0) {
			ge_p1p1_to_p3 (&u, &t);
			ge_madd (&t, &u, &Bi[bslide[i] / 2]);
		} else if (bslide[i] < 0) {
			ge_p1p1_to_p3 (&u, &t);
			ge_msub (&t, &u, &Bi[(-bslide[i]) / 2]);
		}

		ge_p1p1_to_p2 (r, &t);
	}
}

static const fe d = {
	-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116
};

static const fe sqrtm1 = {
	-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
};

int ge_frombytes_negate_vartime(ge_p3 *h, const unsigned char *s) {
	fe u;
	fe v;
	fe v3;
	fe vxx;
	fe check;
	fe_frombytes (h->Y, s);
	fe_1 (h->Z);
	fe_sq (u, h->Y);
	fe_mul (v, u, d);
	fe_sub (u, u, h->Z); /* u = y^2-1 */
	fe_add (v, v, h->Z); /* v = dy^2+1 */
	fe_sq (v3, v);
	fe_mul (v3, v3, v); /* v3 = v^3 */
	fe_sq (h->X, v3);
	fe_mul (h->X, h->X, v);
	fe_mul (h->X, h->X, u); /* x = uv^7 */
	fe_pow22523 (h->X, h->X); /* x = (uv^7)^((q-5)/8) */
	fe_mul (h->X, h->X, v3);
	fe_mul (h->X, h->X, u); /* x = uv^3(uv^7)^((q-5)/8) */
	fe_sq (vxx, h->X);
	fe_mul (vxx, vxx, v);
	fe_sub (check, vxx, u); /* vx^2-u */

	if (fe_isnonzero (check)) {
		fe_add (check, vxx, u); /* vx^2+u */

		if (fe_isnonzero (check)) {
			return -1;
		}

		fe_mul (h->X, h->X, sqrtm1);
	}

	if (fe_isnegative (h->X) == (s[31] >> 7)) {
		fe_neg (h->X, h->X);
	}

	fe_mul (h->T, h->X, h->Y);
	return 0;
}

/*
r = p + q
*/

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
	fe t0;
	fe_add (r->X, p->Y, p->X);
	fe_sub (r->Y, p->Y, p->X);
	fe_mul (r->Z, r->X, q->yplusx);
	fe_mul (r->Y, r->Y, q->yminusx);
	fe_mul (r->T, q->xy2d, p->T);
	fe_add (t0, p->Z, p->Z);
	fe_sub (r->X, r->Z, r->Y);
	fe_add (r->Y, r->Z, r->Y);
	fe_add (r->Z, t0, r->T);
	fe_sub (r->T, t0, r->T);
}

/*
r = p - q
*/

void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
	fe t0;

	fe_add (r->X, p->Y, p->X);
	fe_sub (r->Y, p->Y, p->X);
	fe_mul (r->Z, r->X, q->yminusx);
	fe_mul (r->Y, r->Y, q->yplusx);
	fe_mul (r->T, q->xy2d, p->T);
	fe_add (t0, p->Z, p->Z);
	fe_sub (r->X, r->Z, r->Y);
	fe_add (r->Y, r->Z, r->Y);
	fe_sub (r->Z, t0, r->T);
	fe_add (r->T, t0, r->T);
}

/*
r = p
*/

void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
	fe_mul (r->X, p->X, p->T);
	fe_mul (r->Y, p->Y, p->Z);
	fe_mul (r->Z, p->Z, p->T);
}

/*
r = p
*/

void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
	fe_mul (r->X, p->X, p->T);
	fe_mul (r->Y, p->Y, p->Z);
	fe_mul (r->Z, p->Z, p->T);
	fe_mul (r->T, p->X, p->Y);
}

void ge_p2_0(ge_p2 *h) {
	fe_0 (h->X);
	fe_1 (h->Y);
	fe_1 (h->Z);
}

/*
r = 2 * p
*/

void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
	fe t0;

	fe_sq (r->X, p->X);
	fe_sq (r->Z, p->Y);
	fe_sq2 (r->T, p->Z);
	fe_add (r->Y, p->X, p->Y);
	fe_sq (t0, r->Y);
	fe_add (r->Y, r->Z, r->X);
	fe_sub (r->Z, r->Z, r->X);
	fe_sub (r->X, t0, r->Y);
	fe_sub (r->T, r->T, r->Z);
}

void ge_p3_0(ge_p3 *h) {
	fe_0 (h->X);
	fe_1 (h->Y);
	fe_1 (h->Z);
	fe_0 (h->T);
}

/*
r = 2 * p
*/

void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p) {
	ge_p2 q;
	ge_p3_to_p2 (&q, p);
	ge_p2_dbl (r, &q);
}

/*
r = p
*/

static const fe d2 = {
	-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199
};

void ge_p3_to_cached(ge_cached *r, const ge_p3 *p) {
	fe_add (r->YplusX, p->Y, p->X);
	fe_sub (r->YminusX, p->Y, p->X);
	fe_copy (r->Z, p->Z);
	fe_mul (r->T2d, p->T, d2);
}

/*
r = p
*/

void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p) {
	fe_copy (r->X, p->X);
	fe_copy (r->Y, p->Y);
	fe_copy (r->Z, p->Z);
}

void ge_p3_tobytes(unsigned char *s, const ge_p3 *h) {
	fe recip;
	fe x;
	fe y;
	fe_invert (recip, h->Z);
	fe_mul (x, h->X, recip);
	fe_mul (y, h->Y, recip);
	fe_tobytes (s, y);
	s[31] ^= fe_isnegative (x) << 7;
}

static unsigned char equal(signed char b, signed char c) {
	unsigned char ub = b;
	unsigned char uc = c;
	unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
	uint64_t y = x; /* 0: yes; 1..255: no */
	y -= 1; /* large: yes; 0..254: no */
	y >>= 63; /* 1: yes; 0: no */
	return (unsigned char)y;
}

static unsigned char negative(signed char b) {
	uint64_t x = b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
	x >>= 63; /* 1: yes; 0: no */
	return (unsigned char)x;
}

static void cmov(ge_precomp *t, const ge_precomp *u, unsigned char b) {
	fe_cmov (t->yplusx, u->yplusx, b);
	fe_cmov (t->yminusx, u->yminusx, b);
	fe_cmov (t->xy2d, u->xy2d, b);
}

static void select(ge_precomp *t, int pos, signed char b) {
	ge_precomp minust;
	unsigned char bnegative = negative (b);
	unsigned char babs = b - (((-bnegative) & b) << 1);
	fe_1 (t->yplusx);
	fe_1 (t->yminusx);
	fe_0 (t->xy2d);
	cmov (t, &base[pos][0], equal (babs, 1));
	cmov (t, &base[pos][1], equal (babs, 2));
	cmov (t, &base[pos][2], equal (babs, 3));
	cmov (t, &base[pos][3], equal (babs, 4));
	cmov (t, &base[pos][4], equal (babs, 5));
	cmov (t, &base[pos][5], equal (babs, 6));
	cmov (t, &base[pos][6], equal (babs, 7));
	cmov (t, &base[pos][7], equal (babs, 8));
	fe_copy (minust.yplusx, t->yminusx);
	fe_copy (minust.yminusx, t->yplusx);
	fe_neg (minust.xy2d, t->xy2d);
	cmov (t, &minust, bnegative);
}

/*
h = a * B
where a = a[0]+256*a[1]+...+256^31 a[31]
B is the Ed25519 base point (x,4/5) with x positive.

Preconditions:
  a[31] <= 127
*/

extern void ge_scalarmult_base(ge_p3 *h, const unsigned char *a) {
	signed char e[64];
	signed char carry;
	ge_p1p1 r;
	ge_p2 s;
	ge_precomp t;
	int i;

	for (i = 0; i < 32; i++) {
		e[2 * i + 0] = (a[i] >> 0) & 15;
		e[2 * i + 1] = (a[i] >> 4) & 15;
	}

	/* each e[i] is between 0 and 15 */
	/* e[63] is between 0 and 7 */
	carry = 0;

	for (i = 0; i < 63; i++) {
		e[i] += carry;
		carry = e[i] + 8;
		carry >>= 4;
		e[i] -= carry << 4;
	}

	e[63] += carry;
	/* each e[i] is between -8 and 8 */
	ge_p3_0 (h);

	for (i = 1; i < 64; i += 2) {
		select (&t, i / 2, e[i]);
		ge_madd (&r, h, &t);
		ge_p1p1_to_p3 (h, &r);
	}

	ge_p3_dbl (&r, h);
	ge_p1p1_to_p2 (&s, &r);
	ge_p2_dbl (&r, &s);
	ge_p1p1_to_p2 (&s, &r);
	ge_p2_dbl (&r, &s);
	ge_p1p1_to_p2 (&s, &r);
	ge_p2_dbl (&r, &s);
	ge_p1p1_to_p3 (h, &r);

	for (i = 0; i < 64; i += 2) {
		select (&t, i / 2, e[i]);
		ge_madd (&r, h, &t);
		ge_p1p1_to_p3 (h, &r);
	}
}

/*
r = p - q
*/

static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q) {
	fe t0;

	fe_add (r->X, p->Y, p->X);
	fe_sub (r->Y, p->Y, p->X);
	fe_mul (r->Z, r->X, q->YminusX);
	fe_mul (r->Y, r->Y, q->YplusX);
	fe_mul (r->T, q->T2d, p->T);
	fe_mul (r->X, p->Z, q->Z);
	fe_add (t0, r->X, r->X);
	fe_sub (r->X, r->Z, r->Y);
	fe_add (r->Y, r->Z, r->Y);
	fe_sub (r->Z, t0, r->T);
	fe_add (r->T, t0, r->T);
}

void ge_tobytes(unsigned char *s, const ge_p2 *h) {
	fe recip;
	fe x;
	fe y;
	fe_invert (recip, h->Z);
	fe_mul (x, h->X, recip);
	fe_mul (y, h->Y, recip);
	fe_tobytes (s, y);
	s[31] ^= fe_isnegative (x) << 7;
}
